mod sniffer;

use std::{
    net::IpAddr,
    str::FromStr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Context as _, anyhow};
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
use log::debug;
use nix::net::if_;
use tokio::{signal, sync::watch};

use sniffer::{SnifferConfig, SnifferStats};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eno1")]
    iface: String,
    #[clap(short, long, default_value = "50")]
    percentage: u32,
    #[clap(long)]
    valm: bool,
    #[clap(long)]
    ipv6: bool,
    #[clap(long, default_value = "ebpf")]
    mode: String,
    #[clap(long, default_value = "any")]
    protocol: String,
    #[clap(long, default_value = "1", value_parser = clap::value_parser!(u32).range(1..=10000))]
    count: u32,
    #[clap(long, default_value = "0")]
    delay: u64,
    #[clap(long)]
    fake_ip: Option<String>,
    #[clap(long)]
    closed: bool,
    #[clap(long, default_value = "none")]
    icmp_error: String,
    #[clap(long, default_value = "0", value_parser = clap::value_parser!(u32).range(0..=100))]
    no_rsp_perc: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp_mirror"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            debug!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt {
        iface,
        percentage,
        valm,
        ipv6,
        mode,
        protocol,
        count,
        delay,
        fake_ip,
        closed,
        icmp_error,
        no_rsp_perc,
    } = opt;

    // Resolve numeric interface index to name (e.g. "5" → "eno1").
    // aya's attach() expects the interface name string, not an index.
    let iface = if let Ok(idx) = iface.parse::<u32>() {
        match if_::if_indextoname(idx as u32) {
            Ok(name) => name.to_string_lossy().into_owned(),
            Err(_) => {
                let mut msg = format!("unknown network interface index {idx}");
                if let Ok(interfaces) = if_::if_nameindex() {
                    let names: Vec<String> = interfaces.iter().map(|i| i.name().to_string_lossy().into_owned()).collect();
                    if !names.is_empty() {
                        msg = format!("{msg}. Available interfaces: {}", names.join(", "));
                    }
                }
                return Err(anyhow!(msg));
            }
        }
    } else {
        iface
    };

    let mode_code = match mode.as_str() {
        "ebpf" => 0,
        "raw" => 1,
        "both" => 2,
        _ => anyhow::bail!("invalid mode: {}", mode),
    };

    let protocol_code = match protocol.as_str() {
        "any" => 0,
        "tcp" => 1,
        "udp" => 2,
        "icmp" => 3,
        _ => anyhow::bail!("invalid protocol: {}", protocol),
    };

    let icmp_error_code = match icmp_error.as_str() {
        "none" => 0,
        "port-unreach" => 1,
        "admin-prohibited" => 2,
        "host-unreach" => 3,
        "net-unreach" => 4,
        "time-exceeded" => 5,
        "all" => 6,
        _ => anyhow::bail!("invalid icmp-error type: {}", icmp_error),
    };

    let mut config_map: aya::maps::Array<_, xdp_mirror_common::Config> =
        aya::maps::Array::try_from(
            ebpf.map_mut("CONFIG").context("CONFIG map not found")?
        )?;
    config_map.set(
        0,
        xdp_mirror_common::Config {
            response_probability: percentage,
            validation_mode: valm as u32,
            ipv6: ipv6 as u32,
            protocol: protocol_code,
            mode: mode_code,
            icmp_error_type: icmp_error_code,
            no_rsp_perc,
        },
        0,
    )?;

    let program: &mut Xdp = ebpf
        .program_mut("xdp_mirror")
        .context("xdp_mirror program not found")?
        .try_into()?;
    program.load()?;
    if let Err(e) = program.attach(&iface, XdpFlags::default()) {
        eprintln!("XDP native mode failed ({e}), falling back to SKB_MODE...");
        program.attach(&iface, XdpFlags::SKB_MODE)
            .context("failed to attach the XDP program in SKB_MODE")?;
    }

    let needs_sniffer = mode == "raw" || mode == "both";
    let mut sniffer_handle: Option<tokio::task::JoinHandle<anyhow::Result<()>>> = None;
    let mut stop_tx: Option<watch::Sender<bool>> = None;
    let mut sniffer_stats: Option<Arc<SnifferStats>> = None;

    if needs_sniffer {
        let ring_buf = aya::maps::RingBuf::try_from(
            ebpf.take_map("PROBES").context("PROBES map not found")?
        )?;

        let (fake_ip_bytes, fake_ipv6) = match fake_ip {
            Some(ip_str) => {
                let ip: IpAddr = IpAddr::from_str(&ip_str)
                    .context("failed to parse fake_ip")?;
                match ip {
                    IpAddr::V4(v4) => {
                        let mut bytes = [0u8; 16];
                        bytes[..4].copy_from_slice(&v4.octets());
                        (Some(bytes), false)
                    }
                    IpAddr::V6(v6) => (Some(v6.octets()), true),
                }
            }
            None => (None, false),
        };

        let sniffer_config = SnifferConfig {
            count,
            delay,
            fake_ip: fake_ip_bytes,
            fake_ipv6,
            closed,
        };
        let stats = Arc::new(SnifferStats::default());
        let (tx, rx) = watch::channel(false);

        let handle = tokio::spawn(sniffer::run_sniffer(
            ring_buf,
            iface.clone(),
            sniffer_config,
            stats.clone(),
            rx,
        ));

        sniffer_handle = Some(handle);
        stop_tx = Some(tx);
        sniffer_stats = Some(stats);
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    if let Some(tx) = stop_tx {
        let _ = tx.send(true);
    }
    if let Some(handle) = sniffer_handle {
        match tokio::time::timeout(Duration::from_secs(5), handle).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(ref e)) ) => eprintln!("Sniffer error: {e:#}"),
            Ok(Err(_)) => eprintln!("Sniffer task panicked"),
            Err(_) => eprintln!("Sniffer did not shut down within 5s"),
        }
    }

    let stats_map: aya::maps::PerCpuArray<_, xdp_mirror_common::Stats> =
        aya::maps::PerCpuArray::try_from(
            ebpf.map("STATS").context("STATS map not found")?
        )?;

    let stats = stats_map.get(&0, 0)?;
    let mut total_rx = 0;
    let mut total_valid_syn = 0;
    let mut total_tx = 0;
    let mut total_rst = 0;
    let mut total_udp_rx = 0;
    let mut total_udp_tx = 0;
    let mut total_icmp_rx = 0;
    let mut total_icmp_tx = 0;
    let mut total_ring_dropped = 0;
    let mut total_icmp_error_tx = 0;

    for cpu_stats in stats.iter() {
        total_rx += cpu_stats.rx;
        total_valid_syn += cpu_stats.valid_syn;
        total_tx += cpu_stats.tx;
        total_rst += cpu_stats.rst_packets;
        total_udp_rx += cpu_stats.udp_rx;
        total_udp_tx += cpu_stats.udp_tx;
        total_icmp_rx += cpu_stats.icmp_rx;
        total_icmp_tx += cpu_stats.icmp_tx;
        total_ring_dropped += cpu_stats.ring_dropped;
        total_icmp_error_tx += cpu_stats.icmp_error_tx;
    }

    println!("=========================");
    println!("Empfangene Pakete gesamt:     {}", total_rx);
    println!("Valide SYN Pakete:            {}", total_valid_syn);
    println!("Gesendete Antworten:          {}", total_tx);
    if valm {
        println!("Empfangene RST Pakete:        {}", total_rst);
    }
    println!("UDP RX:                       {}", total_udp_rx);
    println!("UDP TX:                       {}", total_udp_tx);
    println!("ICMP RX:                      {}", total_icmp_rx);
    println!("ICMP TX:                      {}", total_icmp_tx);
    if total_icmp_error_tx > 0 || icmp_error_code != 0 {
        println!("ICMP error TX:               {}", total_icmp_error_tx);
    }
    if total_ring_dropped > 0 || needs_sniffer {
        println!("Ring dropped:                 {}", total_ring_dropped);
    }
    if let Some(ref sniffer_st) = sniffer_stats {
        println!("Sniffer sent:                 {}", sniffer_st.sent.load(Ordering::Relaxed));
        println!("Sniffer closed_sent:          {}", sniffer_st.closed_sent.load(Ordering::Relaxed));
        println!("Sniffer fake_sent:            {}", sniffer_st.fake_sent.load(Ordering::Relaxed));
        println!("Sniffer dropped_ring:         {}", sniffer_st.dropped_ring.load(Ordering::Relaxed));
    }
    println!("=========================");

    Ok(())
}

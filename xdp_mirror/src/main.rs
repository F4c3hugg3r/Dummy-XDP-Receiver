mod sniffer;

use std::{
    net::IpAddr,
    str::FromStr,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use anyhow::{Context as _, anyhow};
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
use log::debug;
use nix::net::if_;
use serde::Serialize;
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
    /// Periodic (1 s) JSONL stats timeline file.
    #[clap(long, default_value = "/tmp/xdp_mirror_stats.jsonl")]
    stats_file: String,
    /// Print the final stats on Ctrl-C as one JSON object instead of the
    /// German human-readable text.
    #[clap(long)]
    json_stats: bool,
}

/// Aggregated (across-CPU) view of the shared `Stats` map.
#[derive(Debug, Default, Clone, Copy, Serialize)]
struct AggregatedStats {
    rx: u64,
    valid_syn: u64,
    tx: u64,
    rst_packets: u64,
    udp_rx: u64,
    udp_tx: u64,
    icmp_rx: u64,
    icmp_tx: u64,
    ring_dropped: u64,
    icmp_error_tx: u64,
    even_rx: u64,
    odd_rx: u64,
    no_rsp_count: u64,
}

/// Sums the `PerCpuArray<Stats>` entry across all CPUs.
fn aggregate_stats<T: std::borrow::Borrow<aya::maps::MapData>>(
    stats_map: &aya::maps::PerCpuArray<T, xdp_mirror_common::Stats>,
) -> anyhow::Result<AggregatedStats> {
    let stats = stats_map.get(&0, 0)?;
    let mut agg = AggregatedStats::default();
    for cpu_stats in stats.iter() {
        agg.rx += cpu_stats.rx;
        agg.valid_syn += cpu_stats.valid_syn;
        agg.tx += cpu_stats.tx;
        agg.rst_packets += cpu_stats.rst_packets;
        agg.udp_rx += cpu_stats.udp_rx;
        agg.udp_tx += cpu_stats.udp_tx;
        agg.icmp_rx += cpu_stats.icmp_rx;
        agg.icmp_tx += cpu_stats.icmp_tx;
        agg.ring_dropped += cpu_stats.ring_dropped;
        agg.icmp_error_tx += cpu_stats.icmp_error_tx;
        agg.even_rx += cpu_stats.even_rx;
        agg.odd_rx += cpu_stats.odd_rx;
        agg.no_rsp_count += cpu_stats.no_rsp_count;
    }
    Ok(agg)
}

/// Sniffer-side counters (atomics), only populated when the sniffer ran.
#[derive(Debug, Default, Serialize)]
struct SnifferStatsJson {
    sent: u64,
    closed_sent: u64,
    fake_sent: u64,
    dropped_ring: u64,
}

fn sniffer_stats_json(stats: &Option<Arc<SnifferStats>>) -> Option<SnifferStatsJson> {
    stats.as_ref().map(|s| SnifferStatsJson {
        sent: s.sent.load(Ordering::Relaxed),
        closed_sent: s.closed_sent.load(Ordering::Relaxed),
        fake_sent: s.fake_sent.load(Ordering::Relaxed),
        dropped_ring: s.dropped_ring.load(Ordering::Relaxed),
    })
}

/// Spawns the periodic (1 s) stats-polling task that appends one JSON line to
/// `stats_file` per tick. The task owns the `STATS` map handle; when stopped
/// via the watch channel it performs one final aggregation, stores it in
/// `final_slot` and exits. Returns its join handle.
async fn spawn_stats_poller(
    stats_map: aya::maps::PerCpuArray<aya::maps::MapData, xdp_mirror_common::Stats>,
    stats_file: String,
    mut stop_rx: watch::Receiver<bool>,
    final_slot: Arc<tokio::sync::Mutex<Option<AggregatedStats>>>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    use std::io::Write;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&stats_file)
        .with_context(|| format!("failed to open stats file {stats_file}"))?;
    let writer = Arc::new(tokio::sync::Mutex::new(std::io::BufWriter::new(file)));
    let start = Instant::now();

    let handle = tokio::task::spawn(async move {
        let stats_map = &stats_map;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = stop_rx.changed() => break,
                _ = interval.tick() => {}
            }
            let agg = match aggregate_stats(stats_map) {
                Ok(a) => a,
                Err(_) => break,
            };
            let line = serde_json::json!({
                "ts": start.elapsed().as_secs(),
                "rx": agg.rx,
                "tx": agg.tx,
                "even_rx": agg.even_rx,
                "odd_rx": agg.odd_rx,
                "udp_rx": agg.udp_rx,
                "udp_tx": agg.udp_tx,
                "icmp_rx": agg.icmp_rx,
                "icmp_tx": agg.icmp_tx,
                "no_rsp_count": agg.no_rsp_count,
                "ring_dropped": agg.ring_dropped,
            });
            let mut w = writer.lock().await;
            if writeln!(w, "{line}").is_err() || w.flush().is_err() {
                break;
            }
        }
        // Final aggregation for the Ctrl-C JSON output.
        if let Ok(agg) = aggregate_stats(stats_map) {
            *final_slot.lock().await = Some(agg);
        }
    });
    Ok(handle)
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
    // Validate the string-valued options before touching eBPF: creating the
    // maps requires root, and a bail after that point would mask the real
    // permission error with a CLI usage error.
    if !matches!(opt.mode.as_str(), "ebpf" | "raw" | "both") {
        anyhow::bail!("invalid mode: {}", opt.mode);
    }
    if !matches!(opt.protocol.as_str(), "any" | "tcp" | "udp" | "icmp") {
        anyhow::bail!("invalid protocol: {}", opt.protocol);
    }
    if !matches!(
        opt.icmp_error.as_str(),
        "none"
            | "port-unreach"
            | "admin-prohibited"
            | "host-unreach"
            | "net-unreach"
            | "time-exceeded"
            | "all"
    ) {
        anyhow::bail!("invalid icmp-error type: {}", opt.icmp_error);
    }

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
        stats_file,
        json_stats,
    } = opt;

    // Resolve numeric interface index to name (e.g. "5" → "eno1").
    // aya's attach() expects the interface name string, not an index.
    let iface = if let Ok(idx) = iface.parse::<u32>() {
        match if_::if_indextoname(idx as u32) {
            Ok(name) => name.to_string_lossy().into_owned(),
            Err(_) => {
                let mut msg = format!("unknown network interface index {idx}");
                if let Ok(interfaces) = if_::if_nameindex() {
                    let names: Vec<String> = interfaces
                        .iter()
                        .map(|i| i.name().to_string_lossy().into_owned())
                        .collect();
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
        aya::maps::Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map not found")?)?;
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
        program
            .attach(&iface, XdpFlags::SKB_MODE)
            .context("failed to attach the XDP program in SKB_MODE")?;
    }
    let needs_sniffer = mode == "raw" || mode == "both";
    let mut sniffer_handle: Option<tokio::task::JoinHandle<anyhow::Result<()>>> = None;
    let mut sniffer_stats: Option<Arc<SnifferStats>> = None;

    // Shared shutdown channel: on Ctrl-C it stops the sniffer (if running)
    // and the periodic stats poller.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    if needs_sniffer {
        let ring_buf =
            aya::maps::RingBuf::try_from(ebpf.take_map("PROBES").context("PROBES map not found")?)?;

        let (fake_ip_bytes, fake_ipv6) = match fake_ip {
            Some(ip_str) => {
                let ip: IpAddr = IpAddr::from_str(&ip_str).context("failed to parse fake_ip")?;
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

        let handle = tokio::spawn(sniffer::run_sniffer(
            ring_buf,
            iface.clone(),
            sniffer_config,
            stats.clone(),
            shutdown_rx.clone(),
        ));

        sniffer_handle = Some(handle);
        sniffer_stats = Some(stats);
    }

    let stats_map_owned: aya::maps::PerCpuArray<aya::maps::MapData, xdp_mirror_common::Stats> =
        aya::maps::PerCpuArray::try_from(ebpf.take_map("STATS").context("STATS map not found")?)?;

    // The poller owns the STATS map handle and deposits the final aggregation
    // here on shutdown (MapData is not cloneable, so main cannot re-read).
    let final_stats_slot: Arc<tokio::sync::Mutex<Option<AggregatedStats>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    let stats_poller_handle = spawn_stats_poller(
        stats_map_owned,
        stats_file.clone(),
        shutdown_rx.clone(),
        final_stats_slot.clone(),
    )
    .await?;
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    // Shared shutdown channel: stops the sniffer AND the stats poller.
    let _ = shutdown_tx.send(true);

    if let Some(handle) = sniffer_handle {
        match tokio::time::timeout(Duration::from_secs(5), handle).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(ref e))) => eprintln!("Sniffer error: {e:#}"),
            Ok(Err(_)) => eprintln!("Sniffer task panicked"),
            Err(_) => eprintln!("Sniffer did not shut down within 5s"),
        }
    }
    // Give the poller a moment to observe the shutdown and flush its line +
    // final aggregation.
    match tokio::time::timeout(Duration::from_secs(2), stats_poller_handle).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => eprintln!("Stats poller task panicked"),
        Err(_) => eprintln!("Stats poller did not shut down within 2s"),
    }

    let stats = final_stats_slot
        .lock()
        .await
        .take()
        .context("stats poller did not produce a final aggregation")?;

    if json_stats {
        let final_stats = serde_json::json!({
            "final": true,
            "rx": stats.rx,
            "valid_syn": stats.valid_syn,
            "tx": stats.tx,
            "rst_packets": stats.rst_packets,
            "udp_rx": stats.udp_rx,
            "udp_tx": stats.udp_tx,
            "icmp_rx": stats.icmp_rx,
            "icmp_tx": stats.icmp_tx,
            "icmp_error_tx": stats.icmp_error_tx,
            "ring_dropped": stats.ring_dropped,
            "even_rx": stats.even_rx,
            "odd_rx": stats.odd_rx,
            "no_rsp_count": stats.no_rsp_count,
            "sniffer": sniffer_stats_json(&sniffer_stats),
        });
        println!("{final_stats}");
        return Ok(());
    }

    let total_rx = stats.rx;
    let total_valid_syn = stats.valid_syn;
    let total_tx = stats.tx;
    let total_rst = stats.rst_packets;
    let total_udp_rx = stats.udp_rx;
    let total_udp_tx = stats.udp_tx;
    let total_icmp_rx = stats.icmp_rx;
    let total_icmp_tx = stats.icmp_tx;
    let total_ring_dropped = stats.ring_dropped;
    let total_icmp_error_tx = stats.icmp_error_tx;

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
        println!(
            "Sniffer sent:                 {}",
            sniffer_st.sent.load(Ordering::Relaxed)
        );
        println!(
            "Sniffer closed_sent:          {}",
            sniffer_st.closed_sent.load(Ordering::Relaxed)
        );
        println!(
            "Sniffer fake_sent:            {}",
            sniffer_st.fake_sent.load(Ordering::Relaxed)
        );
        println!(
            "Sniffer dropped_ring:         {}",
            sniffer_st.dropped_ring.load(Ordering::Relaxed)
        );
    }
    println!("=========================");

    Ok(())
}

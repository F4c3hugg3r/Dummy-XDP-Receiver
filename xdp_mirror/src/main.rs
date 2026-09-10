use anyhow::Context as _;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

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
            warn!("failed to initialize eBPF logger: {e}");
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
    } = opt;

    let mut config_map: aya::maps::Array<_, xdp_mirror_common::Config> =
        aya::maps::Array::try_from(ebpf.map_mut("CONFIG").unwrap())?;
    config_map.set(
        0,
        xdp_mirror_common::Config {
            response_probability: percentage,
            validation_mode: valm as u32,
            ipv6: ipv6 as u32,
        },
        0,
    )?;

    let program: &mut Xdp = ebpf.program_mut("xdp_mirror").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    let stats_map: aya::maps::PerCpuArray<_, xdp_mirror_common::Stats> =
        aya::maps::PerCpuArray::try_from(ebpf.map("STATS").unwrap())?;

    let stats = stats_map.get(&0, 0)?;
    let mut total_rx = 0;
    let mut total_valid_syn = 0;
    let mut total_tx = 0;
    let mut total_rst = 0;

    for cpu_stats in stats.iter() {
        total_rx += cpu_stats.rx;
        total_valid_syn += cpu_stats.valid_syn;
        total_tx += cpu_stats.tx;
        total_rst += cpu_stats.rst_packets;
    }

    println!("=========================");
    println!("Empfangene Pakete gesamt:     {}", total_rx);
    println!("Valide SYN Pakete:            {}", total_valid_syn);
    println!("Gesendete Antworten:          {}", total_tx);
    if valm {
        println!("Empfangene RST Pakete:        {}", total_rst);
    }
    println!("=========================");

    Ok(())
}

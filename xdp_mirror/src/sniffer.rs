use std::{
    cmp::{Ordering as CmpOrdering, Reverse},
    collections::BinaryHeap,
    ffi::CString,
    os::fd::{AsRawFd, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use aya::maps::{MapData, RingBuf};
use nix::sys::socket::SockaddrLike;
use tokio::{io::unix::AsyncFd, sync::watch, time::Instant};
use xdp_mirror_common::ProbeEventHeader;

use crate::schedule::{self, ScheduleConfig};

const HDR_SIZE: usize = std::mem::size_of::<ProbeEventHeader>();

static SEQ_COUNTER: AtomicU64 = AtomicU64::new(1);
static SEQ_BASE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
static FAKE_ROTATE: AtomicU64 = AtomicU64::new(0);

fn next_isn() -> u32 {
    let base = *SEQ_BASE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x12345)
    });
    let n = SEQ_COUNTER.fetch_add(1, Ordering::Relaxed);
    base.wrapping_add(n) as u32
}

#[derive(Clone, Copy)]
pub struct FakeIpEntry {
    pub bytes: [u8; 16],
    pub v6: bool,
}

pub struct SnifferConfig {
    /// `--count`/`--delay`/`--rto-profile`/`--loss-perc`/`--jitter-ms`.
    pub schedule: ScheduleConfig,
    /// `--max-pending`: capacity of the delayed-copy queue (jobs).
    pub max_pending: usize,
    /// `--seed`: root of the per-probe loss/jitter randomness.
    pub seed: u64,
    pub fake_ip: Option<[u8; 16]>,
    pub fake_ipv6: bool,
    pub closed: bool,
    pub tcp_flags: u8,
    pub bad_csum: bool,
    pub ack_delta: u32,
    pub port_override: Option<u16>,
    pub fake_ip_list: Vec<FakeIpEntry>,
    pub fragment: bool,
}

#[derive(Default)]
pub struct SnifferStats {
    /// All successfully sent responses (every copy/retransmit).
    pub sent: AtomicU64,
    pub closed_sent: AtomicU64,
    pub fake_sent: AtomicU64,
    pub frag_sent: AtomicU64,
    pub dropped_ring: AtomicU64,
    /// Probes for which at least one response copy was successfully sent
    /// (counted once, on the first copy that actually went out, whichever
    /// copy that is).
    pub answered_probes: AtomicU64,
    /// Delayed copies/retransmits dropped because the queue was full
    /// (`--max-pending`).
    pub pending_dropped: AtomicU64,
    /// Delayed copies/retransmits dropped by `--loss-perc`.
    pub lost: AtomicU64,
    /// Response copies whose crafting or `sendto` failed (incl. `--closed`
    /// RST/ICMP-unreach replies).
    pub send_failed: AtomicU64,
    /// Queued copies discarded because the sniffer was stopped before they
    /// were due.
    pub discarded_on_stop: AtomicU64,
}

/// One probe drained from the ring, with everything that has to be
/// identical across all of its response copies (like a real retransmit):
/// the TCP ISN and the (possibly forged) source address are chosen once
/// here. Copies queued for later share it via `Arc`, so the UDP payload is
/// stored once per probe.
struct Probe {
    hdr: ProbeEventHeader,
    payload: Box<[u8]>,
    /// SYN-ACK sequence number (TCP only, 0 otherwise).
    isn: u32,
    /// Response source IP (fake/pool entry or the probed destination); v4
    /// in the first 4 bytes.
    src_ip: [u8; 16],
    /// Set by the first copy that was actually sent.
    answered: AtomicBool,
}

impl Probe {
    fn new(hdr: &ProbeEventHeader, payload: &[u8], config: &SnifferConfig) -> Self {
        Self {
            hdr: *hdr,
            payload: payload.into(),
            isn: if hdr.protocol == 6 { next_isn() } else { 0 },
            src_ip: pick_src_ip(hdr, config),
            answered: AtomicBool::new(false),
        }
    }
}

/// Probe identity for the per-probe randomness: `(ip_key, ports, seq)`.
/// `ports` = protocol << 32 | src_port << 16 | dst_port; `seq` = TCP
/// sequence number, ICMP id << 16 | ICMP seq, 0 for UDP.
fn probe_identity(hdr: &ProbeEventHeader) -> (u64, u64, u64) {
    let ip = schedule::ip_key(hdr.version, &hdr.dst_ip);
    let ports = ((hdr.protocol as u64) << 32)
        | ((u16::from_be(hdr.src_port) as u64) << 16)
        | u16::from_be(hdr.dst_port) as u64;
    let seq = match hdr.protocol {
        6 => u32::from_be(hdr.tcp_seq) as u64,
        1 | 58 => {
            ((u16::from_be_bytes(hdr.icmp_id) as u64) << 16)
                | u16::from_be_bytes(hdr.icmp_seq) as u64
        }
        _ => 0,
    };
    (ip, ports, seq)
}

/// Heap entry ordered by `(at_ns, seq)` only; `seq` keeps FIFO order for
/// equal deadlines. `at_ns` is relative to the sniffer start. 24 bytes per
/// queued copy; the probe itself is shared.
struct Due {
    at_ns: u64,
    seq: u64,
    probe: Arc<Probe>,
}

impl PartialEq for Due {
    fn eq(&self, other: &Self) -> bool {
        self.at_ns == other.at_ns && self.seq == other.seq
    }
}
impl Eq for Due {}
impl PartialOrd for Due {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}
impl Ord for Due {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        (self.at_ns, self.seq).cmp(&(other.at_ns, other.seq))
    }
}

/// Max ring entries processed per readiness wakeup before due jobs get a
/// chance to go out (keeps the timer path from starving under load).
const RING_BATCH: usize = 4096;

/// Sends one response copy. Counts `answered_probes` on the probe's first
/// successfully sent copy and `send_failed` on failure.
fn send_copy(
    probe: &Probe,
    sock_fd: &OwnedFd,
    ifindex: u32,
    config: &SnifferConfig,
    stats: &SnifferStats,
) {
    if craft_and_send_response(probe, sock_fd, ifindex, config, stats) {
        if !probe.answered.swap(true, Ordering::Relaxed) {
            stats.answered_probes.fetch_add(1, Ordering::Relaxed);
        }
    } else {
        stats.send_failed.fetch_add(1, Ordering::Relaxed);
    }
}

fn elapsed_ns(t0: Instant) -> u64 {
    t0.elapsed().as_nanos() as u64
}

/// Userspace sniffer that drains the `PROBES` RingBuf and sends crafted
/// responses via an AF_PACKET TX socket.
///
/// Offset-0 copies are sent inline (fast path). Delayed copies and
/// retransmits are queued in a min-heap and sent by a `sleep_until` arm, so
/// a `--delay`/`--rto-profile` never blocks draining the ring. On stop,
/// pending jobs are discarded (counted in `discarded_on_stop`).
pub async fn run_sniffer(
    mut ring_buf: RingBuf<MapData>,
    iface: String,
    config: SnifferConfig,
    stats: Arc<SnifferStats>,
    stop_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let sock_fd = create_afp_socket()?;
    let ifindex = lookup_interface(&iface)?;
    let ring_fd = ring_buf.as_raw_fd();
    let mut async_fd = AsyncFd::new(ring_fd)?;
    tokio::pin!(stop_rx);

    let t0 = Instant::now();
    let mut heap: BinaryHeap<Reverse<Due>> = BinaryHeap::new();
    let mut seq: u64 = 0;
    let mut plan: Vec<u64> = Vec::with_capacity(8);
    let mut stopping = false;

    while !stopping {
        let next_due = heap
            .peek()
            .map(|Reverse(d)| t0 + Duration::from_nanos(d.at_ns));
        tokio::select! {
            _ = stop_rx.changed() => stopping = true,
            _ = tokio::time::sleep_until(next_due.unwrap_or_else(Instant::now)),
                if next_due.is_some() => {
                send_due(&mut heap, t0, &sock_fd, ifindex, &config, &stats);
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let mut drained = false;
                let mut processed = 0usize;
                loop {
                    if *stop_rx.borrow() {
                        stopping = true;
                        break;
                    }
                    if processed >= RING_BATCH {
                        break;
                    }
                    let Some(item) = ring_buf.next() else {
                        drained = true;
                        break;
                    };
                    processed += 1;
                    // The sniffer relies on the entry length (item.len()),
                    // not on a fixed reservation: TCP/ICMP entries are
                    // exactly HDR_SIZE, UDP entries HDR_SIZE + up to 944.
                    if item.len() < HDR_SIZE {
                        stats.dropped_ring.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let hdr: &ProbeEventHeader = unsafe {
                        &*(item[..HDR_SIZE].as_ptr() as *const ProbeEventHeader)
                    };
                    let payload_len = u16::from_be(hdr.udp_payload_len) as usize;
                    let payload: &[u8] = if hdr.protocol == 17
                        && payload_len > 0
                        && item.len() >= HDR_SIZE + payload_len
                    {
                        &item[HDR_SIZE..HDR_SIZE + payload_len]
                    } else {
                        b""
                    };

                    if config.closed {
                        let sent_ok = match hdr.protocol {
                            6 => craft_and_send_rst(hdr, &sock_fd, ifindex),
                            17 => craft_and_send_icmp_unreach(hdr, &sock_fd, ifindex),
                            _ => continue,
                        };
                        if sent_ok {
                            stats.closed_sent.fetch_add(1, Ordering::Relaxed);
                        } else {
                            stats.send_failed.fetch_add(1, Ordering::Relaxed);
                        }
                        continue;
                    }

                    let (ip, ports, pseq) = probe_identity(hdr);
                    let hash = schedule::probe_hash(config.seed, ip, ports, pseq);
                    let lost = schedule::plan_copies(
                        &config.schedule,
                        hdr.protocol == 6,
                        ip,
                        hash,
                        &mut plan,
                    );
                    if lost > 0 {
                        stats.lost.fetch_add(lost, Ordering::Relaxed);
                    }
                    if plan.is_empty() {
                        continue;
                    }
                    let probe = Probe::new(hdr, payload, &config);
                    // Offset-0 copies precede delayed ones in every plan.
                    let inline = plan.iter().take_while(|&&o| o == 0).count();
                    for _ in 0..inline {
                        send_copy(&probe, &sock_fd, ifindex, &config, &stats);
                    }
                    if inline == plan.len() {
                        continue;
                    }
                    let probe = Arc::new(probe);
                    let now_ns = elapsed_ns(t0);
                    for &offset_ms in &plan[inline..] {
                        if heap.len() >= config.max_pending {
                            stats.pending_dropped.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        seq += 1;
                        heap.push(Reverse(Due {
                            at_ns: now_ns + offset_ms * 1_000_000,
                            seq,
                            probe: probe.clone(),
                        }));
                    }
                }
                if drained {
                    guard.clear_ready();
                }
                // Readiness is kept when the batch limit was hit, so the
                // next iteration resumes draining right after due jobs.
                drop(guard);
                if !stopping {
                    send_due(&mut heap, t0, &sock_fd, ifindex, &config, &stats);
                }
            }
        }
    }

    // Pending jobs are discarded on stop.
    stats
        .discarded_on_stop
        .fetch_add(heap.len() as u64, Ordering::Relaxed);
    Ok(())
}

/// Max due jobs sent per call; the `sleep_until` arm re-fires immediately
/// while overdue jobs remain, interleaving with ring draining.
const SEND_BATCH: usize = 4096;

/// Sends queued jobs whose deadline has passed (at most `SEND_BATCH`).
fn send_due(
    heap: &mut BinaryHeap<Reverse<Due>>,
    t0: Instant,
    sock_fd: &OwnedFd,
    ifindex: u32,
    config: &SnifferConfig,
    stats: &SnifferStats,
) {
    let now_ns = elapsed_ns(t0);
    let mut sent = 0usize;
    while sent < SEND_BATCH && heap.peek().is_some_and(|Reverse(d)| d.at_ns <= now_ns) {
        sent += 1;
        let Some(Reverse(due)) = heap.pop() else {
            break;
        };
        send_copy(&due.probe, sock_fd, ifindex, config, stats);
    }
}

fn create_afp_socket() -> anyhow::Result<OwnedFd> {
    let fd = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Packet,
        nix::sys::socket::SockType::Raw,
        nix::sys::socket::SockFlag::empty(),
        nix::sys::socket::SockProtocol::EthAll,
    )?;

    let sndbuf_size: i32 = 32 * 1024 * 1024;
    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sndbuf_size as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(anyhow::anyhow!("failed to set SO_SNDBUF"));
    }

    Ok(fd)
}

fn lookup_interface(iface: &str) -> anyhow::Result<u32> {
    let c_iface =
        CString::new(iface).map_err(|_| anyhow::anyhow!("interface name contains null byte"))?;
    let ifindex = unsafe { libc::if_nametoindex(c_iface.as_ptr()) };
    if ifindex == 0 {
        return Err(anyhow::anyhow!("interface not found: {}", iface));
    }
    Ok(ifindex)
}

fn send_frame(
    frame: &[u8],
    sock_fd: &OwnedFd,
    dst_mac: &[u8; 6],
    ifindex: u32,
) -> anyhow::Result<()> {
    let sock_addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
        sll_ifindex: ifindex as i32,
        sll_hatype: libc::ARPHRD_ETHER,
        sll_pkttype: 0,
        sll_halen: 6,
        sll_addr: [
            dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5], 0, 0,
        ],
    };
    let link_addr = unsafe {
        nix::sys::socket::LinkAddr::from_raw(&sock_addr as *const _ as *const libc::sockaddr, None)
    }
    .ok_or_else(|| anyhow::anyhow!("failed to create LinkAddr"))?;
    nix::sys::socket::sendto(
        sock_fd.as_raw_fd(),
        frame,
        &link_addr,
        nix::sys::socket::MsgFlags::empty(),
    )?;
    Ok(())
}

fn sum_words(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

fn fold_complement(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn put_u16(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset..offset + 2].copy_from_slice(&val.to_be_bytes());
}

fn put_u32(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_be_bytes());
}

fn ipv4_csum(ip_header: &[u8]) -> u16 {
    fold_complement(sum_words(ip_header))
}

fn tcp_csum_v4(src_ip: &[u8], dst_ip: &[u8], tcp_segment: &[u8]) -> u16 {
    let mut pseudo = [0u8; 12];
    pseudo[..4].copy_from_slice(&src_ip[..4]);
    pseudo[4..8].copy_from_slice(&dst_ip[..4]);
    pseudo[9] = 6;
    let tcp_len = tcp_segment.len() as u16;
    pseudo[10..12].copy_from_slice(&tcp_len.to_be_bytes());
    fold_complement(sum_words(&pseudo) + sum_words(tcp_segment))
}

fn tcp_csum_v6(src_ip: &[u8], dst_ip: &[u8], tcp_segment: &[u8]) -> u16 {
    let mut pseudo = [0u8; 40];
    pseudo[..16].copy_from_slice(&src_ip[..16]);
    pseudo[16..32].copy_from_slice(&dst_ip[..16]);
    let tcp_len = tcp_segment.len() as u32;
    pseudo[32..36].copy_from_slice(&tcp_len.to_be_bytes());
    pseudo[39] = 6;
    fold_complement(sum_words(&pseudo) + sum_words(tcp_segment))
}

fn udp_csum_v4(src_ip: &[u8], dst_ip: &[u8], udp_segment: &[u8]) -> u16 {
    let mut pseudo = [0u8; 12];
    pseudo[..4].copy_from_slice(&src_ip[..4]);
    pseudo[4..8].copy_from_slice(&dst_ip[..4]);
    pseudo[9] = 17;
    let udp_len = udp_segment.len() as u16;
    pseudo[10..12].copy_from_slice(&udp_len.to_be_bytes());
    fold_complement(sum_words(&pseudo) + sum_words(udp_segment))
}

fn udp_csum_v6(src_ip: &[u8], dst_ip: &[u8], udp_segment: &[u8]) -> u16 {
    let mut pseudo = [0u8; 40];
    pseudo[..16].copy_from_slice(&src_ip[..16]);
    pseudo[16..32].copy_from_slice(&dst_ip[..16]);
    let udp_len = udp_segment.len() as u32;
    pseudo[32..36].copy_from_slice(&udp_len.to_be_bytes());
    pseudo[39] = 17;
    fold_complement(sum_words(&pseudo) + sum_words(udp_segment))
}

fn icmp_v4_csum(icmp_data: &[u8]) -> u16 {
    fold_complement(sum_words(icmp_data))
}

fn icmp_v6_csum(src_ip: &[u8], dst_ip: &[u8], icmp_data: &[u8]) -> u16 {
    let mut pseudo = [0u8; 40];
    pseudo[..16].copy_from_slice(&src_ip[..16]);
    pseudo[16..32].copy_from_slice(&dst_ip[..16]);
    let icmp_len = icmp_data.len() as u32;
    pseudo[32..36].copy_from_slice(&icmp_len.to_be_bytes());
    pseudo[39] = 58;
    fold_complement(sum_words(&pseudo) + sum_words(icmp_data))
}

fn fake_applies(config: &SnifferConfig, version: u8) -> bool {
    let v6 = version == 6;
    if !config.fake_ip_list.is_empty() {
        return config.fake_ip_list.iter().any(|e| e.v6 == v6);
    }
    config.fake_ip.is_some() && config.fake_ipv6 == v6
}

/// Rotating forged-source pool: picks the next pool entry matching the
/// probe's IP version (round-robin, one step per probe — all copies of a
/// probe share the chosen source). Entries with a mismatched version are
/// skipped; a pool without any matching entry yields None (real destination
/// IP).
fn pick_fake(config: &SnifferConfig, v6: bool) -> Option<[u8; 16]> {
    let matching: Vec<&FakeIpEntry> = config.fake_ip_list.iter().filter(|e| e.v6 == v6).collect();
    if matching.is_empty() {
        return None;
    }
    let idx = FAKE_ROTATE.fetch_add(1, Ordering::Relaxed) as usize;
    Some(matching[idx % matching.len()].bytes)
}

/// Response source IP of a probe, chosen once per probe: pool entry,
/// `--fake-ip` (matching version), else the probed destination.
fn pick_src_ip(hdr: &ProbeEventHeader, config: &SnifferConfig) -> [u8; 16] {
    let v6 = hdr.version == 6;
    if let Some(fake) = pick_fake(config, v6) {
        return fake;
    }
    match &config.fake_ip {
        Some(fake) if config.fake_ipv6 == v6 => *fake,
        _ => hdr.dst_ip,
    }
}

/// Flips one bit of a computed transport checksum. Falls back to a second
/// bit when the flip would produce 0x0000 (UDP treats that as "no checksum").
fn corrupt_csum(csum: u16) -> u16 {
    let bad = csum ^ 0x0001;
    if bad == 0 { csum ^ 0x0002 } else { bad }
}

fn craft_tcp_syn_ack_v4(probe: &Probe, config: &SnifferConfig) -> Vec<u8> {
    let hdr = &probe.hdr;
    let mut frame = vec![0u8; 54];
    let src_ip: [u8; 4] = probe.src_ip[..4].try_into().unwrap();

    frame[0..6].copy_from_slice(&hdr.src_mac);
    frame[6..12].copy_from_slice(&hdr.dst_mac);
    put_u16(&mut frame, 12, 0x0800);

    frame[14] = 0x45;
    put_u16(&mut frame, 16, 40);
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&src_ip);
    frame[30..34].copy_from_slice(&hdr.src_ip[..4]);
    let ip_csum = ipv4_csum(&frame[14..34]);
    put_u16(&mut frame, 24, ip_csum);

    match config.port_override {
        Some(p) => put_u16(&mut frame, 34, p),
        None => put_u16(&mut frame, 34, u16::from_be(hdr.dst_port)),
    }
    put_u16(&mut frame, 36, u16::from_be(hdr.src_port));
    let seq = probe.isn;
    put_u32(&mut frame, 38, seq);
    let ack = u32::from_be(hdr.tcp_seq).wrapping_add(config.ack_delta);
    put_u32(&mut frame, 42, ack);
    frame[46] = 0x50;
    frame[47] = config.tcp_flags;
    put_u16(&mut frame, 48, 64240);
    let tcp_csum = tcp_csum_v4(&src_ip, &hdr.src_ip[..4], &frame[34..54]);
    put_u16(
        &mut frame,
        50,
        if config.bad_csum {
            corrupt_csum(tcp_csum)
        } else {
            tcp_csum
        },
    );

    frame
}

fn craft_tcp_syn_ack_v6(probe: &Probe, config: &SnifferConfig) -> Vec<u8> {
    let hdr = &probe.hdr;
    let mut frame = vec![0u8; 74];
    let src_ip = probe.src_ip;

    frame[0..6].copy_from_slice(&hdr.src_mac);
    frame[6..12].copy_from_slice(&hdr.dst_mac);
    put_u16(&mut frame, 12, 0x86DD);

    put_u32(&mut frame, 14, 0x60000000);
    put_u16(&mut frame, 18, 20);
    frame[20] = 6;
    frame[21] = 64;
    frame[22..38].copy_from_slice(&src_ip);
    frame[38..54].copy_from_slice(&hdr.src_ip[..16]);

    match config.port_override {
        Some(p) => put_u16(&mut frame, 54, p),
        None => put_u16(&mut frame, 54, u16::from_be(hdr.dst_port)),
    }
    put_u16(&mut frame, 56, u16::from_be(hdr.src_port));
    let seq = probe.isn;
    put_u32(&mut frame, 58, seq);
    let ack = u32::from_be(hdr.tcp_seq).wrapping_add(config.ack_delta);
    put_u32(&mut frame, 62, ack);
    frame[66] = 0x50;
    frame[67] = config.tcp_flags;
    put_u16(&mut frame, 68, 64240);
    let tcp_csum = tcp_csum_v6(&src_ip, &hdr.src_ip[..16], &frame[54..74]);
    put_u16(
        &mut frame,
        70,
        if config.bad_csum {
            corrupt_csum(tcp_csum)
        } else {
            tcp_csum
        },
    );

    frame
}

fn craft_udp_echo_v4(probe: &Probe, config: &SnifferConfig) -> Vec<u8> {
    let hdr = &probe.hdr;
    let payload: &[u8] = &probe.payload;
    let payload_len = payload.len();
    let mut frame = vec![0u8; 42 + payload_len];
    let src_ip: [u8; 4] = probe.src_ip[..4].try_into().unwrap();

    frame[0..6].copy_from_slice(&hdr.src_mac);
    frame[6..12].copy_from_slice(&hdr.dst_mac);
    put_u16(&mut frame, 12, 0x0800);

    frame[14] = 0x45;
    let tot_len = (20 + 8 + payload_len) as u16;
    put_u16(&mut frame, 16, tot_len);
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&src_ip);
    frame[30..34].copy_from_slice(&hdr.src_ip[..4]);
    let ip_csum = ipv4_csum(&frame[14..34]);
    put_u16(&mut frame, 24, ip_csum);

    let udp_start = 34;
    match config.port_override {
        Some(p) => put_u16(&mut frame, udp_start, p),
        None => put_u16(&mut frame, udp_start, u16::from_be(hdr.dst_port)),
    }
    put_u16(&mut frame, udp_start + 2, u16::from_be(hdr.src_port));
    let udp_len = (8 + payload_len) as u16;
    put_u16(&mut frame, udp_start + 4, udp_len);
    if !payload.is_empty() {
        frame[udp_start + 8..udp_start + 8 + payload_len].copy_from_slice(payload);
    }
    let udp_csum = udp_csum_v4(
        &src_ip,
        &hdr.src_ip[..4],
        &frame[udp_start..udp_start + 8 + payload_len],
    );
    put_u16(
        &mut frame,
        udp_start + 6,
        if config.bad_csum {
            corrupt_csum(udp_csum)
        } else {
            udp_csum
        },
    );

    frame
}

fn craft_udp_echo_v6(probe: &Probe, config: &SnifferConfig) -> Vec<u8> {
    let hdr = &probe.hdr;
    let payload: &[u8] = &probe.payload;
    let payload_len = payload.len();
    let mut frame = vec![0u8; 62 + payload_len];
    let src_ip = probe.src_ip;

    frame[0..6].copy_from_slice(&hdr.src_mac);
    frame[6..12].copy_from_slice(&hdr.dst_mac);
    put_u16(&mut frame, 12, 0x86DD);

    put_u32(&mut frame, 14, 0x60000000);
    let payload_len_field = (8 + payload_len) as u16;
    put_u16(&mut frame, 18, payload_len_field);
    frame[20] = 17;
    frame[21] = 64;
    frame[22..38].copy_from_slice(&src_ip);
    frame[38..54].copy_from_slice(&hdr.src_ip[..16]);

    let udp_start = 54;
    match config.port_override {
        Some(p) => put_u16(&mut frame, udp_start, p),
        None => put_u16(&mut frame, udp_start, u16::from_be(hdr.dst_port)),
    }
    put_u16(&mut frame, udp_start + 2, u16::from_be(hdr.src_port));
    let udp_len = (8 + payload_len) as u16;
    put_u16(&mut frame, udp_start + 4, udp_len);
    if !payload.is_empty() {
        frame[udp_start + 8..udp_start + 8 + payload_len].copy_from_slice(payload);
    }
    let udp_csum = udp_csum_v6(
        &src_ip,
        &hdr.src_ip[..16],
        &frame[udp_start..udp_start + 8 + payload_len],
    );
    put_u16(
        &mut frame,
        udp_start + 6,
        if config.bad_csum {
            corrupt_csum(udp_csum)
        } else {
            udp_csum
        },
    );

    frame
}

fn craft_icmp_reply_v4(probe: &Probe, config: &SnifferConfig) -> Vec<u8> {
    let hdr = &probe.hdr;
    let mut frame = vec![0u8; 58];
    let src_ip: [u8; 4] = probe.src_ip[..4].try_into().unwrap();

    frame[0..6].copy_from_slice(&hdr.src_mac);
    frame[6..12].copy_from_slice(&hdr.dst_mac);
    put_u16(&mut frame, 12, 0x0800);

    frame[14] = 0x45;
    put_u16(&mut frame, 16, 44);
    frame[22] = 64;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&src_ip);
    frame[30..34].copy_from_slice(&hdr.src_ip[..4]);
    let ip_csum = ipv4_csum(&frame[14..34]);
    put_u16(&mut frame, 24, ip_csum);

    let icmp_start = 34;
    frame[icmp_start] = 0;
    frame[icmp_start + 1] = 0;
    frame[icmp_start + 4..icmp_start + 6].copy_from_slice(&hdr.icmp_id);
    frame[icmp_start + 6..icmp_start + 8].copy_from_slice(&hdr.icmp_seq);
    frame[icmp_start + 8..icmp_start + 24].copy_from_slice(&hdr.icmp_payload);
    let icmp_csum = icmp_v4_csum(&frame[icmp_start..icmp_start + 24]);
    put_u16(
        &mut frame,
        icmp_start + 2,
        if config.bad_csum {
            corrupt_csum(icmp_csum)
        } else {
            icmp_csum
        },
    );

    frame
}

fn craft_icmp_reply_v6(probe: &Probe, config: &SnifferConfig) -> Vec<u8> {
    let hdr = &probe.hdr;
    let mut frame = vec![0u8; 78];
    let src_ip = probe.src_ip;

    frame[0..6].copy_from_slice(&hdr.src_mac);
    frame[6..12].copy_from_slice(&hdr.dst_mac);
    put_u16(&mut frame, 12, 0x86DD);

    put_u32(&mut frame, 14, 0x60000000);
    put_u16(&mut frame, 18, 24);
    frame[20] = 58;
    frame[21] = 64;
    frame[22..38].copy_from_slice(&src_ip);
    frame[38..54].copy_from_slice(&hdr.src_ip[..16]);

    let icmp_start = 54;
    frame[icmp_start] = 129;
    frame[icmp_start + 1] = 0;
    frame[icmp_start + 4..icmp_start + 6].copy_from_slice(&hdr.icmp_id);
    frame[icmp_start + 6..icmp_start + 8].copy_from_slice(&hdr.icmp_seq);
    frame[icmp_start + 8..icmp_start + 24].copy_from_slice(&hdr.icmp_payload);
    let icmp_csum = icmp_v6_csum(
        &src_ip,
        &hdr.src_ip[..16],
        &frame[icmp_start..icmp_start + 24],
    );
    put_u16(
        &mut frame,
        icmp_start + 2,
        if config.bad_csum {
            corrupt_csum(icmp_csum)
        } else {
            icmp_csum
        },
    );

    frame
}

fn craft_tcp_rst_v4(hdr: &ProbeEventHeader) -> Vec<u8> {
    let mut frame = vec![0u8; 54];

    frame[0..6].copy_from_slice(&hdr.src_mac);
    frame[6..12].copy_from_slice(&hdr.dst_mac);
    put_u16(&mut frame, 12, 0x0800);

    frame[14] = 0x45;
    put_u16(&mut frame, 16, 40);
    frame[22] = 64;
    frame[23] = 6;
    frame[26..30].copy_from_slice(&hdr.dst_ip[..4]);
    frame[30..34].copy_from_slice(&hdr.src_ip[..4]);
    let ip_csum = ipv4_csum(&frame[14..34]);
    put_u16(&mut frame, 24, ip_csum);

    put_u16(&mut frame, 34, u16::from_be(hdr.dst_port));
    put_u16(&mut frame, 36, u16::from_be(hdr.src_port));
    let seq = u32::from_be(hdr.tcp_seq).wrapping_add(1);
    put_u32(&mut frame, 38, seq);
    frame[46] = 0x50;
    frame[47] = 0x04;
    let tcp_csum = tcp_csum_v4(&hdr.dst_ip[..4], &hdr.src_ip[..4], &frame[34..54]);
    put_u16(&mut frame, 50, tcp_csum);

    frame
}

fn craft_tcp_rst_v6(hdr: &ProbeEventHeader) -> Vec<u8> {
    let mut frame = vec![0u8; 74];

    frame[0..6].copy_from_slice(&hdr.src_mac);
    frame[6..12].copy_from_slice(&hdr.dst_mac);
    put_u16(&mut frame, 12, 0x86DD);

    put_u32(&mut frame, 14, 0x60000000);
    put_u16(&mut frame, 18, 20);
    frame[20] = 6;
    frame[21] = 64;
    frame[22..38].copy_from_slice(&hdr.dst_ip[..16]);
    frame[38..54].copy_from_slice(&hdr.src_ip[..16]);

    put_u16(&mut frame, 54, u16::from_be(hdr.dst_port));
    put_u16(&mut frame, 56, u16::from_be(hdr.src_port));
    let seq = u32::from_be(hdr.tcp_seq).wrapping_add(1);
    put_u32(&mut frame, 58, seq);
    frame[66] = 0x50;
    frame[67] = 0x04;
    let tcp_csum = tcp_csum_v6(&hdr.dst_ip[..16], &hdr.src_ip[..16], &frame[54..74]);
    put_u16(&mut frame, 70, tcp_csum);

    frame
}

fn craft_icmp_unreach_v4(hdr: &ProbeEventHeader) -> Vec<u8> {
    let payload_len = u16::from_be(hdr.udp_payload_len) as usize;
    let mut frame = vec![0u8; 70];

    frame[0..6].copy_from_slice(&hdr.src_mac);
    frame[6..12].copy_from_slice(&hdr.dst_mac);
    put_u16(&mut frame, 12, 0x0800);

    frame[14] = 0x45;
    put_u16(&mut frame, 16, 56);
    frame[22] = 64;
    frame[23] = 1;
    frame[26..30].copy_from_slice(&hdr.dst_ip[..4]);
    frame[30..34].copy_from_slice(&hdr.src_ip[..4]);
    let ip_csum = ipv4_csum(&frame[14..34]);
    put_u16(&mut frame, 24, ip_csum);

    let icmp_start = 34;
    frame[icmp_start] = 3;
    frame[icmp_start + 1] = 3;

    let orig_ip_start = icmp_start + 8;
    frame[orig_ip_start] = 0x45;
    let orig_tot_len = (20 + 8 + payload_len) as u16;
    put_u16(&mut frame, orig_ip_start + 2, orig_tot_len);
    frame[orig_ip_start + 8] = 64;
    frame[orig_ip_start + 9] = 17;
    frame[orig_ip_start + 12..orig_ip_start + 16].copy_from_slice(&hdr.src_ip[..4]);
    frame[orig_ip_start + 16..orig_ip_start + 20].copy_from_slice(&hdr.dst_ip[..4]);
    let orig_ip_csum = ipv4_csum(&frame[orig_ip_start..orig_ip_start + 20]);
    put_u16(&mut frame, orig_ip_start + 10, orig_ip_csum);

    let orig_udp_start = orig_ip_start + 20;
    put_u16(&mut frame, orig_udp_start, u16::from_be(hdr.src_port));
    put_u16(&mut frame, orig_udp_start + 2, u16::from_be(hdr.dst_port));
    let orig_udp_len = (8 + payload_len) as u16;
    put_u16(&mut frame, orig_udp_start + 4, orig_udp_len);

    let icmp_csum = icmp_v4_csum(&frame[icmp_start..icmp_start + 36]);
    put_u16(&mut frame, icmp_start + 2, icmp_csum);

    frame
}

/// Splits an assembled IPv4 response into two IP fragments after the first
/// 8 transport bytes (frame offset 42 = Ethernet + IP header + 8 transport
/// bytes): fragment 1 carries MF=1 with tot_len=28, fragment 2 carries the
/// remainder with frag_offset=1 (8-byte units). Each fragment's IP checksum
/// is recomputed; the IP ID stays shared (0). Frames with nothing after the
/// split point are returned unfragmented.
fn fragment_frame(frame: &[u8]) -> Vec<Vec<u8>> {
    if frame.len() <= 42 {
        return vec![frame.to_vec()];
    }

    let mut f1 = vec![0u8; 42];
    f1[..34].copy_from_slice(&frame[..34]);
    f1[34..42].copy_from_slice(&frame[34..42]);
    put_u16(&mut f1, 16, 28);
    put_u16(&mut f1, 20, 0x2000);
    let c1 = ipv4_csum(&f1[14..34]);
    put_u16(&mut f1, 24, c1);

    let remainder = frame.len() - 42;
    let mut f2 = vec![0u8; 34 + remainder];
    f2[..34].copy_from_slice(&frame[..34]);
    f2[34..].copy_from_slice(&frame[42..]);
    put_u16(&mut f2, 16, (20 + remainder) as u16);
    put_u16(&mut f2, 20, 0x0001);
    let c2 = ipv4_csum(&f2[14..34]);
    put_u16(&mut f2, 24, c2);

    vec![f1, f2]
}

fn craft_and_send_response(
    probe: &Probe,
    sock_fd: &OwnedFd,
    ifindex: u32,
    config: &SnifferConfig,
    stats: &SnifferStats,
) -> bool {
    let hdr = &probe.hdr;
    let frame = match (hdr.version, hdr.protocol) {
        (4, 6) => craft_tcp_syn_ack_v4(probe, config),
        (6, 6) => craft_tcp_syn_ack_v6(probe, config),
        (4, 17) => craft_udp_echo_v4(probe, config),
        (6, 17) => craft_udp_echo_v6(probe, config),
        (4, 1) => craft_icmp_reply_v4(probe, config),
        (6, 58) => craft_icmp_reply_v6(probe, config),
        _ => return false,
    };
    let frames: Vec<Vec<u8>> = if config.fragment && hdr.version == 4 {
        fragment_frame(&frame)
    } else {
        vec![frame]
    };
    let mut all_sent = true;
    for f in &frames {
        if send_frame(f, sock_fd, &hdr.src_mac, ifindex).is_err() {
            all_sent = false;
        }
    }
    if all_sent {
        stats.sent.fetch_add(1, Ordering::Relaxed);
        if fake_applies(config, hdr.version) {
            stats.fake_sent.fetch_add(1, Ordering::Relaxed);
        }
        if frames.len() > 1 {
            stats
                .frag_sent
                .fetch_add(frames.len() as u64, Ordering::Relaxed);
        }
    }
    all_sent
}

fn craft_and_send_rst(hdr: &ProbeEventHeader, sock_fd: &OwnedFd, ifindex: u32) -> bool {
    let frame = match hdr.version {
        4 => craft_tcp_rst_v4(hdr),
        6 => craft_tcp_rst_v6(hdr),
        _ => return false,
    };
    send_frame(&frame, sock_fd, &hdr.src_mac, ifindex).is_ok()
}

fn craft_and_send_icmp_unreach(hdr: &ProbeEventHeader, sock_fd: &OwnedFd, ifindex: u32) -> bool {
    if hdr.version != 4 {
        return false;
    }
    let frame = craft_icmp_unreach_v4(hdr);
    send_frame(&frame, sock_fd, &hdr.src_mac, ifindex).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_pool() -> SnifferConfig {
        let entry = |last: u8| {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&[10, 99, 99, last]);
            FakeIpEntry { bytes, v6: false }
        };
        SnifferConfig {
            schedule: ScheduleConfig {
                count: 1,
                delay_ms: 0,
                rto: None,
                loss_perc: 0.0,
                jitter_ms: 0,
            },
            max_pending: 1,
            seed: 0,
            fake_ip: None,
            fake_ipv6: false,
            closed: false,
            tcp_flags: 0x12,
            bad_csum: false,
            ack_delta: 1,
            port_override: None,
            fake_ip_list: vec![entry(1), entry(2), entry(3)],
            fragment: false,
        }
    }

    fn tcp_probe_hdr() -> ProbeEventHeader {
        // SAFETY: plain-old-data header (byte arrays and integers only).
        let mut hdr: ProbeEventHeader = unsafe { std::mem::zeroed() };
        hdr.protocol = 6;
        hdr.version = 4;
        hdr.src_ip[..4].copy_from_slice(&[10, 0, 0, 1]);
        hdr.dst_ip[..4].copy_from_slice(&[10, 0, 0, 2]);
        hdr.src_port = 40000u16.to_be();
        hdr.dst_port = 80u16.to_be();
        hdr.tcp_seq = 12345u32.to_be();
        hdr
    }

    #[test]
    fn all_copies_of_a_probe_are_identical() {
        let config = config_with_pool();
        let probe = Probe::new(&tcp_probe_hdr(), b"", &config);
        let first = craft_tcp_syn_ack_v4(&probe, &config);
        for _ in 0..5 {
            assert_eq!(craft_tcp_syn_ack_v4(&probe, &config), first);
        }
        // the next probe advances ISN and the fake-source rotation
        let other = Probe::new(&tcp_probe_hdr(), b"", &config);
        assert_ne!(other.isn, probe.isn);
        assert_ne!(other.src_ip, probe.src_ip);
        assert_eq!(&first[26..30], &probe.src_ip[..4]);
        assert_eq!(
            u32::from_be_bytes(first[38..42].try_into().unwrap()),
            probe.isn
        );
    }

    #[test]
    fn answered_flag_counts_first_sent_copy_once() {
        let probe = Arc::new(Probe::new(&tcp_probe_hdr(), b"", &config_with_pool()));
        let copies: Vec<_> = (0..4).map(|_| probe.clone()).collect();
        let first_sends = copies
            .iter()
            .filter(|p| !p.answered.swap(true, Ordering::Relaxed))
            .count();
        assert_eq!(first_sends, 1);
    }

    #[test]
    fn queue_entry_sizes() {
        // Documented in the README (memory of the delayed-copy queue).
        assert_eq!(std::mem::size_of::<Reverse<Due>>(), 24);
        assert!(
            std::mem::size_of::<Probe>() <= 120,
            "{}",
            std::mem::size_of::<Probe>()
        );
    }

    #[test]
    fn probe_identity_distinguishes_ports_and_seq() {
        let a = tcp_probe_hdr();
        let mut b = a;
        b.tcp_seq = 12346u32.to_be();
        let mut c = a;
        c.dst_port = 81u16.to_be();
        assert_ne!(probe_identity(&a), probe_identity(&b));
        assert_ne!(probe_identity(&a), probe_identity(&c));
        assert_eq!(probe_identity(&a), probe_identity(&tcp_probe_hdr()));
    }
}

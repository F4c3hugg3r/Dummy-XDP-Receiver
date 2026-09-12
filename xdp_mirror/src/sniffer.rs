use std::{
    ffi::CString,
    os::fd::{AsRawFd, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use aya::maps::{MapData, RingBuf};
use nix::sys::socket::SockaddrLike;
use tokio::{io::unix::AsyncFd, sync::watch};
use xdp_mirror_common::ProbeEventHeader;

const HDR_SIZE: usize = std::mem::size_of::<ProbeEventHeader>();

static SEQ_COUNTER: AtomicU64 = AtomicU64::new(1);
static SEQ_BASE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

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

pub struct SnifferConfig {
    pub count: u32,
    pub delay: u64,
    pub fake_ip: Option<[u8; 16]>,
    pub fake_ipv6: bool,
    pub closed: bool,
}

#[derive(Default)]
pub struct SnifferStats {
    pub sent: AtomicU64,
    pub closed_sent: AtomicU64,
    pub fake_sent: AtomicU64,
    pub dropped_ring: AtomicU64,
}

/// Userspace sniffer that drains the `PROBES` RingBuf and sends crafted
/// responses via an AF_PACKET TX socket.
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

    loop {
        tokio::select! {
            _ = stop_rx.changed() => break,
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                while let Some(item) = ring_buf.next() {
                    if *stop_rx.borrow() {
                        break;
                    }
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
                            _ => false,
                        };
                        if sent_ok {
                            stats.closed_sent.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        for _ in 0..config.count {
                            if config.delay > 0 {
                                tokio::select! {
                                    _ = tokio::time::sleep(Duration::from_millis(config.delay)) => {}
                                    _ = stop_rx.changed() => return Ok(()),
                                }
                            }
                            if *stop_rx.borrow() {
                                break;
                            }
                            craft_and_send_response(
                                hdr,
                                payload,
                                &sock_fd,
                                ifindex,
                                &config,
                                &stats,
                            );
                        }
                    }
                }
                guard.clear_ready();
            }
        }
    }

    Ok(())
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
    config.fake_ip.is_some() && config.fake_ipv6 == (version == 6)
}

fn src_ip_v4(hdr: &ProbeEventHeader, config: &SnifferConfig) -> [u8; 4] {
    match &config.fake_ip {
        Some(fake) if !config.fake_ipv6 => [fake[0], fake[1], fake[2], fake[3]],
        _ => [hdr.dst_ip[0], hdr.dst_ip[1], hdr.dst_ip[2], hdr.dst_ip[3]],
    }
}

fn src_ip_v6(hdr: &ProbeEventHeader, config: &SnifferConfig) -> [u8; 16] {
    match &config.fake_ip {
        Some(fake) if config.fake_ipv6 => *fake,
        _ => hdr.dst_ip,
    }
}

fn craft_tcp_syn_ack_v4(hdr: &ProbeEventHeader, config: &SnifferConfig) -> Vec<u8> {
    let mut frame = vec![0u8; 54];
    let src_ip = src_ip_v4(hdr, config);

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

    put_u16(&mut frame, 34, u16::from_be(hdr.dst_port));
    put_u16(&mut frame, 36, u16::from_be(hdr.src_port));
    let seq = next_isn();
    put_u32(&mut frame, 38, seq);
    let ack = u32::from_be(hdr.tcp_seq).wrapping_add(1);
    put_u32(&mut frame, 42, ack);
    frame[46] = 0x50;
    frame[47] = 0x12;
    put_u16(&mut frame, 48, 64240);
    let tcp_csum = tcp_csum_v4(&src_ip, &hdr.src_ip[..4], &frame[34..54]);
    put_u16(&mut frame, 50, tcp_csum);

    frame
}

fn craft_tcp_syn_ack_v6(hdr: &ProbeEventHeader, config: &SnifferConfig) -> Vec<u8> {
    let mut frame = vec![0u8; 74];
    let src_ip = src_ip_v6(hdr, config);

    frame[0..6].copy_from_slice(&hdr.src_mac);
    frame[6..12].copy_from_slice(&hdr.dst_mac);
    put_u16(&mut frame, 12, 0x86DD);

    put_u32(&mut frame, 14, 0x60000000);
    put_u16(&mut frame, 18, 20);
    frame[20] = 6;
    frame[21] = 64;
    frame[22..38].copy_from_slice(&src_ip);
    frame[38..54].copy_from_slice(&hdr.src_ip[..16]);

    put_u16(&mut frame, 54, u16::from_be(hdr.dst_port));
    put_u16(&mut frame, 56, u16::from_be(hdr.src_port));
    let seq = next_isn();
    put_u32(&mut frame, 58, seq);
    let ack = u32::from_be(hdr.tcp_seq).wrapping_add(1);
    put_u32(&mut frame, 62, ack);
    frame[66] = 0x50;
    frame[67] = 0x12;
    put_u16(&mut frame, 68, 64240);
    let tcp_csum = tcp_csum_v6(&src_ip, &hdr.src_ip[..16], &frame[54..74]);
    put_u16(&mut frame, 70, tcp_csum);

    frame
}

fn craft_udp_echo_v4(hdr: &ProbeEventHeader, payload: &[u8], config: &SnifferConfig) -> Vec<u8> {
    let payload_len = payload.len();
    let mut frame = vec![0u8; 42 + payload_len];
    let src_ip = src_ip_v4(hdr, config);

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
    put_u16(&mut frame, udp_start, u16::from_be(hdr.dst_port));
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
    put_u16(&mut frame, udp_start + 6, udp_csum);

    frame
}

fn craft_udp_echo_v6(hdr: &ProbeEventHeader, payload: &[u8], config: &SnifferConfig) -> Vec<u8> {
    let payload_len = payload.len();
    let mut frame = vec![0u8; 62 + payload_len];
    let src_ip = src_ip_v6(hdr, config);

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
    put_u16(&mut frame, udp_start, u16::from_be(hdr.dst_port));
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
    put_u16(&mut frame, udp_start + 6, udp_csum);

    frame
}

fn craft_icmp_reply_v4(hdr: &ProbeEventHeader, config: &SnifferConfig) -> Vec<u8> {
    let mut frame = vec![0u8; 58];
    let src_ip = src_ip_v4(hdr, config);

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
    put_u16(&mut frame, icmp_start + 2, icmp_csum);

    frame
}

fn craft_icmp_reply_v6(hdr: &ProbeEventHeader, config: &SnifferConfig) -> Vec<u8> {
    let mut frame = vec![0u8; 78];
    let src_ip = src_ip_v6(hdr, config);

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
    put_u16(&mut frame, icmp_start + 2, icmp_csum);

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

fn craft_and_send_response(
    hdr: &ProbeEventHeader,
    payload: &[u8],
    sock_fd: &OwnedFd,
    ifindex: u32,
    config: &SnifferConfig,
    stats: &SnifferStats,
) {
    let frame = match (hdr.version, hdr.protocol) {
        (4, 6) => craft_tcp_syn_ack_v4(hdr, config),
        (6, 6) => craft_tcp_syn_ack_v6(hdr, config),
        (4, 17) => craft_udp_echo_v4(hdr, payload, config),
        (6, 17) => craft_udp_echo_v6(hdr, payload, config),
        (4, 1) => craft_icmp_reply_v4(hdr, config),
        (6, 58) => craft_icmp_reply_v6(hdr, config),
        _ => return,
    };
    if send_frame(&frame, sock_fd, &hdr.src_mac, ifindex).is_ok() {
        stats.sent.fetch_add(1, Ordering::Relaxed);
        if fake_applies(config, hdr.version) {
            stats.fake_sent.fetch_add(1, Ordering::Relaxed);
        }
    }
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

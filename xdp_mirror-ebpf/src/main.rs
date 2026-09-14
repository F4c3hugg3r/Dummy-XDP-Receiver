#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    cty::c_void,
    helpers::{bpf_get_prandom_u32, bpf_xdp_adjust_tail, bpf_xdp_load_bytes},
    macros::{map, xdp},
    maps::{Array, PerCpuArray, RingBuf},
    programs::XdpContext,
};
use core::mem;
use xdp_mirror_common::{Config, ProbeEventHeader, Stats};

#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

#[map]
static STATS: PerCpuArray<Stats> = PerCpuArray::with_max_entries(1, 0);

#[map]
static PROBES: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct EthHdr {
    pub dst_addr: [u8; 6],
    pub src_addr: [u8; 6],
    pub ether_type: u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Ipv4Hdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub proto: u8,
    pub check: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Ipv6Hdr {
    pub version_tc_flow: u32,
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TcpHdr {
    pub source: u16,
    pub dest: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub doff_res: u8,
    pub flags: u8,
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UdpHdr {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_ACK: u8 = 0x10;
const ICMPV4_ECHO_REQUEST: u8 = 8;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV4_ECHO_REPLY: u8 = 0;
const ICMPV6_ECHO_REPLY: u8 = 129;
const ICMP_ECHO_MSG_LEN: usize = 24;
const ICMP_ERROR_V4_LEN: usize = 36; // 8 ICMP header + 20 orig IP + 8 orig UDP
const ICMP_ERROR_V6_LEN: usize = 56; // 8 ICMPv6 header + 40 orig IPv6 + 8 orig UDP
// Fixed reservation size per ring entry. aya's RingBuf verifier requires a
// compile-time-constant size, so we reserve a fixed 1024 bytes for every
// entry (header + optional UDP payload up to 944 bytes). TCP/ICMP entries
// only use 80 bytes but still consume 1024 in the ring.
const PROBE_ENTRY_SIZE: usize = 1024;

enum Action {
    Mirror,
    NoResponse,
    IcmpError,
    PushRing,
    Drop,
}

const ICMP_V4_ERRORS: [(u8, u8); 5] = [
    (3, 3),  // port-unreach
    (3, 13), // admin-prohibited
    (3, 1),  // host-unreach
    (3, 0),  // net-unreach
    (11, 0), // time-exceeded
];

const ICMP_V6_ERRORS: [(u8, u8); 5] = [
    (1, 4), // port-unreach
    (1, 1), // admin-prohibited
    (1, 3), // host-unreach
    (1, 0), // net-unreach
    (3, 0), // time-exceeded
];

#[inline(always)]
fn decide(config: &Config, dst_ip_even: bool, no_rsp: bool, is_udp: bool) -> Action {
    match config.mode {
        1 => Action::PushRing,
        2 => {
            if dst_ip_even {
                if no_rsp {
                    Action::NoResponse
                } else {
                    Action::Mirror
                }
            } else if is_udp && config.icmp_error_type != 0 {
                Action::IcmpError
            } else {
                Action::PushRing
            }
        }
        _ => {
            let is_hit = if config.validation_mode != 0 {
                dst_ip_even
            } else {
                let rnd = unsafe { bpf_get_prandom_u32() };
                rnd % 100 < config.response_probability
            };
            if is_hit {
                if no_rsp {
                    Action::NoResponse
                } else {
                    Action::Mirror
                }
            } else if is_udp && config.icmp_error_type != 0 {
                Action::IcmpError
            } else {
                Action::Drop
            }
        }
    }
}

#[inline(always)]
fn icmp_type_code(config: &Config, version: u8) -> (u8, u8) {
    let idx = if config.icmp_error_type == 6 {
        let i = if let Some(stats) = STATS.get_ptr_mut(0) {
            let v = unsafe { (*stats).icmp_error_tx };
            unsafe {
                (*stats).icmp_error_tx = v.wrapping_add(1);
            }
            v as usize
        } else {
            0
        };
        i % 5
    } else {
        (config.icmp_error_type - 1) as usize
    };
    // Match instead of array indexing: a runtime index on a fixed-size
    // array generates a panic_bounds_check handler in .text.unlikely.,
    // which bpf-linker mishandles (creates BTF func_info but not a
    // subprogram), causing the kernel verifier to reject the program.
    // const array indexing with a literal index is compile-time folded.
    let (v4, v6) = match idx {
        0 => (ICMP_V4_ERRORS[0], ICMP_V6_ERRORS[0]), // port-unreach
        1 => (ICMP_V4_ERRORS[1], ICMP_V6_ERRORS[1]), // admin-prohibited
        2 => (ICMP_V4_ERRORS[2], ICMP_V6_ERRORS[2]), // host-unreach
        3 => (ICMP_V4_ERRORS[3], ICMP_V6_ERRORS[3]), // net-unreach
        _ => (ICMP_V4_ERRORS[4], ICMP_V6_ERRORS[4]), // time-exceeded
    };
    if version == 4 { v4 } else { v6 }
}

#[inline(always)]
fn proto_matches(config_proto: u32, ip_proto: u8, ipv6: bool) -> bool {
    match config_proto {
        0 => true,
        1 => ip_proto == IPPROTO_TCP,
        2 => ip_proto == IPPROTO_UDP,
        3 => ip_proto == if ipv6 { IPPROTO_ICMPV6 } else { IPPROTO_ICMP },
        _ => true,
    }
}

#[inline(always)]
fn expand_v4(addr: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&addr.to_ne_bytes());
    out
}

#[xdp]
pub fn xdp_mirror(ctx: XdpContext) -> u32 {
    match try_xdp_mirror(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(xdp_action::XDP_DROP);
    }

    Ok((start + offset) as *mut T)
}

fn try_xdp_mirror(ctx: XdpContext) -> Result<u32, u32> {
    if let Some(stats) = STATS.get_ptr_mut(0) {
        unsafe { (*stats).rx += 1 };
    }

    let config = if let Some(config) = CONFIG.get(0) {
        *config
    } else {
        return Ok(xdp_action::XDP_DROP);
    };

    let ipv6_mode = config.ipv6 != 0;

    let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;
    let expected_ether_type = if ipv6_mode {
        u16::from_be(ETH_P_IPV6)
    } else {
        u16::from_be(ETH_P_IP)
    };
    if unsafe { (*eth_hdr).ether_type } != expected_ether_type {
        return Ok(xdp_action::XDP_PASS);
    }

    let src_mac = unsafe { (*eth_hdr).src_addr };
    let dst_mac = unsafe { (*eth_hdr).dst_addr };

    if ipv6_mode {
        let ipv6_hdr: *const Ipv6Hdr = ptr_at(&ctx, mem::size_of::<EthHdr>())?;
        let ip_proto = unsafe { (*ipv6_hdr).next_header };
        if !proto_matches(config.protocol, ip_proto, true) {
            return Ok(xdp_action::XDP_PASS);
        }
        return match ip_proto {
            IPPROTO_TCP => handle_tcp_v6(&ctx, ipv6_hdr, src_mac, dst_mac, &config),
            IPPROTO_UDP => handle_udp_v6(&ctx, ipv6_hdr, src_mac, dst_mac, &config),
            IPPROTO_ICMPV6 => handle_icmp_v6(&ctx, ipv6_hdr, src_mac, dst_mac, &config),
            _ => Ok(xdp_action::XDP_PASS),
        };
    }

    let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, mem::size_of::<EthHdr>())?;
    let ip_proto = unsafe { (*ipv4_hdr).proto };
    if !proto_matches(config.protocol, ip_proto, false) {
        return Ok(xdp_action::XDP_PASS);
    }
    let ihl = unsafe { (*ipv4_hdr).version_ihl } & 0x0F;
    let ip_hdr_len = (ihl as usize) * 4;
    match ip_proto {
        IPPROTO_TCP => handle_tcp_v4(&ctx, ipv4_hdr, ip_hdr_len, src_mac, dst_mac, &config),
        IPPROTO_UDP => handle_udp_v4(&ctx, ipv4_hdr, ip_hdr_len, src_mac, dst_mac, &config),
        IPPROTO_ICMP => handle_icmp_v4(&ctx, ipv4_hdr, ip_hdr_len, src_mac, dst_mac, &config),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
fn handle_tcp_v4(
    ctx: &XdpContext,
    ipv4_hdr: *const Ipv4Hdr,
    ip_hdr_len: usize,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    config: &Config,
) -> Result<u32, u32> {
    let tcp_hdr: *const TcpHdr = ptr_at(ctx, mem::size_of::<EthHdr>() + ip_hdr_len)?;

    if config.validation_mode != 0
        && (unsafe { (*tcp_hdr).flags } & TCP_FLAG_RST != 0)
        && let Some(stats) = STATS.get_ptr_mut(0)
    {
        unsafe { (*stats).rst_packets += 1 };
    }

    if unsafe { (*tcp_hdr).flags } & TCP_FLAG_SYN == 0 {
        return Ok(xdp_action::XDP_DROP);
    }

    if let Some(stats) = STATS.get_ptr_mut(0) {
        unsafe { (*stats).valid_syn += 1 };
    }

    let dst_addr_be = u32::from_be(unsafe { (*ipv4_hdr).dst_addr });
    let dst_ip_even = dst_addr_be % 2 == 0;
    let no_rsp = dst_addr_be % 100 < config.no_rsp_perc;

    match decide(config, dst_ip_even, no_rsp, false) {
        Action::Mirror => {
            let src_ip = unsafe { (*ipv4_hdr).src_addr };
            let dst_ip = unsafe { (*ipv4_hdr).dst_addr };
            let src_port = unsafe { (*tcp_hdr).source };
            let dst_port = unsafe { (*tcp_hdr).dest };
            let seq = unsafe { u32::from_be((*tcp_hdr).seq) };

            let new_len =
                mem::size_of::<EthHdr>() + mem::size_of::<Ipv4Hdr>() + mem::size_of::<TcpHdr>();
            let old_len = ctx.data_end() - ctx.data();
            let delta = (new_len as isize) - (old_len as isize);

            if delta != 0 {
                let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta as i32) };
                if ret != 0 {
                    return Err(xdp_action::XDP_ABORTED);
                }
            }

            let eth_hdr: *mut EthHdr = ptr_at(ctx, 0)?;
            let ip: *mut Ipv4Hdr = ptr_at(ctx, mem::size_of::<EthHdr>())?;
            let tcp: *mut TcpHdr =
                ptr_at(ctx, mem::size_of::<EthHdr>() + mem::size_of::<Ipv4Hdr>())?;

            unsafe {
                (*eth_hdr).src_addr = dst_mac;
                (*eth_hdr).dst_addr = src_mac;

                (*ip).version_ihl = 0x45;
                (*ip).tot_len = u16::to_be(40);
                (*ip).src_addr = dst_ip;
                (*ip).dst_addr = src_ip;
                (*ip).check = 0;
                (*ip).check = ipv4_csum(ip);

                (*tcp).source = dst_port;
                (*tcp).dest = src_port;
                (*tcp).seq = bpf_get_prandom_u32();
                (*tcp).ack_seq = u32::to_be(seq + 1);
                (*tcp).doff_res = 0x50;
                (*tcp).flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
                (*tcp).window = u16::to_be(64240);
                (*tcp).check = 0;
                (*tcp).urg_ptr = 0;
                (*tcp).check = tcp_v4_csum(ip, tcp);
            }

            if let Some(stats) = STATS.get_ptr_mut(0) {
                unsafe { (*stats).tx += 1 };
            }

            Ok(xdp_action::XDP_TX)
        }
        Action::PushRing => {
            let hdr = ProbeEventHeader {
                protocol: IPPROTO_TCP,
                version: 4,
                _pad: [0, 0],
                src_mac,
                dst_mac,
                src_ip: expand_v4(unsafe { (*ipv4_hdr).src_addr }),
                dst_ip: expand_v4(unsafe { (*ipv4_hdr).dst_addr }),
                src_port: unsafe { (*tcp_hdr).source },
                dst_port: unsafe { (*tcp_hdr).dest },
                tcp_seq: unsafe { (*tcp_hdr).seq },
                icmp_type: 0,
                icmp_code: 0,
                icmp_id: [0, 0],
                icmp_seq: [0, 0],
                icmp_payload: [0; 16],
                udp_payload_len: 0,
            };
            Ok(push_probe_event(ctx, &hdr, 0, 0))
        }
        Action::NoResponse => Ok(xdp_action::XDP_DROP),
        Action::IcmpError => Ok(xdp_action::XDP_DROP),
        Action::Drop => Ok(xdp_action::XDP_DROP),
    }
}

#[inline(always)]
fn handle_tcp_v6(
    ctx: &XdpContext,
    ipv6_hdr: *const Ipv6Hdr,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    config: &Config,
) -> Result<u32, u32> {
    let tcp_hdr: *const TcpHdr = ptr_at(ctx, mem::size_of::<EthHdr>() + mem::size_of::<Ipv6Hdr>())?;

    if config.validation_mode != 0
        && (unsafe { (*tcp_hdr).flags } & TCP_FLAG_RST != 0)
        && let Some(stats) = STATS.get_ptr_mut(0)
    {
        unsafe { (*stats).rst_packets += 1 };
    }

    if unsafe { (*tcp_hdr).flags } & TCP_FLAG_SYN == 0 {
        return Ok(xdp_action::XDP_DROP);
    }

    if let Some(stats) = STATS.get_ptr_mut(0) {
        unsafe { (*stats).valid_syn += 1 };
    }

    let dst_ip_even = unsafe { (*ipv6_hdr).dst_addr[15] } % 2 == 0;
    let no_rsp = unsafe { (*ipv6_hdr).dst_addr[14] } as u32 % 100 < config.no_rsp_perc;

    match decide(config, dst_ip_even, no_rsp, false) {
        Action::Mirror => {
            let src_ip = unsafe { (*ipv6_hdr).src_addr };
            let dst_ip = unsafe { (*ipv6_hdr).dst_addr };
            let src_port = unsafe { (*tcp_hdr).source };
            let dst_port = unsafe { (*tcp_hdr).dest };
            let seq = unsafe { u32::from_be((*tcp_hdr).seq) };

            let new_len =
                mem::size_of::<EthHdr>() + mem::size_of::<Ipv6Hdr>() + mem::size_of::<TcpHdr>();
            let old_len = ctx.data_end() - ctx.data();
            let delta = (new_len as isize) - (old_len as isize);

            if delta != 0 {
                let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta as i32) };
                if ret != 0 {
                    return Err(xdp_action::XDP_ABORTED);
                }
            }

            let eth_hdr: *mut EthHdr = ptr_at(ctx, 0)?;
            let ip: *mut Ipv6Hdr = ptr_at(ctx, mem::size_of::<EthHdr>())?;
            let tcp: *mut TcpHdr =
                ptr_at(ctx, mem::size_of::<EthHdr>() + mem::size_of::<Ipv6Hdr>())?;

            unsafe {
                (*eth_hdr).src_addr = dst_mac;
                (*eth_hdr).dst_addr = src_mac;

                (*ip).version_tc_flow = u32::to_be(6 << 28);
                (*ip).payload_len = u16::to_be(mem::size_of::<TcpHdr>() as u16);
                (*ip).next_header = IPPROTO_TCP;
                (*ip).hop_limit = 64;
                (*ip).src_addr = dst_ip;
                (*ip).dst_addr = src_ip;

                (*tcp).source = dst_port;
                (*tcp).dest = src_port;
                (*tcp).seq = bpf_get_prandom_u32();
                (*tcp).ack_seq = u32::to_be(seq + 1);
                (*tcp).doff_res = 0x50;
                (*tcp).flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
                (*tcp).window = u16::to_be(64240);
                (*tcp).check = 0;
                (*tcp).urg_ptr = 0;
                (*tcp).check = tcp_v6_csum(ip, tcp);
            }

            if let Some(stats) = STATS.get_ptr_mut(0) {
                unsafe { (*stats).tx += 1 };
            }

            Ok(xdp_action::XDP_TX)
        }
        Action::PushRing => {
            let hdr = ProbeEventHeader {
                protocol: IPPROTO_TCP,
                version: 6,
                _pad: [0, 0],
                src_mac,
                dst_mac,
                src_ip: unsafe { (*ipv6_hdr).src_addr },
                dst_ip: unsafe { (*ipv6_hdr).dst_addr },
                src_port: unsafe { (*tcp_hdr).source },
                dst_port: unsafe { (*tcp_hdr).dest },
                tcp_seq: unsafe { (*tcp_hdr).seq },
                icmp_type: 0,
                icmp_code: 0,
                icmp_id: [0, 0],
                icmp_seq: [0, 0],
                icmp_payload: [0; 16],
                udp_payload_len: 0,
            };
            Ok(push_probe_event(ctx, &hdr, 0, 0))
        }
        Action::NoResponse => Ok(xdp_action::XDP_DROP),
        Action::IcmpError => Ok(xdp_action::XDP_DROP),
        Action::Drop => Ok(xdp_action::XDP_DROP),
    }
}

#[inline(always)]
fn handle_udp_v4(
    ctx: &XdpContext,
    ipv4_hdr: *const Ipv4Hdr,
    ip_hdr_len: usize,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    config: &Config,
) -> Result<u32, u32> {
    let udp_off = mem::size_of::<EthHdr>() + ip_hdr_len;
    let udp_hdr: *const UdpHdr = ptr_at(ctx, udp_off)?;

    if let Some(stats) = STATS.get_ptr_mut(0) {
        unsafe { (*stats).udp_rx += 1 };
    }

    let dst_addr_be = u32::from_be(unsafe { (*ipv4_hdr).dst_addr });
    let dst_ip_even = dst_addr_be % 2 == 0;
    let no_rsp = dst_addr_be % 100 < config.no_rsp_perc;

    match decide(config, dst_ip_even, no_rsp, true) {
        Action::Mirror => {
            let eth: *mut EthHdr = ptr_at(ctx, 0)?;
            let ip: *mut Ipv4Hdr = ptr_at(ctx, mem::size_of::<EthHdr>())?;
            let udp: *mut UdpHdr = ptr_at(ctx, udp_off)?;

            // Checksum-neutral swap: the one's complement sum is commutative,
            // so swapping equal-sized src<->dst IP and src<->dst port fields
            // keeps both the IPv4 header checksum and the UDP checksum valid
            // without recompute. Do NOT add non-swap mutations (TTL, tot_len,
            // payload) without recomputing checksums afterwards.
            unsafe {
                (*eth).src_addr = dst_mac;
                (*eth).dst_addr = src_mac;
                let src_ip = (*ip).src_addr;
                let dst_ip = (*ip).dst_addr;
                (*ip).src_addr = dst_ip;
                (*ip).dst_addr = src_ip;
                let src_port = (*udp).source;
                let dst_port = (*udp).dest;
                (*udp).source = dst_port;
                (*udp).dest = src_port;
            }

            if let Some(stats) = STATS.get_ptr_mut(0) {
                unsafe { (*stats).udp_tx += 1 };
            }

            Ok(xdp_action::XDP_TX)
        }
        Action::PushRing => {
            let payload_len = u16::from_be(unsafe { (*udp_hdr).len }).saturating_sub(8) as usize;
            let payload_off = udp_off + mem::size_of::<UdpHdr>();
            const MAX_PAYLOAD: usize = PROBE_ENTRY_SIZE - mem::size_of::<ProbeEventHeader>();
            let capped = if payload_len > MAX_PAYLOAD {
                MAX_PAYLOAD
            } else {
                payload_len
            };
            let hdr = ProbeEventHeader {
                protocol: IPPROTO_UDP,
                version: 4,
                _pad: [0, 0],
                src_mac,
                dst_mac,
                src_ip: expand_v4(unsafe { (*ipv4_hdr).src_addr }),
                dst_ip: expand_v4(unsafe { (*ipv4_hdr).dst_addr }),
                src_port: unsafe { (*udp_hdr).source },
                dst_port: unsafe { (*udp_hdr).dest },
                tcp_seq: 0,
                icmp_type: 0,
                icmp_code: 0,
                icmp_id: [0, 0],
                icmp_seq: [0, 0],
                icmp_payload: [0; 16],
                udp_payload_len: u16::to_be(capped as u16),
            };
            Ok(push_probe_event(ctx, &hdr, payload_off, capped))
        }
        Action::NoResponse => Ok(xdp_action::XDP_DROP),
        Action::IcmpError => {
            let (icmp_type, icmp_code) = icmp_type_code(config, 4);
            let result = craft_icmp_error_v4(
                ctx, ipv4_hdr, ip_hdr_len, src_mac, dst_mac, icmp_type, icmp_code,
            );
            if config.icmp_error_type != 6
                && let Some(stats) = STATS.get_ptr_mut(0)
            {
                unsafe { (*stats).icmp_error_tx += 1 };
            }

            result
        }
        Action::Drop => Ok(xdp_action::XDP_DROP),
    }
}

#[inline(always)]
fn handle_udp_v6(
    ctx: &XdpContext,
    ipv6_hdr: *const Ipv6Hdr,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    config: &Config,
) -> Result<u32, u32> {
    let udp_off = mem::size_of::<EthHdr>() + mem::size_of::<Ipv6Hdr>();
    let udp_hdr: *const UdpHdr = ptr_at(ctx, udp_off)?;

    if let Some(stats) = STATS.get_ptr_mut(0) {
        unsafe { (*stats).udp_rx += 1 };
    }

    let dst_ip_even = unsafe { (*ipv6_hdr).dst_addr[15] } % 2 == 0;
    let no_rsp = unsafe { (*ipv6_hdr).dst_addr[14] } as u32 % 100 < config.no_rsp_perc;

    match decide(config, dst_ip_even, no_rsp, true) {
        Action::Mirror => {
            let eth: *mut EthHdr = ptr_at(ctx, 0)?;
            let ip: *mut Ipv6Hdr = ptr_at(ctx, mem::size_of::<EthHdr>())?;
            let udp: *mut UdpHdr = ptr_at(ctx, udp_off)?;

            // Checksum-neutral swap: see handle_udp_v4 for rationale.
            unsafe {
                (*eth).src_addr = dst_mac;
                (*eth).dst_addr = src_mac;
                let src_ip = (*ip).src_addr;
                let dst_ip = (*ip).dst_addr;
                (*ip).src_addr = dst_ip;
                (*ip).dst_addr = src_ip;
                (*ip).hop_limit = 64;
                let src_port = (*udp).source;
                let dst_port = (*udp).dest;
                (*udp).source = dst_port;
                (*udp).dest = src_port;
            }

            if let Some(stats) = STATS.get_ptr_mut(0) {
                unsafe { (*stats).udp_tx += 1 };
            }

            Ok(xdp_action::XDP_TX)
        }
        Action::PushRing => {
            let payload_len = u16::from_be(unsafe { (*udp_hdr).len }).saturating_sub(8) as usize;
            let payload_off = udp_off + mem::size_of::<UdpHdr>();
            const MAX_PAYLOAD: usize = PROBE_ENTRY_SIZE - mem::size_of::<ProbeEventHeader>();
            let capped = if payload_len > MAX_PAYLOAD {
                MAX_PAYLOAD
            } else {
                payload_len
            };
            let hdr = ProbeEventHeader {
                protocol: IPPROTO_UDP,
                version: 6,
                _pad: [0, 0],
                src_mac,
                dst_mac,
                src_ip: unsafe { (*ipv6_hdr).src_addr },
                dst_ip: unsafe { (*ipv6_hdr).dst_addr },
                src_port: unsafe { (*udp_hdr).source },
                dst_port: unsafe { (*udp_hdr).dest },
                tcp_seq: 0,
                icmp_type: 0,
                icmp_code: 0,
                icmp_id: [0, 0],
                icmp_seq: [0, 0],
                icmp_payload: [0; 16],
                udp_payload_len: u16::to_be(capped as u16),
            };
            Ok(push_probe_event(ctx, &hdr, payload_off, capped))
        }
        Action::NoResponse => Ok(xdp_action::XDP_DROP),
        Action::IcmpError => {
            let (icmp_type, icmp_code) = icmp_type_code(config, 6);
            let result = craft_icmp_error_v6(ctx, ipv6_hdr, src_mac, dst_mac, icmp_type, icmp_code);
            if config.icmp_error_type != 6
                && let Some(stats) = STATS.get_ptr_mut(0)
            {
                unsafe { (*stats).icmp_error_tx += 1 };
            }
            result
        }
        Action::Drop => Ok(xdp_action::XDP_DROP),
    }
}

#[inline(always)]
fn handle_icmp_v4(
    ctx: &XdpContext,
    ipv4_hdr: *const Ipv4Hdr,
    ip_hdr_len: usize,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    config: &Config,
) -> Result<u32, u32> {
    let icmp_off = mem::size_of::<EthHdr>() + ip_hdr_len;
    let icmp_base: *mut u8 = ptr_at::<[u8; ICMP_ECHO_MSG_LEN]>(ctx, icmp_off)? as *mut u8;

    if unsafe { *icmp_base } != ICMPV4_ECHO_REQUEST {
        return Ok(xdp_action::XDP_PASS);
    }

    if let Some(stats) = STATS.get_ptr_mut(0) {
        unsafe { (*stats).icmp_rx += 1 };
    }

    let dst_addr_be = u32::from_be(unsafe { (*ipv4_hdr).dst_addr });
    let dst_ip_even = dst_addr_be % 2 == 0;
    let no_rsp = dst_addr_be % 100 < config.no_rsp_perc;

    match decide(config, dst_ip_even, no_rsp, false) {
        Action::Mirror => {
            let eth: *mut EthHdr = ptr_at(ctx, 0)?;
            let ip: *mut Ipv4Hdr = ptr_at(ctx, mem::size_of::<EthHdr>())?;
            let icmp: *mut u8 = ptr_at::<[u8; ICMP_ECHO_MSG_LEN]>(ctx, icmp_off)? as *mut u8;

            unsafe {
                (*eth).src_addr = dst_mac;
                (*eth).dst_addr = src_mac;
                let src_ip = (*ip).src_addr;
                let dst_ip = (*ip).dst_addr;
                (*ip).src_addr = dst_ip;
                (*ip).dst_addr = src_ip;
                (*ip).check = 0;
                (*ip).check = ipv4_csum(ip);

                *icmp = ICMPV4_ECHO_REPLY;
                *(icmp.add(1)) = 0;
                *(icmp.add(2)) = 0;
                *(icmp.add(3)) = 0;
                let csum = icmp_v4_csum(icmp);
                *(icmp.add(2) as *mut u16) = csum;
            }

            if let Some(stats) = STATS.get_ptr_mut(0) {
                unsafe { (*stats).icmp_tx += 1 };
            }

            Ok(xdp_action::XDP_TX)
        }
        Action::PushRing => {
            let hdr = build_icmp_event(
                IPPROTO_ICMP,
                4,
                src_mac,
                dst_mac,
                expand_v4(unsafe { (*ipv4_hdr).src_addr }),
                expand_v4(unsafe { (*ipv4_hdr).dst_addr }),
                icmp_base,
            );
            Ok(push_probe_event(ctx, &hdr, 0, 0))
        }
        Action::NoResponse => Ok(xdp_action::XDP_DROP),
        Action::IcmpError => Ok(xdp_action::XDP_DROP),
        Action::Drop => Ok(xdp_action::XDP_DROP),
    }
}

#[inline(always)]
fn handle_icmp_v6(
    ctx: &XdpContext,
    ipv6_hdr: *const Ipv6Hdr,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    config: &Config,
) -> Result<u32, u32> {
    let icmp_off = mem::size_of::<EthHdr>() + mem::size_of::<Ipv6Hdr>();
    let icmp_base: *mut u8 = ptr_at::<[u8; ICMP_ECHO_MSG_LEN]>(ctx, icmp_off)? as *mut u8;

    if unsafe { *icmp_base } != ICMPV6_ECHO_REQUEST {
        return Ok(xdp_action::XDP_PASS);
    }

    if let Some(stats) = STATS.get_ptr_mut(0) {
        unsafe { (*stats).icmp_rx += 1 };
    }

    let dst_ip_even = unsafe { (*ipv6_hdr).dst_addr[15] } % 2 == 0;
    let no_rsp = unsafe { (*ipv6_hdr).dst_addr[14] } as u32 % 100 < config.no_rsp_perc;

    match decide(config, dst_ip_even, no_rsp, false) {
        Action::Mirror => {
            let eth: *mut EthHdr = ptr_at(ctx, 0)?;
            let ip: *mut Ipv6Hdr = ptr_at(ctx, mem::size_of::<EthHdr>())?;
            let icmp: *mut u8 = ptr_at::<[u8; ICMP_ECHO_MSG_LEN]>(ctx, icmp_off)? as *mut u8;

            unsafe {
                (*eth).src_addr = dst_mac;
                (*eth).dst_addr = src_mac;
                let src_ip = (*ip).src_addr;
                let dst_ip = (*ip).dst_addr;
                (*ip).src_addr = dst_ip;
                (*ip).dst_addr = src_ip;
                (*ip).hop_limit = 64;

                *icmp = ICMPV6_ECHO_REPLY;
                *(icmp.add(1)) = 0;
                *(icmp.add(2)) = 0;
                *(icmp.add(3)) = 0;
                let csum = icmp_v6_csum(ip, icmp);
                *(icmp.add(2) as *mut u16) = csum;
            }

            if let Some(stats) = STATS.get_ptr_mut(0) {
                unsafe { (*stats).icmp_tx += 1 };
            }

            Ok(xdp_action::XDP_TX)
        }
        Action::PushRing => {
            let hdr = build_icmp_event(
                IPPROTO_ICMPV6,
                6,
                src_mac,
                dst_mac,
                unsafe { (*ipv6_hdr).src_addr },
                unsafe { (*ipv6_hdr).dst_addr },
                icmp_base,
            );
            Ok(push_probe_event(ctx, &hdr, 0, 0))
        }
        Action::NoResponse => Ok(xdp_action::XDP_DROP),
        Action::IcmpError => Ok(xdp_action::XDP_DROP),
        Action::Drop => Ok(xdp_action::XDP_DROP),
    }
}

#[inline(always)]
fn build_icmp_event(
    protocol: u8,
    version: u8,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    icmp_base: *const u8,
) -> ProbeEventHeader {
    let mut payload = [0u8; 16];
    unsafe {
        core::ptr::copy_nonoverlapping(icmp_base.add(8), payload.as_mut_ptr(), 16);
    }
    ProbeEventHeader {
        protocol,
        version,
        _pad: [0, 0],
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        src_port: 0,
        dst_port: 0,
        tcp_seq: 0,
        icmp_type: unsafe { *icmp_base },
        icmp_code: unsafe { *icmp_base.add(1) },
        icmp_id: [unsafe { *icmp_base.add(4) }, unsafe { *icmp_base.add(5) }],
        icmp_seq: [unsafe { *icmp_base.add(6) }, unsafe { *icmp_base.add(7) }],
        icmp_payload: payload,
        udp_payload_len: 0,
    }
}

#[inline(always)]
fn push_probe_event(
    ctx: &XdpContext,
    hdr: &ProbeEventHeader,
    payload_off: usize,
    payload_len: usize,
) -> u32 {
    let hdr_size = mem::size_of::<ProbeEventHeader>();
    if let Some(mut entry) = PROBES.reserve::<[u8; PROBE_ENTRY_SIZE]>(0) {
        let buf = entry.as_mut_ptr() as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(
                hdr as *const ProbeEventHeader as *const u8,
                buf,
                hdr_size,
            );
        }
        let mut ok = true;
        // Only call bpf_xdp_load_bytes when there is payload to copy. The
        // eBPF verifier rejects bpf_xdp_load_bytes with a zero-sized length.
        // A volatile read prevents the compiler from substituting the original
        // UDP length field (which the verifier can't connect back to
        // payload_len), ensuring the verifier sees the guard clearly.
        let plen = unsafe { core::ptr::read_volatile(&payload_len) };
        if plen > 0 {
            let ret = unsafe {
                bpf_xdp_load_bytes(
                    ctx.ctx,
                    payload_off as u32,
                    buf.add(hdr_size) as *mut c_void,
                    plen as u32,
                )
            };
            if ret < 0 {
                ok = false;
            }
        }
        if ok {
            entry.submit(0);
        } else {
            entry.discard(0);
        }
    } else if let Some(stats) = STATS.get_ptr_mut(0) {
        unsafe { (*stats).ring_dropped += 1 };
    }
    xdp_action::XDP_DROP
}

#[inline(always)]
fn craft_icmp_error_v4(
    ctx: &XdpContext,
    ipv4_hdr: *const Ipv4Hdr,
    ip_hdr_len: usize,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    icmp_type: u8,
    icmp_code: u8,
) -> Result<u32, u32> {
    if ip_hdr_len != 20 {
        return Ok(xdp_action::XDP_DROP);
    }

    let orig_src_ip = unsafe { (*ipv4_hdr).src_addr };
    let orig_dst_ip = unsafe { (*ipv4_hdr).dst_addr };

    let target_len = 70usize;
    let old_len = ctx.data_end() - ctx.data();
    let delta = (target_len as isize) - (old_len as isize);
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta as i32) };
        if ret != 0 {
            return Err(xdp_action::XDP_ABORTED);
        }
    }

    let eth: *mut EthHdr = ptr_at(ctx, 0)?;
    let ip: *mut Ipv4Hdr = ptr_at(ctx, mem::size_of::<EthHdr>())?;
    let icmp_off = mem::size_of::<EthHdr>() + mem::size_of::<Ipv4Hdr>();
    let icmp: *mut u8 = ptr_at::<[u8; ICMP_ERROR_V4_LEN]>(ctx, icmp_off)? as *mut u8;

    // After adjust_tail, the original IP4 header (20 bytes at offset 14) and
    // UDP header (8 bytes at offset 34) are still in the packet. Copy them to
    // the ICMP payload area (offset 42-69).
    //
    // Source [14..33] -> dest [42..61] (no overlap)
    // Source [34..41] -> dest [62..69] (no overlap)
    let pkt: *mut u8 = ctx.data() as *mut u8;
    unsafe {
        for i in 0..20usize {
            *pkt.add(42 + i) = *pkt.add(14 + i);
        }
        for i in 0..8usize {
            *pkt.add(62 + i) = *pkt.add(34 + i);
        }
    }

    unsafe {
        (*eth).dst_addr = src_mac;
        (*eth).src_addr = dst_mac;
        (*eth).ether_type = u16::from_be(ETH_P_IP);

        (*ip).version_ihl = 0x45;
        (*ip).tos = 0;
        (*ip).tot_len = u16::to_be(56);
        (*ip).id = 0;
        (*ip).frag_off = 0;
        (*ip).ttl = 64;
        (*ip).proto = IPPROTO_ICMP;
        (*ip).check = 0;
        (*ip).src_addr = orig_dst_ip;
        (*ip).dst_addr = orig_src_ip;
        (*ip).check = ipv4_csum(ip);

        *icmp = icmp_type;
        *(icmp.add(1)) = icmp_code;
        *(icmp.add(2)) = 0;
        *(icmp.add(3)) = 0;
        *(icmp.add(4)) = 0;
        *(icmp.add(5)) = 0;
        *(icmp.add(6)) = 0;
        *(icmp.add(7)) = 0;

        let csum = icmp_v4_error_csum(icmp);
        *(icmp.add(2) as *mut u16) = csum;
    }

    Ok(xdp_action::XDP_TX)
}

#[inline(always)]
fn craft_icmp_error_v6(
    ctx: &XdpContext,
    ipv6_hdr: *const Ipv6Hdr,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    icmp_type: u8,
    icmp_code: u8,
) -> Result<u32, u32> {
    let orig_src_ip = unsafe { (*ipv6_hdr).src_addr };
    let orig_dst_ip = unsafe { (*ipv6_hdr).dst_addr };

    let target_len = 110usize;
    let old_len = ctx.data_end() - ctx.data();
    let delta = (target_len as isize) - (old_len as isize);
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta as i32) };
        if ret != 0 {
            return Err(xdp_action::XDP_ABORTED);
        }
    }

    let eth: *mut EthHdr = ptr_at(ctx, 0)?;
    let ip: *mut Ipv6Hdr = ptr_at(ctx, mem::size_of::<EthHdr>())?;
    let icmp_off = mem::size_of::<EthHdr>() + mem::size_of::<Ipv6Hdr>();
    let icmp: *mut u8 = ptr_at::<[u8; ICMP_ERROR_V6_LEN]>(ctx, icmp_off)? as *mut u8;

    // After adjust_tail, the original IPv6 header (40 bytes at offset 14) and
    // UDP header (8 bytes at offset 54) are still in the packet. Copy them to
    // the ICMPv6 payload area (offset 62-109).
    //
    // Source [14..53] -> dest [62..101] (no overlap)
    // Source [54..61] -> dest [102..109] (no overlap)
    let pkt: *mut u8 = ctx.data() as *mut u8;
    unsafe {
        for i in 0..40usize {
            *pkt.add(62 + i) = *pkt.add(14 + i);
        }
        for i in 0..8usize {
            *pkt.add(102 + i) = *pkt.add(54 + i);
        }
    }

    unsafe {
        (*eth).dst_addr = src_mac;
        (*eth).src_addr = dst_mac;
        (*eth).ether_type = u16::from_be(ETH_P_IPV6);

        (*ip).version_tc_flow = u32::to_be(6 << 28);
        (*ip).payload_len = u16::to_be(56);
        (*ip).next_header = IPPROTO_ICMPV6;
        (*ip).hop_limit = 64;
        (*ip).src_addr = orig_dst_ip;
        (*ip).dst_addr = orig_src_ip;

        *icmp = icmp_type;
        *(icmp.add(1)) = icmp_code;
        *(icmp.add(2)) = 0;
        *(icmp.add(3)) = 0;
        *(icmp.add(4)) = 0;
        *(icmp.add(5)) = 0;
        *(icmp.add(6)) = 0;
        *(icmp.add(7)) = 0;

        let csum = icmp_v6_error_csum(ip, icmp);
        *(icmp.add(2) as *mut u16) = csum;
    }

    Ok(xdp_action::XDP_TX)
}

unsafe fn ipv4_csum(hdr: *mut Ipv4Hdr) -> u16 {
    let ptr = hdr as *const u16;
    let mut sum = 0u32;
    for i in 0..10 {
        sum += unsafe { *ptr.add(i) } as u32;
    }
    // Bounded fold: 2 iterations suffice for all callers (max 47 u16 terms
    // → initial sum ≤ 0x2EFFD1; after 1 fold ≤ 0x1002D; after 2 ≤ 0xFFFF).
    // The eBPF verifier's abstract interpretation cannot prove the equivalent
    // `while (sum >> 16) != 0` loop terminates, because the range widens back
    // to [0, 0x10000] on each iteration. A bounded `for` loop is trivially
    // provably terminating.
    for _ in 0..2 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

unsafe fn tcp_v4_csum(ip_hdr: *mut Ipv4Hdr, tcp_hdr: *mut TcpHdr) -> u16 {
    let mut sum = 0u32;

    let src_ptr = unsafe { &(*ip_hdr).src_addr } as *const u32 as *const u16;
    sum += unsafe { *src_ptr } as u32;
    sum += unsafe { *src_ptr.add(1) } as u32;

    let dst_ptr = unsafe { &(*ip_hdr).dst_addr } as *const u32 as *const u16;
    sum += unsafe { *dst_ptr } as u32;
    sum += unsafe { *dst_ptr.add(1) } as u32;

    sum += u16::to_be(6) as u32;
    sum += u16::to_be(20) as u32;

    let tcp_ptr = tcp_hdr as *const u16;
    for i in 0..10 {
        sum += unsafe { *tcp_ptr.add(i) } as u32;
    }

    // Bounded fold: 2 iterations suffice for all callers (max 47 u16 terms
    // → initial sum ≤ 0x2EFFD1; after 1 fold ≤ 0x1002D; after 2 ≤ 0xFFFF).
    // The eBPF verifier's abstract interpretation cannot prove the equivalent
    // `while (sum >> 16) != 0` loop terminates, because the range widens back
    // to [0, 0x10000] on each iteration. A bounded `for` loop is trivially
    // provably terminating.
    for _ in 0..2 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

unsafe fn tcp_v6_csum(ip_hdr: *mut Ipv6Hdr, tcp_hdr: *mut TcpHdr) -> u16 {
    let mut sum = 0u32;

    let src_ptr = unsafe { (*ip_hdr).src_addr.as_ptr() } as *const u16;
    for i in 0..8 {
        sum += unsafe { *src_ptr.add(i) } as u32;
    }

    let dst_ptr = unsafe { (*ip_hdr).dst_addr.as_ptr() } as *const u16;
    for i in 0..8 {
        sum += unsafe { *dst_ptr.add(i) } as u32;
    }

    sum += u16::to_be((mem::size_of::<TcpHdr>() as u32 >> 16) as u16) as u32;
    sum += u16::to_be((mem::size_of::<TcpHdr>() as u32 & 0xFFFF) as u16) as u32;
    sum += u16::to_be(IPPROTO_TCP as u16) as u32;

    let tcp_ptr = tcp_hdr as *const u16;
    for i in 0..10 {
        sum += unsafe { *tcp_ptr.add(i) } as u32;
    }

    // Bounded fold: 2 iterations suffice for all callers (max 47 u16 terms
    // → initial sum ≤ 0x2EFFD1; after 1 fold ≤ 0x1002D; after 2 ≤ 0xFFFF).
    // The eBPF verifier's abstract interpretation cannot prove the equivalent
    // `while (sum >> 16) != 0` loop terminates, because the range widens back
    // to [0, 0x10000] on each iteration. A bounded `for` loop is trivially
    // provably terminating.
    for _ in 0..2 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

unsafe fn icmp_v4_csum(icmp_base: *const u8) -> u16 {
    let ptr = icmp_base as *const u16;
    let mut sum = 0u32;
    for i in 0..12 {
        sum += unsafe { *ptr.add(i) } as u32;
    }
    // Bounded fold: 2 iterations suffice for all callers (max 47 u16 terms
    // → initial sum ≤ 0x2EFFD1; after 1 fold ≤ 0x1002D; after 2 ≤ 0xFFFF).
    // The eBPF verifier's abstract interpretation cannot prove the equivalent
    // `while (sum >> 16) != 0` loop terminates, because the range widens back
    // to [0, 0x10000] on each iteration. A bounded `for` loop is trivially
    // provably terminating.
    for _ in 0..2 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

unsafe fn icmp_v6_csum(ip_hdr: *const Ipv6Hdr, icmp_base: *const u8) -> u16 {
    let mut sum = 0u32;

    let src_ptr = unsafe { (*ip_hdr).src_addr.as_ptr() } as *const u16;
    for i in 0..8 {
        sum += unsafe { *src_ptr.add(i) } as u32;
    }

    let dst_ptr = unsafe { (*ip_hdr).dst_addr.as_ptr() } as *const u16;
    for i in 0..8 {
        sum += unsafe { *dst_ptr.add(i) } as u32;
    }

    let icmp_len = ICMP_ECHO_MSG_LEN as u32;
    sum += u16::to_be((icmp_len >> 16) as u16) as u32;
    sum += u16::to_be((icmp_len & 0xFFFF) as u16) as u32;
    sum += u16::to_be(IPPROTO_ICMPV6 as u16) as u32;

    let icmp_ptr = icmp_base as *const u16;
    for i in 0..12 {
        sum += unsafe { *icmp_ptr.add(i) } as u32;
    }

    // Bounded fold: 2 iterations suffice for all callers (max 47 u16 terms
    // → initial sum ≤ 0x2EFFD1; after 1 fold ≤ 0x1002D; after 2 ≤ 0xFFFF).
    // The eBPF verifier's abstract interpretation cannot prove the equivalent
    // `while (sum >> 16) != 0` loop terminates, because the range widens back
    // to [0, 0x10000] on each iteration. A bounded `for` loop is trivially
    // provably terminating.
    for _ in 0..2 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

unsafe fn icmp_v4_error_csum(icmp_base: *const u8) -> u16 {
    let ptr = icmp_base as *const u16;
    let mut sum = 0u32;
    for i in 0..18 {
        sum += unsafe { *ptr.add(i) } as u32;
    }
    // Bounded fold: 2 iterations suffice for all callers (max 47 u16 terms
    // → initial sum ≤ 0x2EFFD1; after 1 fold ≤ 0x1002D; after 2 ≤ 0xFFFF).
    // The eBPF verifier's abstract interpretation cannot prove the equivalent
    // `while (sum >> 16) != 0` loop terminates, because the range widens back
    // to [0, 0x10000] on each iteration. A bounded `for` loop is trivially
    // provably terminating.
    for _ in 0..2 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

unsafe fn icmp_v6_error_csum(ip_hdr: *const Ipv6Hdr, icmp_base: *const u8) -> u16 {
    let mut sum = 0u32;

    let src_ptr = unsafe { (*ip_hdr).src_addr.as_ptr() } as *const u16;
    for i in 0..8 {
        sum += unsafe { *src_ptr.add(i) } as u32;
    }

    let dst_ptr = unsafe { (*ip_hdr).dst_addr.as_ptr() } as *const u16;
    for i in 0..8 {
        sum += unsafe { *dst_ptr.add(i) } as u32;
    }

    let icmp_len = ICMP_ERROR_V6_LEN as u32;
    sum += u16::to_be((icmp_len >> 16) as u16) as u32;
    sum += u16::to_be((icmp_len & 0xFFFF) as u16) as u32;
    sum += u16::to_be(IPPROTO_ICMPV6 as u16) as u32;

    let icmp_ptr = icmp_base as *const u16;
    for i in 0..28 {
        sum += unsafe { *icmp_ptr.add(i) } as u32;
    }

    // Bounded fold: 2 iterations suffice for all callers (max 47 u16 terms
    // → initial sum ≤ 0x2EFFD1; after 1 fold ≤ 0x1002D; after 2 ≤ 0xFFFF).
    // The eBPF verifier's abstract interpretation cannot prove the equivalent
    // `while (sum >> 16) != 0` loop terminates, because the range widens back
    // to [0, 0x10000] on each iteration. A bounded `for` loop is trivially
    // provably terminating.
    for _ in 0..2 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

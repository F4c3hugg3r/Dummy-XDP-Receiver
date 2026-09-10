#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_prandom_u32, bpf_xdp_adjust_tail},
    macros::{map, xdp},
    maps::{Array, PerCpuArray},
    programs::XdpContext,
};
use core::mem;
use xdp_mirror_common::{Config, Stats};

#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

#[map]
static STATS: PerCpuArray<Stats> = PerCpuArray::with_max_entries(1, 0);

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

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_ACK: u8 = 0x10;

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
        return Ok(xdp_action::XDP_DROP);
    }

    let src_mac = unsafe { (*eth_hdr).src_addr };
    let dst_mac = unsafe { (*eth_hdr).dst_addr };

    if ipv6_mode {
        let ipv6_hdr: *const Ipv6Hdr = ptr_at(&ctx, mem::size_of::<EthHdr>())?;
        if unsafe { (*ipv6_hdr).next_header } != IPPROTO_TCP {
            return Ok(xdp_action::XDP_DROP);
        }

        let tcp_hdr: *const TcpHdr =
            ptr_at(&ctx, mem::size_of::<EthHdr>() + mem::size_of::<Ipv6Hdr>())?;

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

        if config.validation_mode != 0 {
            let dst_last = unsafe { (*ipv6_hdr).dst_addr[15] };
            if dst_last % 2 != 0 {
                return Ok(xdp_action::XDP_DROP);
            }
        } else {
            let rnd = unsafe { bpf_get_prandom_u32() };
            if (rnd % 100) >= config.response_probability {
                return Ok(xdp_action::XDP_DROP);
            }
        }

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

        let eth_hdr: *mut EthHdr = ptr_at(&ctx, 0)?;
        let ipv6_hdr: *mut Ipv6Hdr = ptr_at(&ctx, mem::size_of::<EthHdr>())?;
        let tcp_hdr: *mut TcpHdr =
            ptr_at(&ctx, mem::size_of::<EthHdr>() + mem::size_of::<Ipv6Hdr>())?;

        unsafe {
            (*eth_hdr).src_addr = dst_mac;
            (*eth_hdr).dst_addr = src_mac;

            (*ipv6_hdr).version_tc_flow = u32::to_be(6 << 28);
            (*ipv6_hdr).payload_len = u16::to_be(mem::size_of::<TcpHdr>() as u16);
            (*ipv6_hdr).next_header = IPPROTO_TCP;
            (*ipv6_hdr).hop_limit = 64;
            (*ipv6_hdr).src_addr = dst_ip;
            (*ipv6_hdr).dst_addr = src_ip;

            (*tcp_hdr).source = dst_port;
            (*tcp_hdr).dest = src_port;
            (*tcp_hdr).seq = bpf_get_prandom_u32();
            (*tcp_hdr).ack_seq = u32::to_be(seq + 1);
            (*tcp_hdr).doff_res = 0x50;
            (*tcp_hdr).flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
            (*tcp_hdr).window = u16::to_be(64240);
            (*tcp_hdr).check = 0;
            (*tcp_hdr).urg_ptr = 0;
            (*tcp_hdr).check = tcp_v6_csum(ipv6_hdr, tcp_hdr);
        }

        if let Some(stats) = STATS.get_ptr_mut(0) {
            unsafe { (*stats).tx += 1 };
        }

        return Ok(xdp_action::XDP_TX);
    }

    let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, mem::size_of::<EthHdr>())?;
    if unsafe { (*ipv4_hdr).proto } != IPPROTO_TCP {
        return Ok(xdp_action::XDP_DROP);
    }

    let ihl = unsafe { (*ipv4_hdr).version_ihl } & 0x0F;
    let ip_hdr_len = (ihl as usize) * 4;
    let tcp_hdr: *const TcpHdr = ptr_at(&ctx, mem::size_of::<EthHdr>() + ip_hdr_len)?;

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

    if config.validation_mode != 0 {
        let dst_addr = unsafe { (*ipv4_hdr).dst_addr };
        if u32::from_be(dst_addr) % 2 != 0 {
            return Ok(xdp_action::XDP_DROP);
        }
    } else {
        let rnd = unsafe { bpf_get_prandom_u32() };
        if (rnd % 100) >= config.response_probability {
            return Ok(xdp_action::XDP_DROP);
        }
    }

    let src_ip = unsafe { (*ipv4_hdr).src_addr };
    let dst_ip = unsafe { (*ipv4_hdr).dst_addr };
    let src_port = unsafe { (*tcp_hdr).source };
    let dst_port = unsafe { (*tcp_hdr).dest };
    let seq = unsafe { u32::from_be((*tcp_hdr).seq) };

    let new_len = mem::size_of::<EthHdr>() + mem::size_of::<Ipv4Hdr>() + mem::size_of::<TcpHdr>();
    let old_len = ctx.data_end() - ctx.data();
    let delta = (new_len as isize) - (old_len as isize);

    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta as i32) };
        if ret != 0 {
            return Err(xdp_action::XDP_ABORTED);
        }
    }

    let eth_hdr: *mut EthHdr = ptr_at(&ctx, 0)?;
    let ipv4_hdr: *mut Ipv4Hdr = ptr_at(&ctx, mem::size_of::<EthHdr>())?;
    let tcp_hdr: *mut TcpHdr = ptr_at(&ctx, mem::size_of::<EthHdr>() + mem::size_of::<Ipv4Hdr>())?;

    unsafe {
        (*eth_hdr).src_addr = dst_mac;
        (*eth_hdr).dst_addr = src_mac;

        (*ipv4_hdr).version_ihl = 0x45;
        (*ipv4_hdr).tot_len = u16::to_be(40);
        (*ipv4_hdr).src_addr = dst_ip;
        (*ipv4_hdr).dst_addr = src_ip;
        (*ipv4_hdr).check = 0;
        (*ipv4_hdr).check = ipv4_csum(ipv4_hdr);

        (*tcp_hdr).source = dst_port;
        (*tcp_hdr).dest = src_port;
        (*tcp_hdr).seq = bpf_get_prandom_u32();
        (*tcp_hdr).ack_seq = u32::to_be(seq + 1);
        (*tcp_hdr).doff_res = 0x50;
        (*tcp_hdr).flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
        (*tcp_hdr).window = u16::to_be(64240);
        (*tcp_hdr).check = 0;
        (*tcp_hdr).urg_ptr = 0;

        (*tcp_hdr).check = tcp_v4_csum(ipv4_hdr, tcp_hdr);
    }

    // info!(&ctx, "sent SYN-ACK");

    if let Some(stats) = STATS.get_ptr_mut(0) {
        unsafe { (*stats).tx += 1 };
    }

    Ok(xdp_action::XDP_TX)
}

unsafe fn ipv4_csum(hdr: *mut Ipv4Hdr) -> u16 {
    let ptr = hdr as *const u16;
    let mut sum = 0u32;
    for i in 0..10 {
        sum += unsafe { *ptr.add(i) } as u32;
    }
    while (sum >> 16) != 0 {
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

    while (sum >> 16) != 0 {
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

    while (sum >> 16) != 0 {
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

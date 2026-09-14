#![no_std]

use core::mem::{offset_of, size_of};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    pub response_probability: u32, // 0-100
    pub validation_mode: u32,      // 0 = percentage, 1 = valm (even-IP)
    pub ipv6: u32,                 // 0 = false, 1 = true
    pub protocol: u32,             // 0 = any, 1 = tcp, 2 = udp, 3 = icmp
    pub mode: u32,                 // 0 = ebpf, 1 = raw, 2 = both
    pub icmp_error_type: u32,      // 0=none, 1=port-unreach, 2=admin-prohibited,
                                  // 3=host-unreach, 4=net-unreach, 5=time-exceeded,
                                  // 6=all (round-robin)
    pub no_rsp_perc: u32,          // 0-100, % of hits that get no response
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Config {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub rx: u64,
    pub valid_syn: u64,
    pub tx: u64,
    pub rst_packets: u64,
    pub udp_rx: u64,
    pub udp_tx: u64,
    pub icmp_rx: u64,
    pub icmp_tx: u64,
    pub ring_dropped: u64,
    pub icmp_error_tx: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stats {}

/// Fixed-size header pushed to the `PROBES` RingBuf for each probe the eBPF
/// program forwards to the userspace sniffer. The full ring-buffer entry is
/// `[ProbeEventHeader][udp_payload_len bytes]` (UDP only).
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, Unaligned, Immutable, KnownLayout)]
pub struct ProbeEventHeader {
    pub protocol: u8,            // 6=TCP, 17=UDP, 1=ICMPv4, 58=ICMPv6
    pub version: u8,             // 4 | 6
    pub _pad: [u8; 2],
    pub src_mac: [u8; 6],        // scanner's MAC (becomes dst in response)
    pub dst_mac: [u8; 6],        // gateway/target MAC (becomes src in response)
    pub src_ip: [u8; 16],        // v4 in first 4 bytes (scanner convention)
    pub dst_ip: [u8; 16],
    pub src_port: u16,           // TCP/UDP; 0 for ICMP (network byte order)
    pub dst_port: u16,           // TCP/UDP; 0 for ICMP (network byte order)
    pub tcp_seq: u32,            // TCP only (network byte order)
    pub icmp_type: u8,           // ICMP only (request type)
    pub icmp_code: u8,           // ICMP only
    pub icmp_id: [u8; 2],        // ICMP only
    pub icmp_seq: [u8; 2],       // ICMP only
    pub icmp_payload: [u8; 16],  // ICMP only
    pub udp_payload_len: u16,    // #bytes following this header (UDP only, network byte order)
}

const _: () = assert!(size_of::<ProbeEventHeader>() == 80);
const _: () = assert!(offset_of!(ProbeEventHeader, protocol) == 0);
const _: () = assert!(offset_of!(ProbeEventHeader, version) == 1);
const _: () = assert!(offset_of!(ProbeEventHeader, _pad) == 2);
const _: () = assert!(offset_of!(ProbeEventHeader, src_mac) == 4);
const _: () = assert!(offset_of!(ProbeEventHeader, dst_mac) == 10);
const _: () = assert!(offset_of!(ProbeEventHeader, src_ip) == 16);
const _: () = assert!(offset_of!(ProbeEventHeader, dst_ip) == 32);
const _: () = assert!(offset_of!(ProbeEventHeader, src_port) == 48);
const _: () = assert!(offset_of!(ProbeEventHeader, dst_port) == 50);
const _: () = assert!(offset_of!(ProbeEventHeader, tcp_seq) == 52);
const _: () = assert!(offset_of!(ProbeEventHeader, icmp_type) == 56);
const _: () = assert!(offset_of!(ProbeEventHeader, icmp_code) == 57);
const _: () = assert!(offset_of!(ProbeEventHeader, icmp_id) == 58);
const _: () = assert!(offset_of!(ProbeEventHeader, icmp_seq) == 60);
const _: () = assert!(offset_of!(ProbeEventHeader, icmp_payload) == 62);
const _: () = assert!(offset_of!(ProbeEventHeader, udp_payload_len) == 78);

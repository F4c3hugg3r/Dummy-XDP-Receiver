# DummyReceiver — Project Context

> Source of truth for the DummyReceiver project. An eBPF/XDP program that
> simulates scan targets for the SYN-Rust scanner
> (`/home/lennard/WorkRepos/ase/SYN-Rust/`). Originally TCP-only; now extended to
> **TCP + UDP + ICMP**.

---

## 1. Purpose

DummyReceiver is an eBPF/XDP program that simulates scan targets for the
SYN-Rust scanner at `/home/lennard/WorkRepos/ase/SYN-Rust/`. It currently
supports TCP and is now extended to TCP + UDP + ICMP. It lets the scanner be
exercised against a deterministic, controllable "victim" without standing up
real services on real hosts.

## 2. Architecture

Hybrid: **eBPF line-rate mirror + userspace raw-socket injector**. Three
mutually-exclusive modes:

- **`ebpf`** (default): eBPF mirrors filter-hits (valm/percentage) at line rate;
  non-hits `XDP_DROP`. No RingBuf, no sniffer.
- **`raw`**: eBPF pushes EVERY valid probe to the `PROBES` RingBuf and
  `XDP_DROP`s. Sniffer drains RingBuf and applies edge-case logic.
- **`both`**: eBPF mirrors even-IP hits (`XDP_TX`); pushes odd-IP to RingBuf +
  `XDP_DROP`. Sniffer handles odd-IPs.

## 3. Data Flow

```
scanner probe -> eBPF parse -> (mirror in-kernel via XDP_TX)
                            OR (push ProbeEventHeader to RingBuf + XDP_DROP)
                            -> userspace sniffer drains RingBuf via AsyncFd
                            -> crafts response -> sends via AF_PACKET TX socket
                            -> back to scanner
```

## 4. Per-Protocol Mirror Logic

- **TCP**: SYN -> SYN-ACK (`ack = seq + 1`, swap ports, recompute IP + TCP
  checksums, `adjust_tail`).
- **UDP**: swap ports, echo payload, NO checksum recompute (swapping is
  checksum-neutral).
- **ICMP**: Echo Request -> Echo Reply (type 8 -> 0 for v4, 128 -> 129 for v6),
  code forced to 0, copy id/seq/payload, recompute IP header checksum (v4) + ICMP
  checksum.

## 5. Real-Kernel Behavior Rule

The dummy simulates **real kernel/host behavior**, NOT scanner quirks.

**Critical**: the ICMPv6 handler accepts ONLY type 128 (Echo Request) and
IGNORES type 129 (Echo Reply). The scanner's ICMPv6 probe uses type 129 (a bug
— should be 128), so a correctly-simulated dummy produces **zero** ICMPv6 hits,
surfacing the scanner bug. Do NOT add a "robust" respond-to-129 shortcut.

## 6. Deterministic (valm) Mode

Universal even-dst-IP for all 3 protocols:

- Even IP -> respond.
- Odd IP -> drop (`ebpf` mode) or push to sniffer (`both` mode).

IPv4: `u32::from_be(dst_addr) % 2`. IPv6: `dst_addr[15] % 2`.

## 7. Edge-Case Flags (raw/both modes)

| Flag | Effect |
|------|--------|
| `--count N` | Multi-response per probe (sniffer sends N responses) |
| `--delay MS` | Delay before responding (ms) |
| `--fake-ip IP` | Fake source IP — tests scanner's forgery defense |
| `--closed` | Closed-host: TCP RST / UDP ICMP Port-Unreach / ICMP silence |

## 8. Known Scanner Quirk

ICMPv6 type-129 request bug in
`SYN-Rust/scanner/src/scan_utils/probes/icmp.rs:25`:

```rust
const ICMPV6_ECHO_REQUEST_TYPECODE: u16 = 129 << 8; // BUG: should be 128 << 8
```

The dummy correctly simulates real-kernel behavior; the fix belongs in the
scanner. A correctly-simulated dummy yields zero ICMPv6 hits.

## 9. ARP-Drop Bug Fix

The eBPF program had a bug where non-IP frames (e.g., ARP) were `XDP_DROP`ped
instead of `XDP_PASS`ed, which could break MAC resolution. Now fixed:
`XDP_PASS` for non-matching `ether_type`.

## 10. Shared Types

Defined in `xdp_mirror-common`:

- **`Config`** (5 `u32` fields): `response_probability`, `validation_mode`,
  `ipv6`, `protocol`, `mode`.
- **`Stats`** (9 `u64` counters): `rx`, `valid_syn`, `tx`, `rst_packets`,
  `udp_rx`, `udp_tx`, `icmp_rx`, `icmp_tx`, `ring_dropped`.
- **`ProbeEventHeader`**: 80-byte packed struct (`#[repr(C, packed)]`,
  `zerocopy` derives) pushed to the RingBuf. Multi-byte fields (`src_port`,
  `dst_port`, `tcp_seq`, `udp_payload_len`) are stored in network byte order.

## 11. Module Layout

- `xdp_mirror-common/` — shared types (`Config`, `Stats`, `ProbeEventHeader`)
- `xdp_mirror-ebpf/` — eBPF kernel (protocol handlers, mode dispatch, RingBuf
  push, checksums)
- `xdp_mirror/` — userspace binary (CLI, eBPF load/attach, RingBuf drain,
  sniffer)
- `xdp_mirror/src/sniffer.rs` — AF_PACKET TX + RingBuf drain + edge-case
  response crafter

## 12. Deferred TODOs (Future Work)

- Malformed/corrupt responses.
- ICMP Dest-Unreachable / Time-Exceeded + unsolicited flood.
- UDP payload variants.

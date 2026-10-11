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

## 7a. Stats Output Flags (all modes)

- `--stats-file <path>` (default `/tmp/xdp_mirror_stats.jsonl`) — a tokio task
  polls the `PerCpuArray<Stats>` every 1 s, aggregates across CPUs (shared
  `aggregate_stats` helper, also used by the Ctrl-C printer) and appends one
  JSON line:
  ```json
  {"ts":<s since start>,"rx":…,"tx":…,"even_rx":…,"odd_rx":…,"udp_rx":…,"udp_tx":…,"icmp_rx":…,"icmp_tx":…,"no_rsp_count":…,"ring_dropped":…}
  ```
  The task stops on the same shutdown watch channel as the sniffer and
  performs one final aggregation before exiting.
- `--json-stats` — on Ctrl-C, print ONE JSON object instead of the German
  human-readable text:
  ```json
  {"final":true,"rx":…,"valid_syn":…,"tx":…,"rst_packets":…,"udp_rx":…,"udp_tx":…,"icmp_rx":…,"icmp_tx":…,"icmp_error_tx":…,"ring_dropped":…,"even_rx":…,"odd_rx":…,"no_rsp_count":…,"sniffer":null}
  ```
  When the sniffer ran, `"sniffer"` is `{"sent":…,"closed_sent":…,"fake_sent":…,"dropped_ring":…}`;
  otherwise `null`. Without the flag the German text output is kept
  (backward compat). The test-suite orchestrator always passes `--json-stats`.

### Counter validity by mode

| Counter | ebpf | raw | both |
|---------|------|-----|------|
| `rx`, `valid_syn`, `udp_rx`, `icmp_rx` | ✓ | ✓ | ✓ |
| `tx`, `udp_tx`, `icmp_tx` | ✓ | 0 (sniffer counts in `SnifferStats.sent`) | even-IP only |
| `even_rx`, `odd_rx` | ✓ | ✓ | ✓ |
| `no_rsp_count` | ✓ | 0 (no no-rsp logic in sniffer) | ✓ |
| `ring_dropped` | ✓ | ✓ | ✓ (eBPF side; sniffer drops count in `SnifferStats.dropped_ring`) |
| `icmp_error_tx` | ✓ | 0 | ✓ (odd-IP UDP errors) |

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

- **`Config`** (7 `u32` fields): `response_probability`, `validation_mode`,
  `ipv6`, `protocol`, `mode`, `icmp_error_type`, `no_rsp_perc`.
- **`Stats`** (13 `u64` counters, `#[repr(C)]` shared with eBPF):
  `rx`, `valid_syn`, `tx`, `rst_packets`, `udp_rx`, `udp_tx`, `icmp_rx`,
  `icmp_tx`, `ring_dropped`, `icmp_error_tx`, plus:
  - `even_rx` — valid probes with an even dst IP (hit candidates in valm).
    Incremented in the eBPF handlers (all modes) right after the
    protocol-specific validity checks, via `bump_rx_parity(dst_ip_even)`.
  - `odd_rx` — valid probes with an odd dst IP (misses in valm). Same
    increment site as `even_rx`.
  - `no_rsp_count` — hits suppressed by `--no-rsp-perc` (a `NoResponse`
    decision). Incremented in `decide()` — i.e. **eBPF only**, so the counter
    is valid in `ebpf` and `both` modes; in `raw` mode everything goes to the
    RingBuf and the sniffer has no no-rsp logic (it stays 0).
  - ⚠ `rx` counts **every frame** entering the program (including ARP and
    non-matching protocols), while `even_rx`/`odd_rx` count only valid probes
    of the selected protocol. On a quiet test LAN `even_rx + odd_rx ≈ rx`;
    the exact invariant is `even_rx + odd_rx <= rx`.
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

## 12. ICMP Error Simulation (ebpf/both modes)

The eBPF program can generate ICMP error responses for UDP misses at line rate,
extending the binary "mirror or drop" decision to a three-way choice:

- **Mirror**: UDP reply (swap src/dst, `XDP_TX`).
- **NoResponse**: silence (`XDP_DROP` for hits). Controlled by `--no-rsp-perc`.
- **IcmpError**: craft an ICMP error packet (`XDP_TX`). Controlled by
  `--icmp-error`.

### `--icmp-error <type>` flag

Selects the ICMP error type for UDP misses. Default: `none` (no ICMP errors).

| Name | Code | IPv4 type/code | IPv6 type/code | Meaning |
|------|------|---------------|----------------|---------|
| `none` | 0 | — | — | No ICMP errors (current behavior) |
| `port-unreach` | 1 | 3/3 | 1/4 | No service bound (closed) |
| `admin-prohibited` | 2 | 3/13 | 1/1 | Firewall rejected (filtered) |
| `host-unreach` | 3 | 3/1 | 1/3 | Router can't reach host |
| `net-unreach` | 4 | 3/0 | 1/0 | Router can't reach network |
| `time-exceeded` | 5 | 11/0 | 3/0 | TTL expired in transit |
| `all` | 6 | round-robin | round-robin | Cycle through all 5 types |

`--icmp-error` applies to **UDP only**. TCP misses → Drop (RST is TCP's closed
signal). ICMP misses → Drop (silence).

### `--no-rsp-perc N` flag

Percentage of hits (0-100) that get no response (silence) instead of a UDP
reply. Default: 0 (all hits get response, current behavior). Applies to **all
protocols**. In valm mode, the split is deterministic per-IP:
- IPv4: `u32::from_be(dst_addr) % 100 < no_rsp_perc`
- IPv6: `dst_addr[14] % 100 < no_rsp_perc` (byte 14, not 15, to avoid
  correlation with the even/odd check on byte 15)

### `decide()` three-way logic

`decide(config, dst_ip_even, no_rsp, is_udp) -> Action` returns one of:
`Mirror`, `NoResponse`, `IcmpError`, `PushRing`, `Drop`.

- **`ebpf` mode**: hit → Mirror or NoResponse (based on `no_rsp`); miss →
  IcmpError (if `is_udp && icmp_error_type != 0`) or Drop.
- **`both` mode**: even-IP → Mirror or NoResponse; odd-IP → IcmpError (if UDP)
  or PushRing.
- **`raw` mode**: PushRing for all (sniffer handles responses; `--closed` for
  ICMP in raw mode).

### `icmp_error_tx` Stats field

Per-CPU counter serving double duty:
- For `--icmp-error all`: round-robin index (read-and-increment per CPU in
  `icmp_type_code()`).
- For all types: count of ICMP errors sent (incremented in the handler for
  non-round-robin types, in `icmp_type_code()` for round-robin).

### ICMP error packet structure

- **IPv4** (70 bytes): Eth(14) + IP4(20, proto=1, tot_len=56) + ICMP(8) +
  Orig IP4(20) + Orig UDP(8). Source = target IP, dest = scanner IP.
- **IPv6** (110 bytes): Eth(14) + IP6(40, nh=58, plen=56) + ICMPv6(8) +
  Orig IP6(40) + Orig UDP(8). Source = target IP, dest = scanner IP.

All ICMP errors use the target IP as source (not a router IP). This is a known
limitation; the scanner ignores ICMP error responses anyway.

### Sniffer `--closed` flag

The sniffer's `--closed` flag remains independent for `raw`/`both` edge cases.
It sends ICMP Port Unreachable via AF_PACKET (userspace, ~100K-500K pps). The
new `--icmp-error` flag is eBPF-generated (line rate) for `ebpf`/`both` modes.

## 13. eBPF Verifier: `.text.unlikely.` Section Bug

### Problem

The kernel eBPF verifier rejected the program with "last insn is not an exit or
jmp / processed 0 insns". This was caused by a `.text.unlikely.` section in the
eBPF binary containing `panic_bounds_check` and `panic_fmt` — cold-path panic
handlers that LLVM places in a separate section.

bpf-linker creates BTF `func_info` entries for functions in `.text.unlikely.`
(because they have DWARF debug info) but does not register them as subprograms,
causing a `func_info_cnt != subprog_cnt` mismatch. The kernel verifier rejects
the program before processing a single instruction.

### Root Cause

Runtime-indexed array access on fixed-size arrays generates a bounds check. The
bounds check's failure path (`panic_bounds_check` → `panic_fmt`) is marked cold
by LLVM and placed in `.text.unlikely.`.

The specific trigger was `icmp_type_code()`:

```rust
// BAD: runtime idx → panic_bounds_check in .text.unlikely.
ICMP_V4_ERRORS[idx]
```

### Fix

Replace runtime array indexing with a `match` on the index. Constant-index
array access in each match arm is compile-time folded by LLVM — no bounds check,
no `.text.unlikely.` section:

```rust
let (v4, v6) = match idx {
    0 => (ICMP_V4_ERRORS[0], ICMP_V6_ERRORS[0]),
    1 => (ICMP_V4_ERRORS[1], ICMP_V6_ERRORS[1]),
    // ...
};
```

### What is NOT the problem

- **memset/memcpy relocations** are normal and accepted by the verifier. The
  working SYN-Rust binary also has 12 memset relocations. They are NOT the cause.
- **Toolchain version** is irrelevant — the issue reproduces on default nightly.
- **Global `debug = 2`** is not needed — the package-scoped
  `[profile.release.package.xdp_mirror-ebpf] debug = 2` is sufficient.

### Verification

After the fix, the eBPF binary has no `.text.unlikely.` section and no panic
symbols. Verify with:
```sh
llvm-objdump --section-headers <ebpf-binary> | grep text.unlikely
```

## 14. Deferred TODOs (Future Work)

- Malformed/corrupt responses.
- Router-spoofed source IPs for ICMP errors (currently target IP).
- UDP payload variants.

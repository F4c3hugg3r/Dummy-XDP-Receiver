# COMPREHENSIVE IMPLEMENTATION PROMPT: DummyReceiver UDP + ICMP Scan Simulation

> **You are an implementation-capable AI agent.** Below is a complete,
> self-contained specification for extending the DummyReceiver project. You have
> no prior context — everything you need is in this document. Read it fully
> before writing any code. When you encounter file paths, read those files for
> full context before editing them.

---

## TABLE OF CONTENTS

1. [Mission](#1-mission)
2. [Repository Layout](#2-repository-layout)
3. [Scanner Validation Reference](#3-scanner-validation-reference)
4. [Scanner Probe Construction Reference](#4-scanner-probe-construction-reference)
5. [Current DummyReceiver Reference](#5-current-dummyreceiver-reference)
6. [Architectural Decisions (All Resolved)](#6-architectural-decisions)
7. [Detailed Task Breakdown](#7-detailed-task-breakdown)
8. [Code Patterns to Follow](#8-code-patterns-to-follow)
9. [Validation](#9-validation)
10. [Risks and Known Issues](#10-risks-and-known-issues)
11. [Final Instruction: Update Project Context](#11-final-instruction)

---

## 1. MISSION

Extend the DummyReceiver (an eBPF/XDP program that simulates scan targets)
so it can simulate **TCP, UDP, and ICMP** scan targets for the SYN-Rust
scanner. Currently it only supports TCP. The extension must be:

1. **Configurable** — CLI flags to select protocol, response mode, edge-case
   behavior.
2. **Deterministic** — a `valm` mode that responds to exactly the even-IP
   targets (predictable assertions).
3. **Edge-case rich** — beyond single correct responses: multi-response,
   delayed responses, fake source IPs, and closed-host simulation.

The dummy must simulate **real kernel/host behavior**, not accommodate
scanner bugs. This is critical — see [§3.4](#34-icmpv6-type-129-bug).

---

## 2. REPOSITORY LAYOUT

### DummyReceiver (the project you're editing)
```
/home/lennard/PrivateRepos/Rust/DummyReceiver/
├── Cargo.toml                      # workspace root (resolver=2, edition 2024)
├── run.sh                          # convenience runner script
├── xdp_mirror-common/             # shared types crate (compiled into eBPF + userspace)
│   ├── Cargo.toml
│   └── src/lib.rs                  # Config, Stats structs
├── xdp_mirror-ebpf/               # the eBPF kernel program (no_std, no_main)
│   ├── Cargo.toml
│   ├── build.rs                    # locates bpf-linker
│   └── src/
│       ├── lib.rs                  # (empty, enables lib target)
│       └── main.rs                 # XDP program: TCP-only mirror
└── xdp_mirror/                     # userspace binary
    ├── Cargo.toml
    ├── build.rs                    # cargo-in-cargo eBPF build (aya_build)
    └── src/
        └── main.rs                 # CLI + eBPF load/attach + stats
```

### SYN-Rust scanner (READ-ONLY reference, do NOT edit except for [§11](#11-final-instruction))
```
/home/lennard/WorkRepos/ase/SYN-Rust/
├── ebpf/src/
│   ├── main.rs                     # XDP program (the scanner's receiving half)
│   ├── lib.rs                      # shared event structs (PacketLog, UdpResponseHeader, IcmpResponseLog)
│   └── handlers/
│       ├── tcp.rs                  # TCP validation
│       ├── udp.rs                  # UDP validation
│       └── icmp.rs                 # ICMP validation
├── scanner/src/
│   ├── scan_utils/probes/
│   │   ├── icmp.rs                 # ICMP probe construction (templates)
│   │   ├── udp.rs                  # UDP probe construction (templates + payloads)
│   │   └── tcp.rs                  # TCP probe construction (templates)
│   ├── scan_utils/emitting/
│   │   ├── sender.rs               # AF_PACKET socket setup (create_afp_socket, initialize_sock_addr)
│   │   └── assembler.rs            # wire offsets for complementing templates
│   ├── scan_utils/capturing/
│   │   └── receiver.rs             # RingBuf drain pattern (AsyncFd + next())
│   └── xdp.rs                      # eBPF load/attach/configure
└── .agents/AGENTS.md               # project context (to be updated in §11)
```

---

## 3. SCANNER VALIDATION REFERENCE

The scanner's eBPF program (`SYN-Rust/ebpf/src/handlers/`) validates incoming
packets in-kernel. A "hit" pushes an event struct to a RingBuf drained by
userspace. Below is exactly what the dummy must produce for its response to be
accepted as a valid hit.

### 3.1 TCP (`SYN-Rust/ebpf/src/handlers/tcp.rs`)

- A non-RST TCP packet is a **hit** iff:
  `ack_num.wrapping_sub(1) == SipHash24(k0,k1)(our_ip, target_ip, our_port, target_port)`
  (tried with current then previous SipHash keypair).
- The scanner bakes that cookie into the outgoing SYN's **sequence number**.
- **Implication for dummy**: respond with a SYN-ACK where `ack = incoming_seq + 1`.
  This passes the scanner's cookie check with **no key sharing needed**.
- RST flag (`tcp_flags & 0x04`) → scanner `XDP_PASS`es (RSTs go to normal stack,
  no hit). The dummy's valm mode counts RSTs it sees back (scanner sends RST
  after receiving SYN-ACK if `reset` is enabled).
- The handler does NOT require the SYN flag — it classifies any non-RST TCP
  packet whose ACK number equals `cookie+1`.

### 3.2 UDP (`SYN-Rust/ebpf/src/handlers/udp.rs`)

- A UDP packet is a **hit** iff its **destination** port is in the `SRC_PORTS`
  map (the scanner's source ports).
- Userspace additionally validates `udp_port_set.contains(src_port)` (the
  reply's source port must be one of the probed ports).
- **No cryptographic gate.** This is the weakest of the three protocol paths.
- **Implication for dummy**: swap src/dst ports (so the reply's dst port = the
  scanner's source port, and the reply's src port = the probed port). Echo the
  payload. Any UDP packet with the right port pairing is accepted.

### 3.3 ICMP (`SYN-Rust/ebpf/src/handlers/icmp.rs`)

- An ICMP Echo Reply is a **hit** iff ALL of:
  1. **Type pre-filter**: reply type must be `0` (IPv4) or `129` (IPv6).
  2. **16-byte payload match**: bytes at ICMP offset 8..24 must exactly equal
     the `ICMP_PAYLOAD` map (two big-endian u64).
  3. **ID match**: the 2-byte id at ICMP offset 4..6 must equal
     `SipHash24(k0,k1)(our_ip, target_ip) as u16` (cur then prev keypair).
- The scanner bakes the payload AND the id into the outgoing Echo Request.
- **`seq` (offset 6) and `code` (offset 1) are NOT validated.**
- ICMP echo message layout (24 bytes read by the handler):
  ```
  [0]     type      (8=Echo Req v4, 0=Echo Rep v4, 128=Echo Req v6, 129=Echo Rep v6)
  [1]     code      (0)
  [2..3]  checksum
  [4..5]  id        (SipHash-derived; must echo back)
  [6..7]  seq       (NOT validated)
  [8..23] payload   (16 random bytes; must echo back)
  ```
- **Implication for dummy**: respond with an Echo Reply that changes type
  (8→0 for v4, 128→129 for v6) and copies id, seq, and the 16-byte payload back.
  This passes the scanner's checks with **no key sharing needed**.

### 3.4 ICMPv6 Type-129 Bug (CRITICAL)

The scanner's ICMPv6 Echo **Request** uses type **129** (the Echo *Reply* type)
instead of type 128 (the Echo *Request* type):

```rust
// SYN-Rust/scanner/src/scan_utils/probes/icmp.rs:25
const ICMPV6_ECHO_REQUEST_TYPECODE: u16 = 129 << 8; // BUG: should be 128
```

A real IPv6 host **ignores** type-129 packets (they are Echo Replies, not
Requests). Therefore:

> **The dummy MUST simulate a real kernel.** It must respond ONLY to type 128
> (Echo Request) for IPv6, and IGNORE type 129. This means the scanner's
> ICMPv6 path will see **zero replies** against a correctly-simulated dummy.
> This is the truthful real-world result and surfaces the scanner bug.
>
> **Do NOT add a "robust" respond-to-129 shortcut.** The dummy's job is to
> simulate reality, not to work around scanner bugs.

For IPv4, the scanner correctly uses type 8 (Echo Request), and the dummy
responds with type 0 (Echo Reply).

### 3.5 Scanner Dedup (relevant for multi-response testing)

- TCP/UDP dedup key: `(ip.octets(), port)`
- ICMP dedup key: `ip.octets()` only
- Eviction window: **3 seconds** (floor)
- Buffer size: 262144 entries (floor)
- A duplicate within the window does NOT refresh the timestamp; duplicates are
  silently collapsed to a single hit.

### 3.6 Scanner Receiver Timing

- `parsing_timeout_millis`: after the sender finishes, the receiver waits this
  long for late replies before exiting. Late replies past this timeout are
  missed.
- 200ms batch-flush tick; 500ms signal-poll tick.

---

## 4. SCANNER PROBE CONSTRUCTION REFERENCE

The scanner builds "templates" — fully-formed Ethernet frames with the
destination IP zeroed (and dst_port/id zeroed for TCP/ICMP). The assembler
patches in the target's IP/port/id at line rate.

### 4.1 Wire Offsets (from `SYN-Rust/scanner/src/scan_utils/emitting/assembler.rs`)

| Protocol | dst_ip | dst_port | seq/id | L3 csum | L4 csum | min len |
|----------|--------|----------|--------|---------|---------|---------|
| TCP IPv4 | `[30..34]` | `[36..38]` | seq `[38..42]` | IP `[24..26]` | TCP `[50..52]` | 54 |
| TCP IPv6 | `[38..54]` | `[56..58]` | seq `[58..62]` | n/a | TCP `[70..72]` | 74 |
| UDP IPv4 | `[30..34]` | `[36..38]` | n/a | IP `[24..26]` | UDP `[40..42]` | 42 |
| UDP IPv6 | `[38..54]` | `[56..58]` | n/a | n/a | UDP `[60..62]` | 62 |
| ICMP IPv4 | `[30..34]` | n/a | id `[38..40]` | IP `[24..26]` | ICMP `[36..38]` | 58 |
| ICMP IPv6 | `[38..54]` | n/a | id `[58..60]` | n/a | ICMPv6 `[56..58]` | 78 |

These are byte offsets from the start of the Ethernet frame. The eBPF dummy
intercepts the *outgoing* probe (dst_ip = target IP, dst_port/id = the
scanned target's port/id). The dummy reflects it back.

### 4.2 ICMP Echo Request Layout (what the dummy sees)

**IPv4** (58 bytes total: 14 eth + 20 ip + 8 icmp + 16 payload):
```
Ethernet: [0..14]
IPv4:     [14..34]  proto=1(ICMP), src=scanner_ip, dst=target_ip
ICMP:     [34..58]
  [34]    type = 8 (Echo Request)
  [35]    code = 0
  [36..37] checksum
  [38..39] id = SipHash24(scanner_ip, target_ip) as u16
  [40..41] seq = 1 (big-endian)
  [42..57] payload = 16 random bytes
```

**IPv6** (78 bytes total: 14 eth + 40 ip + 8 icmp + 16 payload):
```
Ethernet: [0..14]
IPv6:     [14..54]  next_header=58(ICMPv6), src=scanner_ip, dst=target_ip
ICMPv6:   [54..78]
  [54]    type = 129 (BUG — should be 128; dummy must IGNORE)
  [55]    code = 0
  [56..57] checksum
  [58..59] id
  [60..61] seq
  [62..77] payload = 16 random bytes
```

### 4.3 UDP Probe Layout (what the dummy sees)

UDP templates bake in the destination port (unlike TCP). The dummy sees:
```
IPv4: [14..34] proto=17(UDP), src=scanner_ip, dst=target_ip
UDP:  [34..42] src=scanner_src_port, dst=probed_port, len, checksum
      [42..]  payload (varies by service probe: SNMP, NTP, DNS, etc.)
```

---

## 5. CURRENT DUMMY RECEIVER REFERENCE

### 5.1 `xdp_mirror-common/src/lib.rs` (shared types)

```rust
#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    pub response_probability: u32, // 0-100
    pub validation_mode: u32,      // 0 = false, 1 = true
    pub ipv6: u32,                 // 0 = false, 1 = true
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
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Stats {}
```

### 5.2 `xdp_mirror-ebpf/src/main.rs` (eBPF program — TCP only)

Key elements:
- `#![no_std]` `#![no_main]`
- Maps: `#[map] static CONFIG: Array<Config>`, `#[map] static STATS: PerCpuArray<Stats>`
- Header structs: `EthHdr`, `Ipv4Hdr`, `Ipv6Hdr`, `TcpHdr` (all `#[repr(C)]`)
- `ptr_on<T>(ctx, offset)` → bounds-checked pointer derivation (returns `*mut T`)
- `try_xdp_mirror(ctx)` → main logic:
  1. Increment `STATS[0].rx`
  2. Read `CONFIG`
  3. Check ether_type (IPv4 or IPv6 based on `config.ipv6`)
  4. For IPv4: parse IPv4 + TCP, check `proto == TCP`, check SYN flag
  5. For IPv6: parse IPv6 + TCP, check `next_header == TCP`, check SYN flag
  6. **valm mode** (`validation_mode != 0`): respond iff dst IP is even
     - IPv4: `u32::from_be(dst_addr) % 2 != 0` → drop
     - IPv6: `dst_addr[15] % 2 != 0` → drop
  7. **percentage mode**: `bpf_get_prandom_u32() % 100 >= response_probability` → drop
  8. If responding: `bpf_xdp_adjust_tail` to shrink/expand to Eth+IP+TCP,
     swap MACs/IPs/ports, set `ack = seq + 1`, set SYN+ACK flags, recompute
     checksums, return `XDP_TX`
- Checksum helpers: `ipv4_csum`, `tcp_v4_csum`, `tcp_v6_csum`
- Panic handler: `loop {}`

**BUG TO FIX**: Non-IP / wrong-ether-type frames currently return
`XDP_DROP` (line 116). This drops ARP, which can break MAC resolution.
**Change to `XDP_PASS`** so non-targeted frames reach the kernel.

### 5.3 `xdp_mirror/src/main.rs` (userspace binary)

Key elements:
- CLI via clap: `--iface`, `--percentage`, `--valm`, `--ipv6`
- Sets memlock rlimit to infinity
- Loads eBPF via `aya::include_bytes_aligned!`
- Initializes eBPF logger
- Sets `CONFIG` map (response_probability, validation_mode, ipv6)
- Loads + attaches XDP program (`program.load()`, `program.attach(&iface, ...)`)
- Waits for Ctrl-C
- Prints stats from `STATS` PerCpuArray

### 5.4 `Cargo.toml` (workspace)

```toml
[workspace]
resolver = "2"
members = ["xdp_mirror", "xdp_mirror-common", "xdp_mirror-ebpf"]
default-members = ["xdp_mirror", "xdp_mirror-common"]

[workspace.package]
edition = "2024"

[workspace.dependencies]
aya = { git = "https://github.com/aya-rs/aya", default-features = false }
aya-build = { git = "https://github.com/aya-rs/aya", default-features = false }
aya-ebpf = { git = "https://github.com/aya-rs/aya", default-features = false }
# ... clap, tokio, libc, etc.
```

### 5.5 `run.sh`

```bash
#!/bin/bash
IFACE=${1:-eno1}
shift 2>/dev/null || true
PERCENTAGE=50
if [[ "$1" =~ ^[0-9]+$ ]]; then PERCENTAGE=$1; shift; fi
EXTRA_ARGS="$@"
RUST_LOG=info cargo run --release -- --iface "$IFACE" --percentage "$PERCENTAGE" $EXTRA_ARGS
```

---

## 6. ARCHITECTURAL DECISIONS

All decisions below are RESOLVED. Do not revisit them.

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| 1 | Architecture | **Hybrid**: eBPF line-rate mirror + userspace raw-socket injector | eBPF handles normal high-rate mirroring; raw socket handles edge cases that can't be done in-kernel |
| 2 | Coexistence | **Mutually-exclusive modes** (`ebpf` \| `raw` \| `both`) | Clean separation; `both` gives mixed realistic stress |
| 3 | Default behavior | **Real-kernel/host simulation** | The dummy simulates reality, not scanner quirks |
| 4 | Deterministic (valm) mode | **Universal even dst IP** for all 3 protocols | Simple, consistent, easy to assert |
| 5 | Raw-socket edge cases (now) | Multi-response (N per probe), Delayed responses, Fake source IP, Closed-host simulation | See [§7 T4](#t4) for details |
| 5b | Raw-socket edge cases (TODO, do NOT implement now) | Malformed/corrupt; ICMP errors + unsolicited flood; UDP payload variants | Documented for future work |
| 6 | `both` mode split | eBPF mirrors even-IP (TX); pushes odd-IP to RingBuf + DROP; sniffer handles odd-IPs | Deterministic split; easy to assert |
| 7 | Sniffer probe source | **eBPF→RingBuf→sniffer** | eBPF pushes ProbeEvent to RingBuf + XDP_DROPs (kernel never sees probe → no competing kernel RST/echo-reply); sniffer drains RingBuf via AsyncFd + sends via AF_PACKET TX socket |

### Mode semantics

- **`ebpf`** (default): eBPF mirrors filter-hits (valm/percentage) at line rate;
  non-hits `XDP_DROP`. No RingBuf, no sniffer.
- **`raw`**: eBPF pushes EVERY valid probe to the `PROBES` RingBuf and
  `XDP_DROP`s (no in-kernel mirror). Sniffer drains RingBuf and applies
  edge-case logic to all entries.
- **`both`**: eBPF mirrors even-IP hits (`XDP_TX`); pushes odd-IP non-hits to
  the RingBuf + `XDP_DROP`. Sniffer applies edge-case logic to all RingBuf
  entries.

> The valm/percentage filter ONLY gates the eBPF in-kernel mirror. In `raw`
> and `both`, the sniffer responds to every RingBuf entry (the eBPF already
> decided what reaches the sniffer).

### Data flow

```
                    ┌──────────── xdp_mirror-ebpf (kernel) ────────────┐
  scanner probe ──▶ │ parse eth+ip; dispatch proto; apply mode logic:  │
                    │  ebpf-hit  ──▶ mirror in-kernel ──▶ XDP_TX ─────▶ │ back to scanner
                    │  raw/both-nonhit ──▶ push ProbeEvent ──▶ RingBuf │
                    │  else ──▶ XDP_DROP (kernel never sees probe)     │
                    └────────────────────┬─────────────────────────────┘
                                         │ drain (AsyncFd)
                    ┌────────────────────▼────────── xdp_mirror (user) ─┐
                    │ sniffer: for each ProbeEvent apply edge cases:    │
                    │   closed? → RST / ICMP-Port-Unreach / silence     │
                    │   else × count: sleep(delay); craft response      │
                    │   (optional fake_ip); send via AF_PACKET TX ──▶ scanner │
                    └───────────────────────────────────────────────────┘
```

### Module / file layout (new/changed files)

```
xdp_mirror-common/src/lib.rs   — Config (extended), Stats (extended), ProbeEventHeader (NEW)
xdp_mirror-ebpf/src/main.rs    — TCP+UDP+ICMP handlers, mode dispatch, RingBuf push, checksums
xdp_mirror/src/main.rs         — CLI (extended), eBPF load/attach, RingBuf take, spawn sniffer, stats
xdp_mirror/src/sniffer.rs      — (NEW) AF_PACKET TX + RingBuf drain + edge-case response crafter
xdp_mirror/Cargo.toml          — add nix, pnet
.agents/AGENTS.md              — (NEW) architecture doc for this repo
```

---

## 7. DETAILED TASK BREAKDOWN

Implement in order T1→T6. Each task is self-contained; do not skip ahead.

### T1 — `xdp_mirror-common/src/lib.rs`: shared types

**Read the current file first** — it's small (see [§5.1](#51-xdp_mirror-commonsrclibrs-shared-types)).

#### T1.1 Extend `Config`

Add two new `u32` fields (all fields must be `u32` for aya `Pod` simplicity):

```rust
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Config {
    pub response_probability: u32, // 0-100
    pub validation_mode: u32,      // 0 = percentage, 1 = valm (even-IP)
    pub ipv6: u32,                 // 0 = false, 1 = true
    pub protocol: u32,             // 0 = any, 1 = tcp, 2 = udp, 3 = icmp
    pub mode: u32,                 // 0 = ebpf, 1 = raw, 2 = both
}
```

#### T1.2 Extend `Stats`

Keep existing fields, add per-protocol counters:

```rust
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub rx: u64,
    pub valid_syn: u64,    // rename conceptually to "valid_probes" but keep field name for compat
    pub tx: u64,
    pub rst_packets: u64,
    pub udp_rx: u64,
    pub udp_tx: u64,
    pub icmp_rx: u64,
    pub icmp_tx: u64,
}
```

#### T1.3 Add `ProbeEventHeader`

This struct carries everything the userspace sniffer needs to craft a response.
Mirror the scanner's `ebpf/src/lib.rs` style: `#[repr(C, packed)]`, `zerocopy`
`FromBytes`/`Unaligned`/`Immutable`/`KnownLayout`, with compile-time size asserts.

The scanner uses `zerocopy` for this. Check the scanner's
`ebpf/src/lib.rs` for the exact derive pattern and copy it. You'll need to add
`zerocopy` to `xdp_mirror-common/Cargo.toml`.

```rust
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, Unaligned, Immutable, KnownLayout)]
pub struct ProbeEventHeader {
    pub protocol: u8,          // 6=TCP, 17=UDP, 1=ICMPv4, 58=ICMPv6
    pub version: u8,           // 4 | 6
    pub _pad: [u8; 2],
    pub src_mac: [u8; 6],     // scanner's MAC (becomes dst in response)
    pub dst_mac: [u8; 6],     // gateway/target MAC (becomes src in response)
    pub src_ip: [u8; 16],     // v4 in first 4 bytes (scanner convention)
    pub dst_ip: [u8; 16],
    pub src_port: u16,        // TCP/UDP; 0 for ICMP
    pub dst_port: u16,        // TCP/UDP; 0 for ICMP
    pub tcp_seq: u32,         // TCP only (network byte order)
    pub icmp_type: u8,        // ICMP only (request type)
    pub icmp_code: u8,        // ICMP only
    pub icmp_id: [u8; 2],     // ICMP only
    pub icmp_seq: [u8; 2],    // ICMP only
    pub icmp_payload: [u8; 16], // ICMP only
    pub udp_payload_len: u16, // #bytes following this header (UDP only)
}
```

Add compile-time assertions (mirror the scanner's `ebpf/src/lib.rs`):

```rust
const _: () = assert!(core::mem::size_of::<ProbeEventHeader>() == <computed_size>);
const _: () = assert!(core::mem::offset_of!(ProbeEventHeader, protocol) == 0);
// ... one assert per field offset
```

RingBuf entry layout = `[ProbeEventHeader][udp_payload_len bytes]` (the
scanner's `UdpResponseHeader`+payload pattern from
`SYN-Rust/ebpf/src/handlers/udp.rs:push_udp_response`).

### T2 — `xdp_mirror-ebpf/src/main.rs`: protocol handlers + mode logic

**Read the current file first** (374 lines, see [§5.2](#52-xdp_mirrorebbpfsrclibrs-ebpf-program--tcp-only)).

#### T2.1 Add header structs and constants

Add after the existing `TcpHdr`:

```rust
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UdpHdr {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}
```

ICMP is read byte-wise (no struct needed). Add constants:

```rust
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;       // ICMPv4
const IPPROTO_ICMPV6: u8 = 58;    // ICMPv6 (next_header value)
const ICMPV4_ECHO_REQUEST: u8 = 8;
const ICMPV6_ECHO_REQUEST: u8 = 128;   // CORRECT type — real kernel
const ICMPV4_ECHO_REPLY: u8 = 0;
const ICMPV6_ECHO_REPLY: u8 = 129;
```

#### T2.2 Add the PROBES RingBuf map

Add after the existing `STATS` map:

```rust
use aya_ebpf::maps::RingBuf;

#[map]
static PROBES: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0); // 16 MiB
```

This mirrors the scanner's `EVENTS` map in `SYN-Rust/ebpf/src/main.rs:44`.

#### T2.3 Fix the ARP-drop bug

In `try_xdp_mirror`, the current code returns `XDP_DROP` for non-matching
ether_type (line ~116). **Change to `XDP_PASS`**:

```rust
if unsafe { (*eth_hdr).ether_type } != expected_ether_type {
    return Ok(xdp_action::XDP_PASS);  // was XDP_DROP — fixes ARP resolution
}
```

#### T2.4 Refactor into protocol dispatch with mode logic

Create an `enum Action { Mirror, PushRing, Drop }` and a `decide` function:

```rust
enum Action { Mirror, PushRing, Drop }

#[inline(always)]
fn decide(config: &Config, dst_ip_even: bool) -> Action {
    match config.mode {
        1 => Action::PushRing,  // raw mode: push everything
        2 => {                  // both mode: even-IP mirrors, odd-IP pushes
            if dst_ip_even { Action::Mirror } else { Action::PushRing }
        }
        _ => {                  // ebpf mode: valm or percentage
            let is_hit = if config.validation_mode != 0 {
                dst_ip_even
            } else {
                unsafe { bpf_get_prandom_u32() % 100 } < config.response_probability
            };
            if is_hit { Action::Mirror } else { Action::Drop }
        }
    }
}
```

Also apply the **protocol filter**: if `config.protocol != 0` (not "any") and
the packet's IP protocol doesn't match the configured protocol, return
`XDP_PASS` (don't eat non-targeted protocols).

#### T2.5 TCP handler (refactor existing)

Keep the existing TCP mirror logic (IPv4 and IPv6 SYN→SYN-ACK). For each
protocol+version path, after parsing and validating the SYN:

1. Compute `dst_ip_even` (IPv4: `u32::from_be(dst_addr) % 2 == 0`; IPv6:
   `dst_addr[15] % 2 == 0`).
2. Call `decide(config, dst_ip_even)`.
3. `Mirror` → existing mirror code (adjust_tail, swap, recompute, XDP_TX).
4. `PushRing` → fill a `ProbeEventHeader` with `{protocol, version, macs, ips,
   ports, tcp_seq}` and call `push_probe_event()`.
5. `Drop` → `XDP_DROP`.

Keep the existing RST-counting in valm mode (`rst_packets++` on RST seen).

#### T2.6 UDP handler (NEW, v4+v6)

For each version:
1. Validate `proto == UDP` (IPv4) or `next_header == UDP` (IPv6).
2. Parse the UDP header.
3. Compute `payload_len = u16::from_be(udp.len).saturating_sub(8)`.
4. Compute `dst_ip_even`.
5. Call `decide(config, dst_ip_even)`.
6. **Mirror**: swap MACs/IPs/ports, keep payload in place (echo), recompute IP
   csum (IPv4) + UDP csum. UDP csum includes the IPv4/IPv6 pseudo-header —
   mirror the existing `tcp_v4_csum`/`tcp_v6_csum` pattern but with proto=17
   and the UDP length. **No `adjust_tail` needed** (same length). Return
   `XDP_TX`.
7. **PushRing**: fill `ProbeEventHeader` with `{protocol=17, version, macs,
   ips, ports, udp_payload_len}` and call `push_probe_event()` with a pointer
   to the UDP payload and `payload_len`.
8. Increment `udp_rx` on parse, `udp_tx` on mirror.

#### T2.7 ICMP handler (NEW, v4+v6)

For each version:
1. Validate `proto == ICMP` (IPv4, proto=1) or `next_header == ICMPv6` (IPv6,
   next_header=58).
2. Read the ICMP type byte at the ICMP offset.
3. **IPv4**: accept only type 8 (Echo Request). Ignore everything else → `XDP_PASS`.
4. **IPv6**: accept only type 128 (Echo Request). **Ignore type 129** (real
   kernel behavior — see [§3.4](#34-icmpv6-type-129-bug-critical)). → `XDP_PASS`.
5. Read id (offset 4..6), seq (offset 6..8), payload (offset 8..24).
6. Compute `dst_ip_even`.
7. Call `decide(config, dst_ip_even)`.
8. **Mirror**: set type to 0 (v4) / 129 (v6), keep id/seq/payload, swap
   MACs/IPs, recompute IP csum (v4) + ICMP csum. **No `adjust_tail` needed**
   (same length). Return `XDP_TX`.
9. **PushRing**: fill `ProbeEventHeader` with `{protocol, version, macs, ips,
   icmp_type, icmp_id, icmp_seq, icmp_payload}` and call `push_probe_event()`.
10. Increment `icmp_rx` on parse, `icmp_tx` on mirror.

#### T2.8 Add checksum helpers

Follow the existing `tcp_v4_csum`/`tcp_v6_csum`/`ipv4_csum` patterns exactly:

- `udp_v4_csum(ip_hdr, udp_hdr, udp_len)`: pseudo-header = src_ip(4) + dst_ip(4)
  + proto(17, 2 bytes) + udp_len(2 bytes), then sum over UDP header+payload.
- `udp_v6_csum(ip_hdr, udp_hdr, udp_len)`: pseudo-header = src_addr(16) +
  dst_addr(16) + udp_len(4 bytes, upper+lower) + next_header(58→use 17 for UDP,
  2 bytes), then sum over UDP header+payload.
- `icmp_v4_csum(icmp_ptr, total_len)`: Internet checksum over ICMP header+payload
  only (NO pseudo-header for IPv4 ICMP).
- `icmp_v6_csum(ip_hdr, icmp_ptr, total_len)`: Internet checksum over ICMPv6
  header+payload + IPv6 pseudo-header (src, dst, length, next_header=58).

The existing checksum pattern sums u16 words, carry-folds, and complements:

```rust
unsafe fn checksum_words(ptr: *const u16, count: usize, initial_sum: u32) -> u16 {
    let mut sum = initial_sum;
    for i in 0..count {
        sum += unsafe { *ptr.add(i) } as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}
```

#### T2.9 Add `push_probe_event`

Mirrors the scanner's `push_udp_response` in
`SYN-Rust/ebpf/src/handlers/udp.rs`:

```rust
#[inline(always)]
fn push_probe_event(
    hdr: &ProbeEventHeader,
    udp_payload_ptr: *const u8,
    udp_payload_len: usize,
) -> Result<u32, ()> {
    let hdr_size = mem::size_of::<ProbeEventHeader>();
    let total = hdr_size + udp_payload_len;
    if let Some(mut bytes) = PROBES.reserve_bytes(total, 0) {
        let hdr_bytes = unsafe {
            core::slice::from_raw_parts(hdr as *const ProbeEventHeader as *const u8, hdr_size)
        };
        bytes[..hdr_size].copy_from_slice(hdr_bytes);
        if udp_payload_len > 0 {
            let dst = bytes[hdr_size..].as_mut_ptr();
            unsafe { core::ptr::copy_nonoverlapping(udp_payload_ptr, dst, udp_payload_len) };
        }
        bytes.submit(0);
    } else {
        // ring overflow — increment a drop stat
    }
    Ok(xdp_action::XDP_DROP)
}
```

### T3 — `xdp_mirror/src/main.rs`: CLI + mode dispatch + RingBuf + stats

**Read the current file first** (see [§5.3](#53-xdp_mirroresrcmainrs-userspace-binary)).

#### T3.1 Extend the CLI (`Opt` struct)

```rust
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
    // NEW:
    #[clap(long, default_value = "ebpf")]
    mode: String,           // "ebpf" | "raw" | "both"
    #[clap(long, default_value = "any")]
    protocol: String,       // "any" | "tcp" | "udp" | "icmp"
    #[clap(long, default_value = "1")]
    count: u32,             // sniffer: responses per probe
    #[clap(long, default_value = "0")]
    delay: u64,             // sniffer: delay before responding (ms)
    #[clap(long)]
    fake_ip: Option<String>, // sniffer: fake source IP
    #[clap(long)]
    closed: bool,           // sniffer: simulate closed port/host
}
```

#### T3.2 Set extended Config

Map `mode` string to u32: `ebpf`=0, `raw`=1, `both`=2.
Map `protocol` string to u32: `any`=0, `tcp`=1, `udp`=2, `icmp`=3.

```rust
config_map.set(0, xdp_mirror_common::Config {
    response_probability: percentage,
    validation_mode: valm as u32,
    ipv6: ipv6 as u32,
    protocol: protocol_code,
    mode: mode_code,
}, 0)?;
```

#### T3.3 Take the RingBuf and spawn the sniffer (raw/both modes only)

Mirror the scanner's pattern from `SYN-Rust/scanner/src/main.rs:65`:

```rust
let needs_sniffer = mode == "raw" || mode == "both";
let ring_buf = if needs_sniffer {
    Some(aya::maps::RingBuf::try_from(ebpf.take_map("PROBES").unwrap())?)
} else {
    None
};
```

If `needs_sniffer`, create an `AF_PACKET` TX socket (see [§8.3](#83-af_packet-socket-setup))
and spawn the sniffer task (T4). The sniffer needs:
- The `RingBuf` (for draining probe events)
- The `AF_PACKET` socket fd + `LinkAddr`
- The edge-case config (`count`, `delay`, `fake_ip`, `closed`)

#### T3.4 Print extended stats on Ctrl-C

Sum eBPF `PerCpuArray<Stats>` across CPUs (existing pattern), plus print
sniffer userspace atomics if the sniffer ran.

### T4 — `xdp_mirror/src/sniffer.rs`: AF_PACKET TX + RingBuf drain + edge cases

This is a **NEW file**. Create `xdp_mirror/src/sniffer.rs` and declare it in
`xdp_mirror/src/main.rs` with `mod sniffer;`.

#### T4.1 AF_PACKET TX socket setup

Mirror the scanner's `create_afp_socket` and `initialize_sock_addr` from
`SYN-Rust/scanner/src/scan_utils/emitting/sender.rs:665-755`:

```rust
// Create AF_PACKET raw socket
let fd = nix::sys::socket::socket(
    nix::sys::socket::AddressFamily::Packet,
    nix::sys::socket::SockType::Raw,
    nix::sys::socket::SockFlag::empty(),
    nix::sys::socket::SockProtocol::EthAll,
)?;

// Set SO_SNDBUF to 32 MB (mirror scanner)
// Find interface index by name (use libc::if_nametoindex or nix)
// Build sockaddr_ll with the interface index
// Wrap in nix::sys::socket::LinkAddr
```

See [§8.3](#83-af_packet-socket-setup) for the full reference code.

#### T4.2 RingBuf drain loop

Mirror the scanner's receiver pattern from
`SYN-Rust/scanner/src/scan_utils/capturing/receiver.rs:174-381`:

```rust
let fd = ring_buf.as_raw_fd();
let async_fd = tokio::unix::AsyncFd::new(fd).unwrap();

loop {
    tokio::select! {
        // Stop signal
        _ = stop_rx.recv() => break,
        // RingBuf readable
        guard = async_fd.readable_mut() => {
            while let Some(item) = ring_buf.next() {
                // Parse ProbeEventHeader from item bytes
                // Apply edge-case logic (T4.3)
                // Craft + send response via AF_PACKET
            }
            guard.clear_ready();
        }
    }
}
```

`ring_buf.next()` returns `Option<&[u8]>` — a byte slice of one entry. Parse
the first `size_of::<ProbeEventHeader>()` bytes as the header, then the
remaining `udp_payload_len` bytes as UDP payload (if protocol == UDP).

#### T4.3 Edge-case logic

For each `ProbeEvent`:

```rust
if closed {
    match protocol {
        TCP  => craft_and_send_rst(event),        // RST: seq=event.tcp_seq+1, ack=0, flags=RST
        UDP  => craft_and_send_icmp_unreach(event), // ICMP type 3 code 3
        ICMP => { /* send nothing — closed host is silent */ }
    }
} else {
    for _ in 0..count {
        if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }
        craft_and_send_response(event, fake_ip);
    }
}
```

**Normal response crafting** (for each of `count` iterations):
- Build a full Ethernet frame from scratch.
- `dst_mac = event.src_mac`, `src_mac = event.dst_mac`.
- TCP: SYN-ACK with `ack = event.tcp_seq + 1`, random seq, swap ports.
- UDP: swap ports, echo payload (from the event's trailing bytes).
- ICMP: Echo Reply (type 0 v4 / 129 v6), copy id/seq/payload from event.
- If `fake_ip` is set: replace the response's source IP with `fake_ip`.
  - Note: TCP/ICMP fake-IP replies will be **rejected** by the scanner's
    cookie/id gate (the SipHash won't match). This is the intended test of the
    scanner's forgery defense.
  - UDP fake-IP replies **are accepted** by the scanner (no crypto gate).
- Recompute all checksums (IP, TCP/UDP/ICMP).
- `sendto(fd, frame, &link_addr, MsgFlags::empty())`.

**Closed-port responses**:
- TCP RST: `seq = event.tcp_seq + 1`, `ack_seq = 0`, flags = RST (0x04),
  `doff_res = 0x50`, window=0, swap ports, swap IPs/MACs, recompute checksums.
- UDP ICMP Port Unreachable: ICMP type 3, code 3, src = target IP (event.dst_ip),
  dst = scanner IP (event.src_ip). Payload = original IPv4 header (20 bytes) +
  original UDP header (8 bytes) = 28 bytes minimum (per RFC 792). Reconstruct
  these from the event's fields.
- ICMP: send nothing (closed host = no reply).

#### T4.4 Userspace stats (atomics)

Track: `sniffer_sent`, `sniffer_closed`, `sniffer_fake`, `sniffer_dropped_ring`.
Print on exit.

### T5 — `.agents/AGENTS.md`: document the architecture

Create `/home/lennard/PrivateRepos/Rust/DummyReceiver/.agents/AGENTS.md`
documenting:
- The dummy's purpose (testing tool for SYN-Rust scanner)
- The 3 modes (`ebpf`/`raw`/`both`)
- The eBPF→RingBuf→sniffer data flow
- Per-protocol mirror logic (TCP SYN-ACK, UDP echo, ICMP Echo Reply)
- The real-kernel behavior rule (including the ICMPv6 type-128/129 note)
- Edge-case flags (`--count`, `--delay`, `--fake-ip`, `--closed`)
- The known scanner quirk (ICMPv6 type-129 request bug)
- The ARP-drop bug fix

Keep this as the source of truth for the DummyReceiver project.

### T6 — `run.sh` + `README.md`

#### T6.1 `run.sh`

The script already forwards `$@` as extra args, so no changes are strictly
needed. But add a comment documenting the new flags:

```bash
# New flags (passed via EXTRA_ARGS):
#   --mode ebpf|raw|both       (default: ebpf)
#   --protocol any|tcp|udp|icmp (default: any)
#   --count N                   (sniffer: responses per probe, default 1)
#   --delay MS                  (sniffer: delay before responding, ms)
#   --fake-ip IP                (sniffer: fake source IP)
#   --closed                    (sniffer: simulate closed port/host)
```

#### T6.2 `README.md`

Add a section documenting the new modes and flags, with a usage example per
protocol. Keep the existing prerequisites and build instructions.

---

## 8. CODE PATTERNS TO FOLLOW

### 8.1 eBPF `ptr_at` pattern (BPF verifier constraint)

The existing `ptr_on<T>` function in `xdp_mirror-ebpf/src/main.rs` is the
bounds-checked pointer derivation pattern. The BPF verifier requires the
bounds check and pointer derivation in the same function scope. Always use
this helper — never dereference packet data without it.

### 8.2 Checksum pattern

All checksum functions in the existing code follow this pattern:
1. Sum u16 words (in network byte order) into a `u32` accumulator.
2. Add pseudo-header words first (for TCP/UDP/ICMPv6).
3. Add the L4 header + payload words.
4. Carry-fold: `while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }`
5. Complement: `!sum as u16`

For UDP/ICMP, the checksum field must be zeroed BEFORE summing, then set to
the result.

### 8.3 AF_PACKET socket setup (from scanner `sender.rs:665-755`)

```rust
// Create the socket
let fd = nix::sys::socket::socket(
    nix::sys::socket::AddressFamily::Packet,  // AF_PACKET
    nix::sys::socket::SockType::Raw,
    nix::sys::socket::SockFlag::empty(),
    nix::sys::socket::SockProtocol::EthAll,   // ETH_P_ALL
)?;

// Optionally set PACKET_QDISC_BYPASS and SO_SNDBUF (see scanner code)

// Find interface index
let ifindex = libc::if_nametoindex(interface.as_ptr()); // or use nix helper

// Build sockaddr_ll
let sock_addr = libc::sockaddr_ll {
    sll_family: libc::AF_PACKET as u16,
    sll_protocol: libc::ETH_P_ALL as u16,
    sll_ifindex: ifindex as i32,
    sll_hatype: 0,
    sll_pkttype: 0,
    sll_halen: 6,
    sll_addr: [dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5], 0, 0],
};

// Wrap in LinkAddr
let link_addr = unsafe {
    nix::sys::socket::LinkAddr::from_raw(
        &sock_addr as *const _ as *const libc::sockaddr, None
    )
}?;

// Send a packet
nix::sys::socket::sendto(
    fd.as_raw_fd(),
    &packet_bytes,      // full Ethernet frame
    &link_addr,
    nix::sys::socket::MsgFlags::empty(),
)?;
```

Note: for the sniffer, the `dst_mac` in the sockaddr_ll should be the scanner's
MAC (= `event.src_mac`), since we're sending back to the scanner. However, the
Ethernet frame itself carries the real dst_mac, so the sockaddr_ll mac may not
matter on all kernels. Set it to the event's src_mac to be safe.

### 8.4 RingBuf drain pattern (from scanner `receiver.rs:174-381`)

```rust
let fd = ring_buf.as_raw_fd();
let async_fd = tokio::unix::AsyncFd::new(fd).unwrap();

loop {
    tokio::select! {
        _ = stop_rx.recv() => break,
        guard = async_fd.readable_mut() => {
            let mut guard = guard.unwrap();
            while let Some(item) = ring_buf.next() {
                // item is &[u8] — one ring entry
                let header = ProbeEventHeader::ref_from_bytes(&item[..size_of::<ProbeEventHeader>()]).unwrap();
                // ... process ...
            }
            guard.clear_ready();
        }
    }
}
```

### 8.5 `Config`/`Stats` Pod trait

All shared types used in aya maps must implement `Pod` (unsafe). The existing
pattern uses `#[cfg(feature = "user") unsafe impl aya::Pod for Type {}`. For
the new `ProbeEventHeader`, if it needs to be in a map (it doesn't — it goes
through the RingBuf as raw bytes), you don't need Pod. But you DO need
`zerocopy::FromBytes` for userspace parsing.

### 8.6 Import style

The project uses `rustfmt.toml` with `group_imports = StdExternalCrate` and
`imports_granularity = Crate`. Follow this for new files. Check
`/home/lennard/PrivateRepos/Rust/DummyReceiver/rustfmt.toml` for settings.

---

## 9. VALIDATION

1. **Build**: `cargo build` with no warnings. The eBPF builds via cargo-in-cargo
   (`xdp_mirror/build.rs` calls `aya_build::build_ebpf`).
2. **TCP regression**: `./run.sh <iface> 50` — scanner TCP scan sees ~50% hits.
   `./run.sh <iface> 50 --valm` — only even-IP targets hit.
3. **UDP (ebpf)**: `./run.sh <iface> 50 --protocol udp` — scanner UDP scan sees
   echo replies on hits.
4. **ICMP (ebpf)**: `./run.sh <iface> 50 --protocol icmp` — scanner ICMPv4 scan
   sees Echo Replies on hits. ICMPv6 scan → **0 replies** (expected; scanner
   type-129 bug, see [§3.4](#34-icmpv6-type-129-bug-critical)).
5. **raw mode edge cases**:
   - `--mode raw --count 3` → scanner dedup collapses 3→1.
   - `--mode raw --delay 3000` → late replies missed (if past scanner's
     `parsing_timeout_millis`).
   - `--mode raw --fake-ip <ip>` UDP → scanner attributes hit to fake IP.
   - `--mode raw --fake-ip <ip>` TCP/ICMP → scanner rejects (forgery defense).
   - `--mode raw --closed` → RST (TCP) / ICMP Port-Unreach (UDP) / silence (ICMP).
6. **both mode**: `--mode both` → even-IPs mirror at line rate; odd-IPs get edge
   cases from the sniffer.
7. **Checksums**: verify with `tcpdump`/`wireshark` — all responses must have
   valid IP + L4 checksums.

---

## 10. RISKS AND KNOWN ISSUES

- **RingBuf sizing**: 16 MiB shared by all pushed probes. In `raw` mode at high
  scan rates, the sniffer must drain fast enough or the ring overflows. Add a
  drop counter. If overflow is a problem, raise the byte size.
- **`ProbeEventHeader` layout drift**: the compile-time `size_of`/`offset_of`
  asserts in `xdp_mirror-common` guard against this. Keep eBPF + userspace in
  sync via the shared crate.
- **ICMP Port Unreachable payload**: must include the original IP+UDP header
  (≥28 bytes per RFC 792). Reconstruct from the `ProbeEvent` fields. The
  scanner ignores this (UDP mode doesn't process ICMP), but keep it RFC-correct.
- **BPF verifier**: every function that dereferences packet bytes must use the
  `ptr_on<T>` pattern (bounds check + pointer derivation in the same scope).
  See [§8.1](#81-ebpf-ptr_at-pattern-bpf-verifier-constraint).
- **`bpf_xdp_adjust_tail`**: only needed for TCP (shrink/expand to Eth+IP+TCP).
  UDP and ICMP mirrors are same-length (no adjust needed).
- **eBPF `info!` macro**: the existing code has a commented-out `info!` call.
  The aya-log eBPF logger may not be available for the pinned toolchain. Don't
  rely on logging in the eBPF program.
- **No test harness**: the dummy has no existing tests. Validation is manual
  (run vs. the scanner). If you add unit tests, focus on checksum helpers and
  `ProbeEvent` (de)serialization round-trips.
- **TODO (deferred, do NOT implement)**: malformed/corrupt responses; ICMP
  Dest-Unreachable/Time-Exceeded + unsolicited flood; UDP payload variants.
  Document these as future TODOs in `.agents/AGENTS.md`.

---

## 11. FINAL INSTRUCTION

### 11.1 Create DummyReceiver project context

Create `/home/lennard/PrivateRepos/Rust/DummyReceiver/.agents/AGENTS.md`
documenting the architecture (as described in T5 above). This is the source of
truth for the DummyReceiver project context.

### 11.2 Update SYN-Rust scanner project context

After all implementation is complete, update the SYN-Rust scanner's project
context file at:

```
/home/lennard/WorkRepos/ase/SYN-Rust/.agents/AGENTS.md
```

Add a new section (e.g., under a "## Testing Tools" heading, or as a new
subsection of the existing structure) documenting:

1. **The DummyReceiver's existence and location**:
   `/home/lennard/PrivateRepos/Rust/DummyReceiver/`

2. **What it does**: an eBPF/XDP program that simulates scan targets for the
   scanner. Supports TCP, UDP, and ICMP. Three modes: `ebpf` (line-rate
   in-kernel mirror), `raw` (userspace sniffer with edge cases), `both`
   (hybrid).

3. **The eBPF→RingBuf→sniffer architecture**: eBPF intercepts scanner probes,
   either mirrors them in-kernel (`XDP_TX`) or pushes a `ProbeEvent` to an aya
   `RingBuf` and `XDP_DROP`s. The userspace sniffer drains the RingBuf and
   sends crafted responses via an `AF_PACKET` TX socket.

4. **The ICMPv6 type-129 scanner bug**: the scanner's ICMPv6 Echo Request uses
   type 129 (the Reply type) instead of type 128 (the Request type) in
   `scanner/src/scan_utils/probes/icmp.rs:25`:
   ```rust
   const ICMPV6_ECHO_REQUEST_TYPECODE: u16 = 129 << 8; // should be 128 << 8
   ```
   A correctly-simulated dummy (responding only to type 128) will produce zero
   ICMPv6 hits, surfacing this bug. Add this to the "Known issues" section
   (§10 of AGENTS.md) with a note that the DummyReceiver correctly simulates
   real-kernel behavior and the fix belongs in the scanner.

5. **The ARP-drop bug fix**: the DummyReceiver's eBPF program had a bug where
   non-IP frames were `XDP_DROP`ped instead of `XDP_PASS`ed, which could break
   ARP resolution. This is now fixed. (Note: this is a DummyReceiver fix, not
   a scanner issue — document it briefly for cross-reference.)

6. **Edge-case testing capabilities**: the raw-socket sniffer supports
   multi-response (`--count`), delayed responses (`--delay`), fake source IP
   (`--fake-ip`), and closed-host simulation (`--closed`). These test the
   scanner's dedup (3s window), `parsing_timeout_millis`, forgery defense
   (TCP cookie / ICMP id gate), and RST/ICMP-error handling respectively.

7. **Deferred TODOs**: malformed/corrupt responses, ICMP error flood, and UDP
   payload variants are documented as future work.

Keep the AGENTS.md update concise — add only what's needed for cross-project
awareness. Do not duplicate the full DummyReceiver architecture there (that
lives in the DummyReceiver's own `.agents/AGENTS.md`); just reference it.

---

## SUMMARY CHECKLIST

- [ ] T1: `xdp_mirror-common/src/lib.rs` — extended `Config`, `Stats`, new `ProbeEventHeader` with size asserts
- [ ] T2: `xdp_mirror-ebpf/src/main.rs` — UDP+ICMP handlers, mode dispatch, `PROBES` RingBuf, ARP fix, checksum helpers, `push_probe_event`
- [ ] T3: `xdp_mirror/src/main.rs` — extended CLI, mode/protocol config, RingBuf take, sniffer spawn, extended stats
- [ ] T4: `xdp_mirror/src/sniffer.rs` — AF_PACKET TX socket, RingBuf drain loop, edge-case logic (multi-response, delay, fake-IP, closed)
- [ ] T5: `.agents/AGENTS.md` — DummyReceiver architecture doc
- [ ] T6: `run.sh` + `README.md` — document new flags
- [ ] `cargo build` with no warnings
- [ ] §11.1: DummyReceiver `.agents/AGENTS.md` created
- [ ] §11.2: SYN-Rust `.agents/AGENTS.md` updated with DummyReceiver reference + ICMPv6 bug note

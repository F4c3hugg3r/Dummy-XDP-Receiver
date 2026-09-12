# DummyReceiver: UDP + ICMP Scan Simulation

**Goal:** Extend the `xdp_mirror` dummy receiver so it can simulate TCP, UDP, and
ICMP scan targets for the SYN-Rust scanner (`~/WorkRepos/ase/SYN-Rust`). The
dummy must be configurable, offer a deterministic mode per protocol, and exercise
edge cases beyond a single correct response.

**Status:** Implementation-ready (all architectural decisions resolved with the
user). This plan is for an implementation-capable agent.

---

## 1. Context & key findings

### How the scanner validates responses (verified in `SYN-Rust/ebpf/src/handlers/`)
- **TCP** (`tcp.rs`): a non-RST TCP packet is a "hit" iff
  `ack_num.wrapping_sub(1) == SipHash24(k0,k1)(our_ip, target_ip, our_port, target_port)`
  (tried with cur then prev keypair). The scanner bakes that cookie into the
  outgoing SYN's **sequence number**, so any compliant SYN-ACK with
  `ack = seq + 1` passes — **no key sharing needed**.
- **UDP** (`udp.rs`): the reply's **destination** port must be in the `SRC_PORTS`
  map (scanner source ports). Userspace adds `udp_port_set.contains(src_port)`
  (reply source port ∈ probed ports). **No cryptographic gate.**
- **ICMP** (`icmp.rs`): an Echo Reply is a hit iff (a) its 16-byte payload at
  offset 8 exactly matches the `ICMP_PAYLOAD` map, AND (b) its id at offset 4
  equals `SipHash24(k0,k1)(our_ip, target_ip) as u16` (cur then prev). The
  scanner bakes both into the outgoing Echo Request, so **echoing id+seq+payload
  back passes — no key sharing needed.** Type pre-filter: reply type must be
  `0` (IPv4) or `129` (IPv6). `seq` (offset 6) and `code` (offset 1) are NOT
  validated.

### The "mirror" trick (works for all 3 protocols)
The dummy intercepts the scanner's outgoing probe (dst = target) on the NIC and
reflects it back as a valid response by swapping MACs/IPs/ports and adjusting the
L4 header, recomputing checksums, then `XDP_TX`:

| Proto | Incoming (scanner→target) | Outgoing (target→scanner) | L4 change |
|-------|---------------------------|---------------------------|-----------|
| TCP   | SYN (`seq=cookie`)        | SYN-ACK (`ack=seq+1`)     | `ack=seq+1`, swap ports |
| UDP   | probe (`src=sport,dst=dport`) | response (`src=dport,dst=sport`) | swap ports, echo payload |
| ICMP  | Echo Req (type 8 v4 / 128 v6) | Echo Rep (type 0 v4 / 129 v6) | change type, copy id/seq/payload |

### Findings the user must keep in mind
1. **Real-kernel behavior is the default.** The dummy simulates a real host, not
   the scanner's quirks. Concretely:
   - ICMPv4: respond only to type 8 (Echo Request) → reply type 0.
   - ICMPv6: respond only to type 128 (Echo Request) → reply type 129.
   - The scanner's `ICMPV6_ECHO_REQUEST_TYPECODE = 129 << 8`
     (`SYN-Rust/scanner/src/scan_utils/probes/icmp.rs:25`) is type 129 = the
     **Reply** type, not Request (128). A real host ignores it. The dummy must
     **also ignore** type-129 v6 requests — so the scanner's ICMPv6 path will
     see zero replies against a correctly-simulated dummy. This is the truthful
     real-world result and surfaces the scanner bug. Do NOT add a "robust"
     respond-to-129 shortcut.
2. **ARP-drop bug (pre-existing).** `xdp_mirror-ebpf/src/main.rs` currently
   `XDP_DROP`s any frame whose ether_type ≠ IP. This drops ARP, which can break
   MAC resolution. Fix: non-IP / non-matching-ether-type frames → `XDP_PASS` so
   ARP/other L2 reaches the kernel.
3. **Cannot forge cryptographically-valid responses from a fake IP** (TCP cookie
   / ICMP id need the rotating SipHash key). Fake-IP TCP/ICMP replies are
   correctly *rejected* by the scanner — a valid forgery-defense test. UDP has
   no crypto gate, so fake-IP UDP replies *are* accepted (integrity test).

---

## 2. Decisions (resolved with user)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Architecture | **Hybrid**: eBPF line-rate mirror + userspace raw-socket injector |
| 2 | Coexistence | **Mutually-exclusive modes** (`ebpf` \| `raw` \| `both`); `both` = eBPF mirrors even-IP, sniffer handles odd-IP |
| 3 | Default behavior | **Real-kernel/host** simulation (see Finding 1) |
| 4 | Deterministic (valm) mode | **Universal even dst IP** for all 3 protocols |
| 5 | Raw-socket edge cases (now) | Multi-response (N per probe), Delayed responses, Fake source IP, Closed-host simulation |
| 5b | Raw-socket edge cases (TODO) | Malformed/corrupt responses; ICMP errors + unsolicited flood; UDP payload variants |
| 6 | `both` mode split | eBPF mirrors even-IP (TX); pushes odd-IP `ProbeEvent` to RingBuf + DROP; sniffer applies edge cases to odd-IPs |
| 7 | Sniffer probe source | **eBPF→RingBuf→sniffer**: eBPF pushes a compact `ProbeEvent` to an aya `RingBuf` and `XDP_DROP`s (kernel never sees the probe → no competing kernel RST/echo-reply); sniffer drains the RingBuf (`AsyncFd`, the scanner's own receiver pattern) and sends responses via an `AF_PACKET` TX socket |

### Additional recommendations baked in (low-stakes; adjust if desired)
- **Protocol filter**: `--protocol any|tcp|udp|icmp`, default `any` (respond to
  all, like a real multi-service host). eBPF and sniffer both dispatch by IP proto.
- **eBPF UDP payload**: echo the incoming probe payload (simplest, realistic-ish).
  Payload variants are TODO #5b (raw-socket later).
- **Stats**: extend `Stats` to per-protocol counters (tcp/udp/icmp rx + tx, keep
  existing `rst_packets` for TCP).
- **Userspace deps**: add `nix` (AF_PACKET socket setup) and `pnet` (packet
  construction) to `xdp_mirror/Cargo.toml`. (Hand-rolling is acceptable if the
  implementer prefers a smaller dep footprint.)
- **Project context**: create `.agents/AGENTS.md` for this repo documenting the
  architecture (per the project guideline that context lives in `.agents/`).

---

## 3. Architecture

### Modes (`--mode ebpf|raw|both`, default `ebpf`)
- **ebpf**: eBPF mirrors filter-hits (valm/percentage) at line rate; non-hits
  `XDP_DROP`. No RingBuf, no sniffer. (Current TCP behavior, extended to 3 protos.)
- **raw**: eBPF pushes EVERY valid probe to the `PROBES` RingBuf and `XDP_DROP`s
  (no in-kernel mirror). Sniffer drains RingBuf and applies edge-case logic to
  all entries.
- **both**: eBPF mirrors even-IP hits (`XDP_TX`); pushes odd-IP non-hits to the
  RingBuf + `XDP_DROP`. Sniffer applies edge-case logic to all RingBuf entries.

> The valm/percentage filter only gates the **ebpf in-kernel mirror**. In `raw`
> and `both`, the sniffer responds to every RingBuf entry (the eBPF already
> decided what reaches the sniffer). This keeps sniffer logic uniform: "respond
> to every event with the configured edge-case behavior."

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

### Module / file layout
```
xdp_mirror-common/src/lib.rs   — Config (extended), Stats (extended), ProbeEventHeader (new)
xdp_mirror-ebpf/src/main.rs    — TCP+UDP+ICMP handlers, mode dispatch, RingBuf push, checksums
xdp_mirror/src/main.rs         — CLI (extended), eBPF load/attach, RingBuf take, spawn sniffer, stats
xdp_mirror/src/sniffer.rs      — (new) AF_PACKET TX + RingBuf drain + edge-case response crafter
xdp_mirror/Cargo.toml          — add nix, pnet
.agents/AGENTS.md              — (new) architecture doc
```

---

## 4. Implementation tasks (ordered)

### T1 — `xdp_mirror-common/src/lib.rs`: shared types
- Extend `Config` (all `u32` for aya `Pod` simplicity):
  `response_probability`, `validation_mode` (0=percentage,1=valm), `ipv6`,
  `protocol` (0=any,1=tcp,2=udp,3=icmp), `mode` (0=ebpf,1=raw,2=both).
- Extend `Stats`: keep `rx, valid_syn, tx, rst_packets`; add `udp_rx, udp_tx,
  icmp_rx, icmp_tx` (all `u64`, `Default`).
- Add `ProbeEventHeader` (`#[repr(C, packed)]`, `zerocopy` `FromBytes` etc. to
  mirror the scanner's `ebpf/src/lib.rs` style, with compile-time size asserts):
  ```
  protocol: u8        // 6=TCP, 17=UDP, 1=ICMPv4, 58=ICMPv6
  version: u8         // 4 | 6
  _pad: [u8;2]
  src_mac: [u8;6]; dst_mac: [u8;6]
  src_ip: [u8;16]     // v4 in first 4 bytes (the scanner convention)
  dst_ip: [u8;16]
  src_port: u16       // TCP/UDP; 0 for ICMP
  dst_port: u16       // TCP/UDP; 0 for ICMP
  tcp_seq: u32        // TCP only (network order)
  icmp_type: u8       // ICMP only (request type)
  icmp_id: [u8;2]     // ICMP only
  icmp_seq: [u8;2]    // ICMP only
  icmp_payload: [u8;16] // ICMP only
  udp_payload_len: u16  // #bytes following this header (UDP only)
  ```
  RingBuf entry layout = `[ProbeEventHeader][udp_payload_len bytes]` (the
  scanner's `UdpResponseHeader`+payload pattern; avoids a fixed payload cap).

### T2 — `xdp_mirror-ebpf/src/main.rs`: protocol handlers + mode logic
- Add header structs: `UdpHdr` (src,dst,len,check — 8 bytes), `IcmpHdr` is read
  byte-wise (type@0, code@1, csum@2, id@4, seq@6, payload@8). Add constants:
  `IPPROTO_UDP=17`, `IPPROTO_ICMP=1`, `IPPROTO_ICMPV6=58`, `ICMPV4_ECHO_REQ=8`,
  `ICMPV6_ECHO_REQ=128`, `ICMPV4_ECHO_REPLY=0`, `ICMPV6_ECHO_REPLY=129`.
- Add `#[map] static PROBES: RingBuf = RingBuf::with_byte_size(16*1024*1024, 0);`
  (mirror the scanner's `EVENTS`).
- **Fix the ARP-drop bug**: non-IP / wrong-ether-type frames → `XDP_PASS`
  (currently `XDP_DROP`).
- Refactor `try_xdp_mirror` into a protocol dispatch that, for the matched
  protocol, calls a shared `decide(mode, config, dst_ip) -> Action` where
  `Action ::= Mirror | PushRing | Drop`. `Mirror` = build+TX in-kernel;
  `PushRing` = write `ProbeEvent` to `PROBES` then `XDP_DROP`; `Drop` =
  `XDP_DROP`. `decide`:
  - `mode==raw` → `PushRing` (all probes).
  - `mode==both` → `(dst_ip even) ? Mirror : PushRing` (valm forced).
  - `mode==ebpf` → `is_hit = validation_mode==valm ? dst_ip_even :
    (bpf_get_prandom_u32()%100 < response_probability)`; `is_hit ? Mirror : Drop`.
  - Apply `protocol` filter first: if `config.protocol != any` and the packet's
    proto doesn't match → `XDP_PASS` (let the kernel/other handler see it; do not
    eat non-targeted protocols).
- **TCP handler** (refactor existing IPv4+IPv6 SYN→SYN-ACK paths): keep the
  in-kernel mirror (ack=seq+1, swap MACs/IPs/ports, recompute IP+TCP csums,
  `bpf_xdp_adjust_tail` to 14+20/40+20, `XDP_TX`). For `PushRing`, fill
  `ProbeEvent{protocol, version, macs, ips, ports, tcp_seq}` and push.
  Keep the existing RST-counting in valm mode (`rst_packets++` on RST seen).
- **UDP handler** (new, v4+v6): valid probe = `proto==UDP`. Mirror: swap
  MACs/IPs/ports, keep payload in place (echo), recompute IP+UDP csums (UDP csum
  includes IPv4/IPv6 pseudo-header — mirror `tcp_v4_csum`/`tcp_v6_csum` with
  proto=17 and the UDP length), `XDP_TX` (same length, no `adjust_tail`).
  `PushRing`: fill `ProbeEvent` with `udp_payload_len` + copy payload bytes
  after the header (use `PROBES.reserve_bytes(hdr_size + payload_len, 0)`).
- **ICMP handler** (new, v4+v6): valid probe = Echo Request (type 8 v4 / 128 v6).
  **Ignore** type 129 v6 (real-kernel behavior; see Finding 1). Mirror: set type
  to 0 (v4) / 129 (v6), keep id/seq/payload, swap MACs/IPs, recompute IP csum
  (v4) + ICMP csum. ICMPv4 csum = Internet checksum over ICMP header+payload
  (NO pseudo-header). ICMPv6 csum = Internet checksum over ICMPv6 header+payload
  + IPv6 pseudo-header (src,dst,length,next-header=58) — mirror `tcp_v6_csum`
  with next-header=58. Same length, no `adjust_tail`. `XDP_TX`.
  `PushRing`: fill `ProbeEvent` with `icmp_type/id/seq/payload`.
- Add checksum helpers: `udp_v4_csum`, `udp_v6_csum`, `icmp_v4_csum`,
  `icmp_v6_csum` (follow the existing `tcp_v*_csum` / `ipv4_csum` patterns).
- Add `push_probe_event(ctx, hdr, udp_payload_ptr, udp_payload_len)`:
  `PROBES.reserve_bytes(size_of::<ProbeEventHeader>()+udp_payload_len, 0)`,
  write header bytes, `copy_nonoverlapping` UDP payload, `submit(0)`. On
  overflow, increment a ring-drop stat (reuse `STATS` slot or add one).

### T3 — `xdp_mirror/src/main.rs`: CLI + mode dispatch + RingBuf + stats
- Extend `Opt` (clap):
  - `--mode <ebpf|raw|both>` (default `ebpf`)
  - `--protocol <any|tcp|udp|icmp>` (default `any`)
  - existing `--iface`, `--percentage`, `--valm`, `--ipv6`
  - sniffer flags: `--count <N>` (default 1), `--delay <ms>` (default 0),
    `--fake-ip <ip>` (optional), `--closed` (bool)
- Load eBPF (existing). Set the extended `CONFIG` map (map `protocol`/`mode` from
  CLI). Attach the XDP program (existing) in ALL modes (the eBPF is always
  loaded; in `raw`/`both` it drives the RingBuf).
- In `raw`/`both`: `take` the `PROBES` RingBuf out of the `Ebpf` object, wrap
  `as_raw_fd()` in `tokio::unix::AsyncFd`, spawn the sniffer task (T4) with the
  edge-case config and the `AF_PACKET` TX socket.
- On Ctrl-C: signal sniffer stop, join, then print extended stats (eBPF
  `PerCpuArray<Stats>` summed + sniffer userspace atomics).

### T4 — `xdp_mirror/src/sniffer.rs`: AF_PACKET TX + RingBuf drain + edge cases
- `AF_PACKET` TX socket: `nix::sys::socket` raw socket, `SOCK_RAW`,
  `ETH_P_ALL`, `bind` to `iface` index, promiscuous off (we only TX). Build a
  `sockaddr_ll` from the iface index (mirror the scanner's
  `emitting/sender.rs::initialize_sock_addr`). `sendto` full Ethernet frames.
- Drain loop (`AsyncFd` readable): `ring_buf.next()` → parse
  `ProbeEventHeader` + trailing UDP payload. For each event apply edge cases:
  - **closed**: TCP → craft+send RST (`seq=tcp_seq+1`, `ack=0`, flags=RST,
    swap ports); UDP → craft+send ICMP Port Unreachable (type 3 code 3, src=
    target, dst=scanner, payload = original IPv4+UDP header ≥28 bytes —
    reconstruct from the event's ips/ports/a representative UDP header);
    ICMP → send nothing.
  - **normal** (not closed): for `i in 0..count`: `tokio::time::sleep(delay)`;
    craft+send the protocol response. TCP → SYN-ACK (`ack=tcp_seq+1`, random
    seq, swap ports). UDP → swap ports, echo payload. ICMP → Echo Reply (type
    0 v4 / 129 v6, copy id/seq/payload). Apply `fake_ip` (if set): replace the
    response's src IP with `fake_ip` (note: TCP/ICMP fake-IP replies will be
    rejected by the scanner's cookie/id gate — that's the intended test; UDP
    fake-IP replies are accepted).
  - Response frames: `dst_mac = event.src_mac`, `src_mac = event.dst_mac`,
    recompute all checksums. Use `pnet` builders or hand-roll.
- Userspace stats (atomics): `sniffer_sent`, `sniffer_closed`, `sniffer_fake`,
  `sniffer_dropped_ring`. Print on exit.

### T5 — `.agents/AGENTS.md`: document the architecture
- Per the project guideline (context lives in `.agents/`): create
  `.agents/AGENTS.md` describing the dummy's purpose, the 3 modes, the
  eBPF→RingBuf→sniffer flow, the per-protocol mirror logic, the real-kernel
  behavior rule (incl. the ICMPv6 type-128/129 note), the edge-case flags, and
  the known scanner quirk (ICMPv6 type-129 request bug). Keep it the source of
  truth; update if the structure changes.

### T6 — `run.sh` + README
- Update `run.sh` to pass through the new flags (it already forwards `$@`).
- Update `README.md` with the new modes/flags and a usage example per protocol.

---

## 5. Edge cases covered (validation matrix)

| Capability | Mode | Tests in scanner |
|------------|------|------------------|
| TCP/UDP/ICMP correct mirror | ebpf | Happy-path hit counting at line rate |
| valm even-IP deterministic | ebpf/both | Predictable "which IPs are up" assertions |
| Percentage response rate | ebpf | Throughput + partial-response behavior |
| Multi-response (N per probe) | raw/both | Dedup (TCP/UDP key=ip+port, ICMP key=ip; 3s window) collapses N→1 |
| Delayed responses | raw/both | `parsing_timeout_millis` — late replies past timeout missed |
| Fake source IP (UDP) | raw/both | Result integrity: scanner accepts fake-IP UDP hit (no src-IP validation) |
| Fake source IP (TCP/ICMP) | raw/both | Forgery defense: scanner rejects via cookie/id gate |
| Closed TCP (RST) | raw/both | Scanner ignores RSTs (eBPF passes them; no hit) |
| Closed UDP (ICMP Port-Unreach) | raw/both | Scanner (UDP mode) ignores ICMP; no hit; robustness |
| Closed ICMP (silence) | raw | No reply; scanner records host down |
| ICMPv6 type-129 requests | all | Real-kernel ignore → scanner sees 0 v6 replies (surfaces scanner bug) |
| ARP/other L2 frames | all | `XDP_PASS` reaches kernel (fixes ARP resolution) |

---

## 6. Validation
1. `cargo build` (both `xdp_mirror` and `xdp_mirror-ebpf` via the cargo-in-cargo
   build) with no warnings. The eBPF uses the aya-pinned toolchain via
   `aya_build` (already wired in `xdp_mirror/build.rs`).
2. **TCP regression**: `./run.sh <iface> 50` (ebpf mode, percentage) — scanner
   TCP scan sees ~50% hits. `--valm` — only even-IP targets hit. Confirm stats.
3. **UDP (ebpf)**: scanner UDP scan → echo replies on valm/percentage hits.
4. **ICMP (ebpf)**: scanner ICMPv4 scan → Echo Replies on hits. ICMPv6 scan →
   **0 replies** (expected; scanner type-129 bug) unless the scanner is fixed to
   send type 128.
5. **raw mode edge cases**: `--mode raw --count 3` → scanner dedup collapses 3→1.
   `--mode raw --delay 3000` (vs scanner `parsing_timeout`) → late replies
   missed. `--mode raw --fake-ip <ip>` UDP → scanner attributes hit to fake IP;
   TCP/ICMP → rejected. `--mode raw --closed` → RST/ICMP-unreach/silence.
6. **both mode**: even-IPs mirror at line rate; odd-IPs get edge cases.
7. Spot-check checksums with `tcpdump`/`wireshark` — all mirrored/injected
   responses must have valid IP+L4 checksums (the scanner doesn't validate L4
   csums, but a real kernel would drop invalid ones).

---

## 7. Risks / open questions / TODOs

- **RingBuf sizing**: 16 MiB shared by all pushed probes. In `raw` mode at high
  scan rates the sniffer must drain fast enough or the ring overflows (drop
  stat). If overflow is a problem, raise the byte size or add backpressure.
- **`ProbeEventHeader` layout drift**: add compile-time `size_of`/`offset_of`
  asserts in `xdp_mirror-common` (mirror the scanner's `ebpf/src/lib.rs`) and
  keep eBPF + userspace in sync via the shared crate.
- **ICMP Port Unreachable payload**: must include the original IP+UDP header
  (≥28 bytes per RFC). Reconstruct from the `ProbeEvent` (ips, ports) + a
  representative UDP header; the scanner ignores this anyway (UDP mode doesn't
  process ICMP), so exact byte fidelity is low-risk but keep it RFC-correct.
- **TODO (deferred, documented for later)**: malformed/corrupt responses (wrong
  port/id/payload/type, truncated) — tests eBPF/userspace filtering; ICMP
  Dest-Unreachable/Time-Exceeded + unsolicited flood — tests off-path noise
  resistance; UDP payload variants (empty/oversized/mismatched length) — tests
  payload forwarding + the eBPF `saturating_sub` bounds path.
- **Scanner-side quirk**: the ICMPv6 type-129 request bug is in the *scanner*,
  not the dummy. The dummy behaving correctly will make ICMPv6 show 0 hits.
  Confirm with the scanner maintainer whether to fix the scanner (send type 128)
  — out of scope for this dummy plan, but flag it.
- **No tests added**: the dummy has no existing test harness. Validation is
  manual (run vs. the scanner). If the implementer adds unit tests, focus on
  checksum helpers and `ProbeEvent` (de)serialization round-trips.

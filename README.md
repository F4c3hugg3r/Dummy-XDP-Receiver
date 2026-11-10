# xdp_mirror

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Modes & Protocols

DummyReceiver has three mutually-exclusive modes, selected via `--mode`:

- `ebpf` (default): eBPF mirrors filter-hits (valm/percentage) at line rate; non-hits are dropped in-kernel — no userspace sniffer.
- `raw`: eBPF pushes every valid probe to a RingBuf and drops it; a userspace sniffer drains the RingBuf and crafts responses (enables edge cases).
- `both`: eBPF mirrors even-IP hits at line rate; odd-IP probes go to the sniffer.

Select the protocol to respond to with `--protocol`:

- `--protocol any` (default) — respond to TCP, UDP, and ICMP
- `--protocol tcp` — TCP only
- `--protocol udp` — UDP only
- `--protocol icmp` — ICMP only

### Response mode flags

- `--valm` — deterministic mode: respond only to even-destination-IP targets (all protocols). When omitted, `--percentage N` controls the random response probability.
- `--ipv6` — operate in IPv6 mode (parse/emit IPv6 headers instead of IPv4).
- `--percentage N` — response probability 0-100 (default 50). Ignored in `--valm` mode.

### Edge-case flags (raw/both modes)

The userspace sniffer supports edge-case behavior:

- `--count N` — send N responses per probe (1..=10000, default 1)
- `--delay MS` — delay in ms (0..=60000): copy i (0-based) is sent at
  `(i+1)*MS` after the probe was drained (the first copy is delayed too).
  Delayed copies are queued (non-blocking): the sniffer keeps draining the
  ring while copies wait. With `--delay 0` all copies go out immediately.
- `--fake-ip IP` — use a fake source IP (tests scanner forgery defense)
- `--closed` — simulate a closed port/host (TCP RST / UDP ICMP Port-Unreach / ICMP silence)

### Hostile-mode flags (raw mode)

Each flag attacks one scanner validation gate. All are raw-sniffer features;
the eBPF path is unaffected. They are orthogonal and compose.

| Flag | Semantics | Attacked gate | Rig test |
|------|-----------|---------------|----------|
| `--tcp-flags VAL` | TCP flags byte in SYN-ACK replies (hex `0x02` or decimal, default `0x12`) | response flag validation | `edge_bad_flags` |
| `--bad-csum` | corrupts the transport checksum of TCP/UDP/ICMP replies (IP header stays valid) | transport checksum validation | `edge_bad_csum` |
| `--ack-delta N` | SYN-ACK ack = probe seq + N (default 1 = correct cookie) | cookie/ack validation | `edge_wrong_ack` |
| `--port-override PORT` | reply SOURCE port = PORT instead of the probed port | port identity check | `edge_port_override` |
| `--fake-ip-list a,b,c` | rotating forged source pool (round-robin per probe — all copies/retransmits of a probe use the same source; counts into `fake_sent`); supersedes `--fake-ip` (conflict error if both given); pool entries of a mismatching IP version are skipped — a v6 probe with a v4-only pool gets the real source | source-IP validation (TCP cookie binding) | `edge_reflection` |
| `--fragment` | split IPv4 replies into two IP fragments after the first 8 transport bytes (MF=1 / frag_offset=1, per-fragment IP checksum); IPv6 replies stay unfragmented | fragmented-response handling | `edge_fragmented` |

Known limitations (documented, specs are IPv4): a forged pool without any
entry matching the probe's IP version falls back to the real source IP;
`--fragment` only applies to IPv4.

### Filtered raw mode, retransmits, loss and jitter (raw/both modes)

| Flag | Semantics |
|------|-----------|
| `--raw-filter` | raw mode only: the eBPF applies the same hit/no-rsp/icmp-error decision as `ebpf` mode and pushes only hits to the sniffer; misses are dropped in-kernel (UDP misses get ICMP errors if `--icmp-error` is set), suppressed hits count into `no_rsp_count`. Requires `--valm`; rejected with `--closed` and `--mode both`; a no-op (warning) in `--mode ebpf`. |
| `--rto-profile linux\|bsd\|windows\|internet` | realistic SYN-ACK retransmits, **TCP only** (UDP/ICMP probes get a single immediate answer under `--rto-profile`; use `--count`, which works for every protocol, for multiple UDP/ICMP answers). All copies of a probe are identical like a real retransmit (same ISN, same — possibly forged — source, chosen once per probe). The first answer goes out immediately and is never lost; retransmits at cumulative offsets `linux` 1/3/7/15/31 s, `bsd` 3/9/21 s, `windows` 3/9 s. `internet` picks per target IP deterministically (independent of `--seed`): 31 % linux (6 packets), 42 % bsd (4), 7 % windows (3), 4 % linux up to 15 s (5), 16 % single answer. Bucket = `splitmix64(key) % 100` with key = IPv4 as big-endian u32, IPv6 as `hi64 ^ lo64` of the big-endian u128; buckets `0..31` linux, `31..73` bsd, `73..80` windows, `80..84` linux-15s, `84..100` single. Rejected with `--count > 1` or `--delay > 0`. |
| `--loss-perc P` | 0..=100 (float, e.g. `3.3`): each retransmit / delayed copy is dropped with probability P (never the first answer of `--rto-profile`; `--delay 0` copies are never lost). Counted in `lost`. |
| `--jitter-ms J` | 0..=60000: uniform extra delay in `[0, J]` ms per retransmit / delayed copy; copies may reorder. |
| `--max-pending N` | capacity of the delayed-copy queue in jobs (>= 1, default 2000000). A full queue drops the job and counts it in `pending_dropped`. |
| `--seed S` | u64 seed for loss/jitter (default: random). The used seed is printed to stderr at startup and reported as `sniffer.seed`. Every decision is a pure function of the seed and the probe/copy (`splitmix64` chained over seed, target-IP key, protocol+ports, TCP seq / ICMP id+seq, copy index), so a given seed yields the same losses and jitter per probe regardless of the ring read order or interleaving with other probes. |

The rto/loss/jitter/queue/seed flags only affect the userspace sniffer:
they are ignored (with a warning) in `--mode ebpf` and with `--closed`.

On stop (Ctrl-C) pending delayed copies are discarded and counted in
`discarded_on_stop`.

Queue memory: each queued copy is a 24 B heap entry; all copies of a probe
share one 136 B probe record (header, ISN, source, answered flag, `Arc`
counters; ~144 B with malloc overhead) plus the UDP payload, stored once per
probe. Worst case (one queued copy per probe, e.g. `--count 1 --delay D`) is
therefore ~170 B per job, i.e. the default `--max-pending 2000000` can take
~340 MB (plus UDP payloads); with `--rto-profile linux` (5 queued
retransmits per probe) it is ~53 B per job (~106 MB). The heap does not shrink after a load burst: memory stays at the
peak until the process exits.

Sniffer stats (`--json-stats` final object, key `sniffer`):

- `sent` — all successfully sent responses (every copy/retransmit)
- `answered_probes` — probes for which at least one response copy was
  successfully sent; counted once per probe, on the first copy that
  actually went out, whichever copy that is (with `--count/--delay` copy 0
  may be lost or dropped while a later copy still answers the probe)
- `pending_dropped` — copies dropped because the queue was full
- `lost` — copies dropped by `--loss-perc`
- `send_failed` — copies whose crafting or `sendto` failed (incl.
  `--closed` RST/ICMP-unreach replies)
- `discarded_on_stop` — queued copies discarded at stop (not yet due)
- `seed` — the seed in use

`answered_probes`, `pending_dropped`, `send_failed` and `discarded_on_stop`
are also written to every 1 s line of the `--stats-file` timeline (0 when no
sniffer runs). With `--raw-filter`, `answered_probes <= even_rx -
no_rsp_count` always holds (TCP/UDP/ICMP, v4/v6); equality holds when no
probe ended up without any sent copy, i.e. `ring_dropped == 0`,
`sniffer.dropped_ring == 0`, `send_failed == 0`, and either
- `--rto-profile` or `--delay 0` (the first answer is sent inline and is
  never lost/queued), or
- `--delay > 0` with `lost == 0`, `pending_dropped == 0` and
  `discarded_on_stop == 0` (otherwise a probe may lose all its copies).

Ring capacity: TCP/ICMP ring entries reserve only the 80-byte probe header
(UDP entries keep the fixed 1024 B for header + payload), so the 16 MiB
`PROBES` ring holds ~190k TCP/ICMP probes instead of 16k.

### ICMP error simulation (ebpf/both modes)

- `--icmp-error <type>` — send ICMP errors for UDP misses instead of dropping
  silently. Types: `port-unreach`, `admin-prohibited`, `host-unreach`,
  `net-unreach`, `time-exceeded`, `all` (round-robin). Default: `none`.
- `--no-rsp-perc N` — percentage of hits that get no response (silence) instead
  of a UDP reply. In valm mode, the split is deterministic per-IP. Default: 0.

See `docs/ICMP-ERROR-SIMULATION.md` for detailed usage and the full decision
matrix.

### Usage examples

TCP:

```shell
./run.sh eth0 50
./run.sh eth0 50 --valm
```

UDP:

```shell
./run.sh eth0 50 --protocol udp
```

ICMP:

```shell
./run.sh eth0 50 --protocol icmp
```

Raw mode edge cases:

```shell
./run.sh eth0 50 --mode raw --count 3
./run.sh eth0 50 --mode raw --closed
./run.sh eth0 50 --mode raw --tcp-flags 0x02
./run.sh eth0 50 --mode raw --bad-csum
./run.sh eth0 50 --mode raw --ack-delta 2
./run.sh eth0 50 --mode raw --port-override 9999
./run.sh eth0 50 --mode raw --fake-ip-list 10.99.99.1,10.99.99.2,10.99.99.3
./run.sh eth0 50 --mode raw --fragment
./run.sh eth0 50 --valm --mode raw --raw-filter --no-rsp-perc 20
./run.sh eth0 50 --mode raw --count 3 --delay 2000 --jitter-ms 500 --loss-perc 3.3 --seed 42
./run.sh eth0 50 --valm --mode raw --raw-filter --rto-profile internet --loss-perc 2
```

Both mode:

```shell
./run.sh eth0 50 --mode both
```

ICMP error simulation:

```shell
./run.sh eth0 50 --valm --icmp-error port-unreach
./run.sh eth0 50 --valm --icmp-error all
./run.sh eth0 50 --valm --no-rsp-perc 50
./run.sh eth0 50 --valm --icmp-error all --no-rsp-perc 50
./run.sh eth0 50 --mode both --icmp-error port-unreach
./run.sh eth0 50 --ipv6 --valm --icmp-error port-unreach
```

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package xdp_mirror --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/xdp_mirror` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, xdp_mirror is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2

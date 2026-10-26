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

- `--count N` — send N responses per probe (default 1)
- `--delay MS` — delay MS milliseconds before responding
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
| `--fake-ip-list a,b,c` | rotating forged source pool (round-robin per reply, counts into `fake_sent`); supersedes `--fake-ip` (conflict error if both given); pool entries of a mismatching IP version are skipped — a v6 probe with a v4-only pool gets the real source | source-IP validation (TCP cookie binding) | `edge_reflection` |
| `--fragment` | split IPv4 replies into two IP fragments after the first 8 transport bytes (MF=1 / frag_offset=1, per-fragment IP checksum); IPv6 replies stay unfragmented | fragmented-response handling | `edge_fragmented` |

Known limitations (documented, specs are IPv4): a forged pool without any
entry matching the probe's IP version falls back to the real source IP;
`--fragment` only applies to IPv4.

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

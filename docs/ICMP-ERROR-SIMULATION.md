# ICMP Error Simulation Guide

### 1. Overview

DummyReceiver can generate ICMP error responses for UDP probes at line rate via eBPF, replacing the binary "mirror or drop" decision with a three-way decision: UDP reply, no response (silence), or ICMP error.

### 2. The Three-Way Decision

- **UDP reply (Mirror)**: eBPF mirrors the UDP probe back (swap src/dst, XDP_TX)
- **No response (NoResponse)**: XDP_DROP — silence. Controlled by `--no-rsp-perc`
- **ICMP error (IcmpError)**: eBPF crafts an ICMP error packet and transmits (XDP_TX). Controlled by `--icmp-error`

### 3. ICMP Error Types

| Name | IPv4 type/code | IPv6 type/code | Meaning |
|------|---------------|----------------|---------|
| port-unreach | 3/3 | 1/4 | No service bound (closed) |
| admin-prohibited | 3/13 | 1/1 | Firewall rejected (filtered) |
| host-unreach | 3/1 | 1/3 | Router can't reach host |
| net-unreach | 3/0 | 1/0 | Router can't reach network |
| time-exceeded | 11/0 | 3/0 | TTL expired in transit |

Use `--icmp-error all` for round-robin among all 5 types.

### 4. Decision Logic

The `decide()` logic:

- In `ebpf` mode: hits (valm even-IP or percentage) get Mirror or NoResponse (based on `--no-rsp-perc`); misses get IcmpError (if `--icmp-error` is set for UDP) or Drop.
- In `both` mode: even-IP hits get Mirror or NoResponse; odd-IP misses get IcmpError (if UDP + `--icmp-error`) or PushRing (sniffer).
- In `raw` mode: all probes go to PushRing (sniffer). `--icmp-error` has no effect; use sniffer's `--closed` flag instead.

### 5. Deterministic Split (valm mode)

With `--valm`:

- Even IP → hit: `--no-rsp-perc N` deterministically splits hits. IPv4: `u32::from_be(dst_addr) % 100 < N` → NoResponse. IPv6: `dst_addr[14] % 100 < N` → NoResponse (byte 14, not 15, to avoid correlation with the even/odd check on byte 15).
- Odd IP → miss: ICMP error (if `--icmp-error` set for UDP) or Drop.

### 6. Mode Interaction Table

| Mode | Even IP (hit) | Odd IP (miss) |
|------|---------------|----------------|
| `ebpf` + `--icmp-error` | Mirror or NoResponse | IcmpError (eBPF crafts) |
| `ebpf` without `--icmp-error` | Mirror or NoResponse | Drop (current) |
| `both` + `--icmp-error` | Mirror or NoResponse | IcmpError (eBPF crafts, line rate) |
| `both` without `--icmp-error` | Mirror or NoResponse | PushRing (sniffer, current) |
| `raw` | PushRing (sniffer) | PushRing (sniffer; `--closed` for ICMP) |

### 7. Scope

- `--icmp-error` applies to UDP only. TCP misses → Drop (RST is TCP's closed signal). ICMP misses → Drop (silence).
- `--no-rsp-perc` applies to all protocols (controls hit/no-response split). Default 0 (all hits get response, current behavior).

### 8. Usage Examples

```shell
# ICMP Port Unreachable on odd IPs (valm mode)
./run.sh eth0 50 --valm --icmp-error port-unreach

# Round-robin all 5 ICMP error types on odd IPs
./run.sh eth0 50 --valm --icmp-error all

# 50% of hits get silence, rest get UDP reply
./run.sh eth0 50 --valm --no-rsp-perc 50

# Combined: even IPs split 50/50, odd IPs get round-robin ICMP errors
./run.sh eth0 50 --valm --icmp-error all --no-rsp-perc 50

# both mode: even IPs mirrored, odd IPs get ICMP Port Unreachable from eBPF
./run.sh eth0 50 --mode both --icmp-error port-unreach

# IPv6: ICMPv6 type 1 code 4 on odd IPs
./run.sh eth0 50 --ipv6 --valm --icmp-error port-unreach

# Regression: no new flags, identical to current behavior
./run.sh eth0 50
```

### 9. Packet Structure

#### IPv4 ICMP error (70 bytes)
```
[Eth: 14] dst=scanner_mac, src=target_mac, 0x0800
[IP4: 20] src=target_ip, dst=scanner_ip, proto=1, tot_len=56
[ICMP: 8] type, code, checksum, unused=0
[Orig IP4: 20] original IP header (from probe)
[Orig UDP: 8]  original UDP header (from probe)
```

#### IPv6 ICMPv6 error (110 bytes)
```
[Eth: 14] dst=scanner_mac, src=target_mac, 0x86DD
[IP6: 40] src=target_ip, dst=scanner_ip, nh=58, plen=56
[ICMP6: 8] type, code, checksum, unused=0
[Orig IP6: 40] original IPv6 header (from probe)
[Orig UDP: 8]  original UDP header (from probe)
```

### 10. Known Limitations

- All ICMP errors use the target IP as the source (not a router IP). Real router-originated errors (Host/Net Unreachable, Time Exceeded) would come from a router IP. This is a known limitation; the scanner ignores ICMP error responses anyway.
- `--icmp-error` in `raw` mode has no effect. Use the sniffer's `--closed` flag for ICMP in raw mode.
- The ICMP error payload includes the original IP header + UDP header (28 bytes for IPv4 with IHL=5, 48 bytes for IPv6). IP options (IHL > 5) are not included; the eBPF program drops probes with IHL != 5.
- The round-robin counter is per-CPU, so different CPUs alternate independently. This is acceptable for round-robin distribution.

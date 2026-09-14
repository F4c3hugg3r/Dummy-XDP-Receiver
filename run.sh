#!/bin/bash
# Usage: ./run.sh [interface] [percentage]
# Example: ./run.sh eth0 80
#
# New flags (passed via EXTRA_ARGS):
#   --mode ebpf|raw|both       (default: ebpf)
#   --protocol any|tcp|udp|icmp (default: any)
#   --count N                   (sniffer: responses per probe, default 1)
#   --delay MS                  (sniffer: delay before responding, ms)
#   --fake-ip IP                (sniffer: fake source IP)
#   --closed                    (sniffer: simulate closed port/host)
#   --icmp-error <type>         (ebpf/both: ICMP error type for UDP misses; default: none)
#   --no-rsp-perc N             (0-100: % of hits that get no response; default: 0)

IFACE=${1:-eno1}
shift 2>/dev/null || true

PERCENTAGE=50
if [[ "$1" =~ ^[0-9]+$ ]]; then
    PERCENTAGE=$1
    shift
fi

echo "Running xdp_mirror on interface $IFACE with response probability $PERCENTAGE% and extra args: $*"
cargo build --release 2>/dev/null || { echo "Build failed. Run 'cargo build' to see errors."; exit 1; }
sudo -E RUST_LOG=warn target/release/xdp_mirror --iface "$IFACE" --percentage "$PERCENTAGE" "$@"

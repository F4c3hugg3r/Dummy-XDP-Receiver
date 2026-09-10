#!/bin/bash
# Usage: ./run.sh [interface] [percentage]
# Example: ./run.sh eth0 80

IFACE=${1:-eno1}
shift 2>/dev/null || true

PERCENTAGE=50
if [[ "$1" =~ ^[0-9]+$ ]]; then
    PERCENTAGE=$1
    shift
fi

EXTRA_ARGS="$@"

echo "Running xdp_mirror on interface $IFACE with response probability $PERCENTAGE% and extra args: $EXTRA_ARGS"
RUST_LOG=info cargo run --release -- --iface "$IFACE" --percentage "$PERCENTAGE" $EXTRA_ARGS

#!/bin/bash
# Usage: ./run.sh [interface] [percentage]
# Example: ./run.sh eth0 80

IFACE=${1:-eno1}
PERCENTAGE=${2:-50}

echo "Running xdp_mirror on interface $IFACE with response probability $PERCENTAGE%"
RUST_LOG=info cargo run --release -- --iface "$IFACE" --percentage "$PERCENTAGE"

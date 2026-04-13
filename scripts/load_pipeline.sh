#!/bin/bash
set -e

IFACE="ens33"
PIN_DIR="/sys/fs/bpf/ebpf-json-pipeline"

# 1. Ensure BPF filesystem is mounted
if ! mount | grep -q /sys/fs/bpf; then
    sudo mount -t bpf bpf /sys/fs/bpf
fi

# 2. Cleanup old state
echo "[*] Cleaning up old pins..."
sudo rm -rf $PIN_DIR
sudo mkdir -p $PIN_DIR

echo "[+] Loading and Pinning BPF Programs (Architecture: Unified Maps)..."

# 3. Load XDP Program and establish the shared maps
# This pins ALL maps found in xdp_edge.bpf.o to $PIN_DIR
sudo bpftool prog load kernel/layer1_xdp/xdp_edge.bpf.o $PIN_DIR/obj_xdp \
    type xdp pinmaps $PIN_DIR

# 4. Load TC Program, explicitly REUSING the pinned maps from the XDP object
# IMPORTANT: We do NOT use 'pinmaps' here because the maps are already pinned. 
# We only link the program to the existing map pins.
sudo bpftool prog load kernel/layer1_tc/tc_stateful.bpf.o $PIN_DIR/obj_tc \
    type classifier \
    map name log_ringbuf pinned $PIN_DIR/log_ringbuf \
    map name port_proto_filter pinned $PIN_DIR/port_proto_filter \
    map name ip_allowlist pinned $PIN_DIR/ip_allowlist \
    map name rate_limit_map pinned $PIN_DIR/rate_limit_map \
    map name drop_counters pinned $PIN_DIR/drop_counters

# 5. Attach the pinned programs to the network interface
echo "[+] Attaching programs to $IFACE..."

# Attach XDP
sudo ip link set dev $IFACE xdp pinned $PIN_DIR/obj_xdp

# Attach TC
sudo tc qdisc add dev $IFACE clsact 2>/dev/null || true
sudo tc filter add dev $IFACE ingress bpf pinned $PIN_DIR/obj_tc da

echo "[+] Pipeline successfully loaded and unified."
echo "[+] All shared maps are pinned in $PIN_DIR"

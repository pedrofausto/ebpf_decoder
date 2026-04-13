#!/bin/bash

# Configuration
IFACE=${1:-ens33}
PIN_PATH="/sys/fs/bpf/ebpf-json-pipeline"

echo "[*] Unloading eBPF JSON Pipeline from interface: $IFACE"

# 1. Detach XDP
echo "[*] Detaching XDP programs..."
ip link set dev $IFACE xdp off 2>/dev/null || echo "[-] No XDP program found on $IFACE"

# 2. Detach TC
echo "[*] Removing TC ingress filter and qdisc..."
tc filter del dev $IFACE ingress 2>/dev/null
tc qdisc del dev $IFACE clsact 2>/dev/null

# 3. Clean up pinned maps
echo "[*] Cleaning up pinned BPF objects in $PIN_PATH..."
rm -rf $PIN_PATH/*
rmdir $PIN_PATH 2>/dev/null

echo "[+] Pipeline successfully unloaded."

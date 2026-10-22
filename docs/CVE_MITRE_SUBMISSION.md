# MITRE CVE Submission — IEC 62351-6 CIL-DoS
## Protocol-Level Vulnerability in IEC 62351-6 Cryptographic Authentication

> **Submission Target:** MITRE CVE Program (https://cveform.mitre.org/)
> **Precedent:** CVE-2017-13077 (KRACK — WPA2 protocol-level vulnerability)
> **Status:** DRAFT — Do not submit until Pi 5 hardware evidence is complete

---

## CVE Request Form Fields

### 1. Request Type
```
Report a new vulnerability / request a CVE ID
```

### 2. Vulnerability Type
```
Protocol Design Flaw — Computational Denial of Service
```

### 3. Vendor of the Product
```
International Electrotechnical Commission (IEC)
Technical Committee 57 (TC 57) — Power Systems Management
Working Group 15 (WG 15) — Data and Communication Security
```

### 4. Affected Product / Standard
```
IEC 62351-6:2020 — Power systems management and associated information
exchange — Data and communications security — Part 6: Security for
IEC 61850 profiles

Specifically: Sections defining cryptographic authentication profiles
for GOOSE (Generic Object Oriented Substation Event) messages, including
RSA-2048 digital signatures, ECDSA-P256 digital signatures, and
HMAC-SHA-256 message authentication codes applied to IEC 61850 GOOSE
multicast frames (EtherType 0x88B8).
```

### 5. Version(s) Affected
```
IEC 62351-6:2020 (current edition)
IEC 62351-6:2007 (previous edition)
All implementations of IEC 62351-6 cryptographic authentication on
IEC 61850 GOOSE messages are affected.

The vulnerability is inherent to the standard's design — any compliant
implementation on resource-constrained IED hardware is vulnerable.
```

### 6. Vulnerability Description
```
IEC 62351-6 mandates cryptographic authentication (digital signatures
or MACs) on IEC 61850 GOOSE protection messages in electrical
substations. GOOSE carries safety-critical circuit breaker trip commands
with a hard 3.0 ms real-time delivery deadline (IEC 61850 Performance
Class P2/P3).

The standard requires receiving Intelligent Electronic Devices (IEDs)
to perform full cryptographic verification on every incoming GOOSE
frame before accepting or rejecting it. This creates a Crypto-Induced
Latency Denial of Service (CIL-DoS) vulnerability:

An attacker with Layer-2 access to the substation process bus can flood
structurally valid but cryptographically INVALID GOOSE frames at rates
of 10,000–100,000 packets per second. Each frame forces the IED
processor to execute computationally expensive signature verification
(modular exponentiation for RSA, elliptic curve point multiplication
for ECDSA) before it can determine the frame is invalid and discard it.

Under flood conditions, the IED's verification queue saturates
(server utilization ρ >> 1), causing legitimate protection trip
commands to queue behind thousands of attack frames. The 3.0 ms
safety deadline is violated 100% of the time, with measured queuing
delays exceeding 2,388 ms.

The attacker requires:
  - Layer-2 (Ethernet) access to the substation process bus
  - Knowledge of GOOSE frame structure (publicly documented)
  - NO cryptographic keys (invalid signatures are the weapon)

Physical consequences of delayed trip commands include:
  - Generator rotor angle instability past Critical Clearing Time
  - Transformer through-fault thermal damage (6.25× I²t surge)
  - Breaker-failure protection (ANSI 50BF) blinding
  - Potential cascading blackout
```

### 7. Attack Vector
```
CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H

Attack Vector (AV): Adjacent Network — requires Layer-2 access to the
  substation process bus (not remotely exploitable over IP)
Attack Complexity (AC): Low — attack requires only flooding invalid
  frames; no race conditions, no special preparation
Privileges Required (PR): None — no authentication or keys needed
User Interaction (UI): None — fully automated attack
Scope (S): Changed — the cyber attack on the communication layer
  affects the physical power grid safety function
Confidentiality (C): None
Integrity (I): None — no data is modified
Availability (A): High — safety-critical protection function is
  completely denied

Base Score: 7.4 (High)

Note: The physical safety impact (potential grid damage, cascading
blackout) is not captured by CVSS 3.1 but would be classified as
Safety: Catastrophic under IEC 62443 consequence assessment.
```

### 8. Discovery Details
```
Discoverers:
  - Dr. Sapna Vikram Mewundi (PES University, Bengaluru, India)
  - Prajwal Chowdary M. (PES University, Bengaluru, India)
  - Prof. Prasad B. Honnavalli (PES University, Bengaluru, India)

Discovery Date: August 2026
Disclosure Timeline:
  - August 2026: Vulnerability discovered during research
  - October 7, 2026: Academic manuscript submitted to IEEE TSG
  - [PENDING]: IEC TC 57 WG 15 notified
  - [PENDING]: CVE ID requested from MITRE
  - [PENDING]: Coordinated public disclosure at Black Hat Asia 2027
```

### 9. Proof of Concept / Evidence
```
All evidence is publicly reproducible:

1. EMBEDDED HARDWARE BENCHMARKS (ESP32 Xtensa LX6 @ 240 MHz):
   - ECDSA-P256 verification: 310,475.9 µs (103× past 3 ms deadline)
   - RSA-2048 verification: 980.1 µs (saturates at ~1,000 pps)
   - HMAC-SHA-256 verification: 167.3 µs (sub-millisecond)
   Dataset: results/esp32_crypto_benchmark.csv

2. ARM CORTEX-A76 BENCHMARKS (Raspberry Pi 5, BCM2712 @ 2.4 GHz):
   - HMAC-SHA-256 verification: 2.50 µs (well under deadline)
   - ECDSA-P256 verification: 192.26 µs (saturation at ~5,200 pps)
   - RSA-2048 verification: 101.15 µs (saturation at ~9,886 pps)
   - Ed25519 verification: 145.54 µs (saturation at ~6,870 pps)
   - Key finding: Pi 5 Cortex-A76 is 1,600× faster than ESP32 for
     ECDSA — yet a 10K pps flood STILL saturates the queue (ρ > 1)
   Dataset: results/pi5_crypto_benchmark.csv

3. DOCKER TESTBED REPRODUCTION (single command):
   Repository: https://github.com/sapnadfir-blip/gridpulse
   Command: docker compose run --rm subscriber --mode fifo --attack-rate 100000
   Result: Trip latency > 2,388 ms, 100% deadline violation

4. QUEUEING-THEORETIC PROOF:
   M/M/1 model: ρ = λ_attack / μ_verify
   At 100K pps with RSA-2048 (μ = 1/34µs ≈ 29,412 pps):
   ρ = 100,000 / 29,412 = 3.4 >> 1 (queue diverges to infinity)

5. 49 CONTROLLED EXPERIMENTS validating attack and defense across
   multiple configurations, algorithms, and attack rates.
   Datasets: results/*.csv

6. DEFENSE (PQAC) achieving 3,140× latency reduction:
   Demonstrates the vulnerability is real AND mitigable.
```

### 10. Has the vendor been notified?
```
Partially. The findings have been submitted to IEEE Transactions on
Smart Grid for academic peer review (October 7, 2026). Direct
notification to IEC TC 57 WG 15 is in preparation (see attached
disclosure letter draft).

No specific equipment vendor has been notified because the
vulnerability is in the standard's design, not in any particular
vendor's implementation. All compliant implementations are affected.
```

### 11. References
```
- IEC 62351-6:2020 standard specification
- IEC 61850-8-1 (GOOSE protocol specification)
- IEEE Std C37.111 (protection relay timing requirements)
- IEEE Std C57.109-2018 (transformer through-fault protection)
- Mewundi et al., "Crypto-Induced Latency Denial of Service in
  IEC 61850 Substation Communications," submitted to IEEE TSG, 2026
- Open-source toolkit: https://github.com/sapnadfir-blip/gridpulse
```

---

## Submission Checklist

- [ ] ESP32 hardware benchmarks (DONE — in results/)
- [x] Raspberry Pi 5 hardware benchmarks (DONE — results/pi5_crypto_benchmark.csv)
- [ ] Real GOOSE PCAP capture from Pi 5 testbed (PENDING)
- [ ] Docker testbed verified and documented (DONE)
- [ ] IEC TC 57 WG 15 disclosure letter sent (PENDING — draft below)
- [ ] Academic paper submitted (DONE — IEEE TSG, Oct 7 2026)
- [ ] MITRE CVE form submitted (PENDING — submit after Pi 5 evidence)
- [ ] Black Hat Asia 2027 submission (IN PROGRESS)

---

## Timeline for Submission

```
Phase 1 (NOW):
  ✅ Draft CVE submission form (this document)
  ✅ Draft IEC disclosure letter
  ⬜ Build Wireshark dissector (supporting tool)
  ⬜ Build adaptive attacker (strengthens evidence)

Phase 2 (When Pi 5 Ethernet adapter arrives):
  ⬜ Run Pi 5 ARM Cortex-A76 crypto benchmarks
  ⬜ Capture real GOOSE PCAP over Ethernet
  ⬜ Run CIL-DoS attack on Pi 5 native testbed
  ⬜ Add Pi 5 results to evidence package

Phase 3 (After Pi 5 evidence):
  ⬜ Send IEC TC 57 WG 15 disclosure letter
  ⬜ Submit MITRE CVE request form
  ⬜ Request 90-day coordinated disclosure window

Phase 4 (If university has relay access):
  ⬜ Test on real IED hardware (ABB/Siemens/SEL)
  ⬜ Capture oscilloscope traces of trip delay
  ⬜ Update CVE with vendor-specific evidence
  ⬜ Notify vendor PSIRT (ABB PSIRT / Siemens ProductCERT)
```

---

## KRACK Precedent Analysis

CVE-2017-13077 (KRACK) is the closest precedent:

| Aspect | KRACK (WPA2) | CIL-DoS (IEC 62351-6) |
|--------|-------------|----------------------|
| Target | WiFi protocol standard | Power grid comm standard |
| Flaw type | Protocol design flaw | Protocol design flaw |
| Vendor | Wi-Fi Alliance (IEEE 802.11i) | IEC TC 57 (IEC 62351-6) |
| Impact | Confidentiality (decryption) | Availability (safety denial) |
| Proof | Software PoC on real devices | Docker testbed + ESP32 + Pi 5 |
| Disclosure | Coordinated with vendors | Coordinated with IEC TC 57 |
| CVE scope | Protocol-level, all vendors | Protocol-level, all vendors |
| Physical impact | None | Grid instability, equipment damage |

Key difference: CIL-DoS has PHYSICAL SAFETY consequences that KRACK
did not. This strengthens the case for a CVE, as the impact extends
beyond the digital domain.

Mathy Vanhoef's approach:
1. Published academic paper (CCS 2017)
2. Built krackattacks.com disclosure website
3. Coordinated with CERT/CC (US-CERT)
4. CERT/CC assigned CVE IDs
5. Notified vendors through CERT/CC

Our approach should mirror this:
1. Academic paper (IEEE TSG — submitted) ✅
2. Build gridpulse disclosure page on GitHub ✅
3. Coordinate with IEC TC 57 WG 15 (their CERT equivalent)
4. Request CVE through MITRE CNA
5. IEC TC 57 issues advisory to member national committees

# CVE Submission — IEC 62351-6 CIL-DoS
## Protocol-Level Vulnerability in IEC 62351-6 Cryptographic Authentication

> **Precedent:** CVE-2017-13077 (KRACK — WPA2 protocol-level vulnerability)
> **Status:** READY — Pi 5 hardware evidence complete (October 22, 2026)

---

## Submission Routes (in priority order)

### Route A — CISA VINCE-NT (RECOMMENDED)

> **Why this route:** CISA is the **Root CNA for Industrial Control Systems**.
> IEC is NOT a CNA and cannot assign CVE IDs. For ICS/OT protocol
> vulnerabilities, CISA is the correct authority. KRACK went through
> CERT/CC (CISA's predecessor) — we should follow the same path.

- **Portal:** https://vulnerabilities.cisa.gov/vincent/auth/login/
- **Email (backup):** cvd@cisa.dhs.gov
- **Process:**
  1. Create account on VINCE-NT
  2. Submit vulnerability report (details below)
  3. CISA triages (checks legitimacy, scope, actionability)
  4. CISA coordinates with IEC TC 57 / affected vendors
  5. CISA assigns CVE ID (they are the ICS Root CNA)
  6. CISA publishes ICS Advisory (ICSA-XX-XXX-XX)
- **Timeline:** CISA may disclose as early as 45 days after first
  contact if the vendor (IEC) is unresponsive.

### Route B — MITRE CNA-LR (Backup)

> **Note:** The legacy form at cveform-legacy.mitre.org is deprecated
> on **November 1, 2026**. The new portal uses Google login.

- **New Portal:** https://mitre.github.io/mitre-cve-roles/cve-id-request/
  (Google or GitLab login → Reserve CAN → Enter details → Submit)
- **Required fields:**
  - Problem types
  - Vendor or project
  - Product name
  - Version
  - Vulnerability description
  - References URL
  - CVSS 4.0 or 3.1 (optional but recommended)
- **Process:**
  1. Log in with Google
  2. Click "Reserve One CAN" → receive CAN-YYYY-####### tracking number
  3. Fill in vulnerability details (Vulnogram format)
  4. Add CVSS metrics
  5. Press "Submit Request"
  6. CNA-LR team reviews → assigns CVE ID if accepted
- **Emails to whitelist:** cve-request@mitre.org, cve@mitre.org

### Recommended Strategy

```
1. Submit to CISA VINCE-NT first (they own ICS CVE assignment)
2. If CISA does not respond within 30 days, submit to MITRE CNA-LR
3. Reference the CISA submission in the MITRE request
4. Send IEC TC 57 WG 15 disclosure letter in parallel
```

---

## Vulnerability Report (for CISA VINCE-NT and/or MITRE CNA-LR)

### Problem Type / Vulnerability Type
```
CWE-400: Uncontrolled Resource Consumption
(secondary: CWE-770: Allocation of Resources Without Limits or Throttling)

Protocol Design Flaw — Computational Denial of Service against
safety-critical real-time system
```

### Vendor / Project
```
International Electrotechnical Commission (IEC)
Technical Committee 57 (TC 57) — Power Systems Management
Working Group 15 (WG 15) — Data and Communication Security
```

### Product
```
IEC 62351-6 — Power systems management and associated information
exchange — Data and communications security — Part 6: Security for
IEC 61850 profiles

Specifically: Cryptographic authentication profiles for GOOSE (Generic
Object Oriented Substation Event) messages, including RSA-2048 digital
signatures, ECDSA-P256 digital signatures, and HMAC-SHA-256 message
authentication codes applied to IEC 61850 GOOSE multicast frames
(EtherType 0x88B8).
```

### Version
```
IEC 62351-6:2020 (current edition)
IEC 62351-6:2007 (previous edition)
All implementations of IEC 62351-6 cryptographic authentication on
IEC 61850 GOOSE messages are affected.

The vulnerability is inherent to the standard's design — any compliant
implementation on resource-constrained IED hardware is vulnerable.
```

### Description
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

### CVSS Metrics
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

### Discovery Details
```
Discoverers:
  - Dr. Sapna Vikram Mewundi (PES University, Bengaluru, India)
    Email: sapnavm@pes.edu
  - Prajwal Chowdary M. (PES University, Bengaluru, India)
    Email: chowdaryprajwal2@gmail.com
  - Prof. Prasad B. Honnavalli (PES University, Bengaluru, India)

Discovery Date: August 2026
Disclosure Timeline:
  - August 2026: Vulnerability discovered during research
  - October 7, 2026: Academic manuscript submitted to IEEE TSG
  - October 22, 2026: Raspberry Pi 5 ARM Cortex-A76 hardware evidence collected
  - [NEXT]: IEC TC 57 WG 15 disclosure letter sent
  - [NEXT]: CVE ID requested from CISA VINCE-NT (ICS Root CNA)
  - [TARGET]: Coordinated public disclosure at Black Hat Asia 2027 (March 2027)
```

### References URL / Proof of Concept
```
All evidence is publicly reproducible:

1. EMBEDDED HARDWARE BENCHMARKS (ESP32 Xtensa LX6 @ 240 MHz):
   - ECDSA-P256 verification: 310,475.9 µs (103× past 3 ms deadline)
   - RSA-2048 verification: 980.1 µs (saturates at ~1,000 pps)
   - HMAC-SHA-256 verification: 167.3 µs (sub-millisecond)
   Dataset: results/esp32_crypto_benchmark.csv

2. ARM CORTEX-A76 BENCHMARKS (Raspberry Pi 5, BCM2712 @ 2.4 GHz):
   - HMAC-SHA-256 verification: 2.33 µs (saturation at ~429,000 pps)
   - ECDSA-P256 verification: 193.63 µs (saturation at ~5,164 pps)
   - RSA-2048 verification: 100.85 µs (saturation at ~9,916 pps)
   - Ed25519 verification: 143.98 µs (saturation at ~6,945 pps)
   - Key finding: Pi 5 Cortex-A76 is 1,603× faster than ESP32 for
     ECDSA — yet a 10K pps flood STILL saturates the queue (ρ = 1.94)
   - 50,000-iteration benchmark, OpenSSL 3.5.7, ARM crypto extensions
   Dataset: results/pi5_crypto_benchmark.csv

3. DOCKER TESTBED REPRODUCTION (single command):
   Repository: https://github.com/sapnadfir-blip/gridpulse
   Command: docker compose run --rm subscriber --mode fifo --attack-rate 100000
   Result: Trip latency > 2,388 ms, 100% deadline violation

4. QUEUEING-THEORETIC PROOF:
   M/M/1 model: ρ = λ_attack / μ_verify
   At 100K pps with RSA-2048 on ESP32 (μ = 1/980µs ≈ 1,020 vps):
   ρ = 100,000 / 1,020 = 98.0 >> 1 (queue diverges to infinity)
   Even on Pi 5 Cortex-A76 (μ = 1/101µs ≈ 9,901 vps):
   ρ = 100,000 / 9,901 = 10.1 >> 1 (still saturated)

5. 49 CONTROLLED EXPERIMENTS validating attack and defense across
   multiple configurations, algorithms, and attack rates.
   Datasets: results/*.csv

6. DEFENSE (PQAC) achieving 3,140× latency reduction:
   Demonstrates the vulnerability is real AND mitigable.
```

### Vendor Notification Status
```
Partially. The findings have been submitted to IEEE Transactions on
Smart Grid for academic peer review (October 7, 2026). Direct
notification to IEC TC 57 WG 15 is in preparation (see attached
disclosure letter draft).

No specific equipment vendor has been notified because the
vulnerability is in the standard's design, not in any particular
vendor's implementation. All compliant implementations are affected.
```

### References
```
- IEC 62351-6:2020 standard specification
- IEC 61850-8-1 (GOOSE protocol specification)
- IEC 61850-5 (communication requirements for functions and device models — defines Performance Classes P1/P2/P3 and the 3 ms transfer time constraint)
- IEEE Std C57.109-2018 (transformer through-fault protection)
- Mewundi et al., "Crypto-Induced Latency Denial of Service in
  IEC 61850 Substation Communications," submitted to IEEE TSG, 2026
- Open-source toolkit: https://github.com/sapnadfir-blip/gridpulse
```

---

## Submission Checklist

- [x] ESP32 hardware benchmarks (DONE — results/esp32_crypto_benchmark.csv)
- [x] Raspberry Pi 5 hardware benchmarks (DONE — results/pi5_crypto_benchmark.csv)
- [x] Real GOOSE PCAP capture from Pi 5 testbed (DONE — results/pcap/, 50K mixed frames)
- [x] Docker testbed verified and documented (DONE)
- [x] Wireshark GOOSE CIL-DoS dissector (DONE — tools/wireshark/)
- [x] Adaptive attacker module (DONE — gridpulse/attacks/adaptive_cildos.py)
- [ ] IEC TC 57 WG 15 disclosure letter sent (DRAFT READY — docs/IEC_TC57_DISCLOSURE_LETTER.md)
- [x] Academic paper submitted (DONE — IEEE TSG, Oct 7 2026)
- [ ] CISA VINCE-NT submission (READY — recommended route for ICS)
- [ ] MITRE CNA-LR submission (BACKUP — if CISA unresponsive)
- [x] Black Hat Asia 2027 submission (IN PORTAL — editing)

---

## Timeline for Submission

```
Phase 1 (COMPLETE — October 22, 2026):
  ✅ Draft CVE submission form (this document)
  ✅ Draft IEC disclosure letter
  ✅ Build Wireshark dissector (tools/wireshark/)
  ✅ Build adaptive attacker (gridpulse/attacks/adaptive_cildos.py)
  ✅ Run Pi 5 ARM Cortex-A76 crypto benchmarks (results/pi5_crypto_benchmark.csv)

Phase 2 (COMPLETE — October 22, 2026, virtual bridge on Pi 5):
  ✅ Capture real GOOSE PCAP on Pi 5 (results/pcap/, 50K frames)
  ✅ Run native CIL-DoS attack simulation on Pi 5 (6,423 pps achieved)
  ✅ Run XDP/eBPF PQAC defense on Pi 5 (DONE — 99% attack drop at XDP layer, native mode)

Phase 3 (SUBMIT — before November 1, 2026):
  ⬜ Submit to CISA VINCE-NT (https://vulnerabilities.cisa.gov)
      → CISA is the ICS Root CNA, correct authority for IEC 62351
  ⬜ Send IEC TC 57 WG 15 disclosure letter (in parallel)
  ⬜ If CISA unresponsive in 30 days → submit to MITRE CNA-LR
      → Legacy form deprecated Nov 1, 2026; use new Google-login portal
  ⬜ Request 90-day coordinated disclosure window

Phase 4 (OPTIONAL — if university has relay access):
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

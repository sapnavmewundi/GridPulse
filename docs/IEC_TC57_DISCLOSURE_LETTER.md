# Coordinated Vulnerability Disclosure
## IEC Technical Committee 57 — Working Group 15
## Data and Communication Security

---

**From:**
Dr. Sapna Vikram Mewundi
Associate Professor, Department of Computer Science and Engineering
PES University, Bengaluru 560085, India
Email: sapnavm@pes.edu

Prajwal Chowdary M.
Security Researcher, PES University
Email: chowdaryprajwal2@gmail.com

Prof. Prasad B. Honnavalli
Professor, Department of Computer Science and Engineering
PES University, Bengaluru 560085, India

**To:**
IEC Technical Committee 57 — Working Group 15
Data and Communication Security
International Electrotechnical Commission
3 rue de Varembé, CH-1211 Geneva 20, Switzerland

**Date:** [TO BE SENT — Pi 5 evidence collected October 22, 2026]

**Subject:** Coordinated Disclosure — Crypto-Induced Latency Denial of
Service (CIL-DoS) Vulnerability in IEC 62351-6 Cryptographic
Authentication for IEC 61850 GOOSE Messages

---

Dear Members of IEC TC 57 Working Group 15,

We are writing to report a protocol-level vulnerability we have
discovered in IEC 62351-6:2020, specifically in the cryptographic
authentication mechanism specified for IEC 61850 GOOSE (Generic Object
Oriented Substation Event) messages. We are disclosing this finding to
your working group in advance of public presentation, in accordance
with coordinated vulnerability disclosure practices.

### Summary

IEC 62351-6 mandates digital signature verification (RSA-2048,
ECDSA-P256) or MAC verification (HMAC-SHA-256) on all incoming GOOSE
frames at the receiving Intelligent Electronic Device (IED). We have
identified that this mandatory verification creates a computational
denial-of-service vulnerability we term **Crypto-Induced Latency
Denial of Service (CIL-DoS)**.

An attacker with Layer-2 access to the substation process bus can flood
structurally valid but cryptographically invalid GOOSE frames at rates
of 10,000–100,000 packets per second. The receiving IED must execute
full cryptographic verification on each frame before rejection,
saturating the processor queue and causing legitimate protection trip
commands to exceed the 3.0 ms IEC 61850 Performance Class P2/P3
delivery deadline.

### Key Findings

1. **ECDSA-P256 verification on representative embedded silicon
   (ESP32 Xtensa LX6 @ 240 MHz) requires 310.5 ms per operation** —
   exceeding the 3.0 ms safety deadline by 103× even without an
   attack.

2. **Under CIL-DoS at 100,000 pps, measured queuing delay exceeds
   2,388 ms** with 100% deadline violation rate across 49 controlled
   experiments.

3. **Naïve countermeasures (larger buffers, additional CPU threads)
   provably fail** due to the fundamental queueing-theoretic
   relationship λ_attack >> μ_verify.

4. **ARM Cortex-A76 silicon (Raspberry Pi 5 @ 2.4 GHz) confirms the
   vulnerability scales beyond low-end microcontrollers**: ECDSA-P256
   verification takes 193 µs, meaning a flood of just 5,200 pps
   saturates the queue (ρ > 1). RSA-2048 saturates at ~9,900 pps.
   Even on desktop-class ARM silicon, a 100K pps flood yields ρ = 10.1.

5. **NIST Post-Quantum Cryptography standards (FIPS 204/205) worsen
   the vulnerability**: SLH-DSA-SHA2-128s requires 597 ms for signing
   and produces 7,856-byte signatures exceeding standard Ethernet MTU.

6. **Physical grid consequences** include generator rotor angle
   instability past the Critical Clearing Time, transformer
   through-fault thermal damage (6.25× I²t surge), and breaker-failure
   protection blinding.

### Proposed Mitigation

We have developed and validated a defense mechanism — the **Priority
Queue Admission Controller (PQAC)** — that achieves a 3,140×
latency reduction (2,388 ms → 760 µs) with 0.00% deadline miss rate.
PQAC performs O(1) triage in < 0.2 µs per frame using:

- SCD-based MAC allowlist pre-filtering
- RFC 1982 serial arithmetic with bounded plausibility window
- Verify-before-commit state tracking

We recommend the working group consider incorporating PQAC-style
admission control requirements into future revisions of IEC 62351-6,
and issuing guidance to implementers of current editions.

### Evidence and Reproducibility

All findings are supported by:
- Real embedded hardware benchmarks (ESP32, Raspberry Pi 5)
- A Docker-based multi-container testbed reproducible with a single
  command
- 49 controlled experimental datasets (CSV)
- Queueing-theoretic proofs (M/M/1 and M/D/1 models)
- An open-source toolkit released under MIT License

Repository: https://github.com/sapnadfir-blip/gridpulse

### Academic Publication

A full manuscript detailing these findings has been submitted to
IEEE Transactions on Smart Grid (October 7, 2026) and is currently
under peer review.

### Disclosure Timeline

We request a **90-day coordinated disclosure window** from the date
this letter is received, during which we will withhold public
presentation of exploitation techniques while the working group
assesses the findings and considers mitigations.

| Date | Action |
|------|--------|
| [Date sent] | This disclosure letter sent to IEC TC 57 WG 15 |
| [+30 days] | Request acknowledgement and initial assessment |
| [+60 days] | Request status update on mitigation guidance |
| [+90 days] | Public disclosure (Black Hat Asia 2027, March 2-3) |

We are committed to working with the committee to ensure responsible
handling of this vulnerability. We welcome the opportunity to present
our findings to the working group and to collaborate on mitigation
guidance.

### Contact

For technical questions or to arrange a presentation:

Dr. Sapna Vikram Mewundi — sapnavm@pes.edu
Prajwal Chowdary M. — chowdaryprajwal2@gmail.com

Respectfully submitted,

Dr. Sapna Vikram Mewundi
Prajwal Chowdary M.
Prof. Prasad B. Honnavalli

Department of Computer Science and Engineering
PES University, Bengaluru, India

# Black Hat Asia 2027 — Briefings Submission
## GridPulse: Killing Power Grids with Their Own Crypto

> **Use this document to copy-paste into the BH CFP Portal fields.**
> Each section heading matches a portal field exactly.

---

### Session Title

```
GridPulse: Killing Power Grids with Their Own Crypto
```

*(Alternative: "When Security Kills Safety: Weaponizing IEC 62351 to Crash Power Grids")*

---

### Track (Primary)

```
Critical Infrastructure / ICS / SCADA
```

### Track (Secondary)

```
Applied Security / Novel Attack
```

---

### Format

```
40 minutes
```

*(Recommended: 40 min gives room for the live demo and the defense deep-dive. 30 min works if they need to fit the schedule.)*

---

### Audience Level

```
Intermediate
```

---

### Abstract (75–300 words)

```
Modern electrical substations are replacing copper wiring with Ethernet,
transmitting safety-critical circuit breaker trip commands as IEC 61850
GOOSE multicast packets with a hard 3-millisecond delivery deadline. To
prevent spoofing, IEC 62351-6 mandates cryptographic authentication —
digital signatures on every frame. We discovered that this security
mandate creates a fatal vulnerability: Crypto-Induced Latency Denial of
Service (CIL-DoS).

An attacker with Layer-2 access to the substation process bus floods
structurally valid but cryptographically invalid GOOSE frames at
10K–100K packets per second. Each frame forces the protection relay to
burn CPU cycles on full signature verification before it can reject
the forgery. Legitimate fault-trip commands queue behind thousands of
attack frames — the 3 ms safety deadline is violated 100% of the time,
with measured queuing delays exceeding 2,388 ms.

We validated CIL-DoS on real embedded silicon (ESP32 / Arduino) and
found that a single ECDSA-P256 verification takes 310 ms — over 100x
past the safety deadline, even without an attack. We then modeled the
physical grid consequences: generator rotor angle divergence past the
critical clearing time (201.6 ms), breaker-failure protection blinded,
and a 6.25x surge in transformer thermal energy causing winding damage.

We also benchmarked NIST Post-Quantum Cryptography standards (ML-DSA,
SLH-DSA, FALCON) and found that hash-based PQC makes the problem
catastrophically worse (597 ms sign time, 7,856-byte signatures that
break Ethernet MTU).

Finally, we present GridPulse PQAC — a Priority Queue Admission
Controller defense achieving a 3,140x latency reduction (2,388 ms to
760 microseconds) with 0.00% deadline miss rate across 49 controlled
experiments, plus an open-source Docker testbed for immediate
reproducibility.
```

*(~270 words)*

---

### Presentation Outline (max 4,000 characters)

```
1. THE SECURITY-SAFETY PARADOX (5 min)
   - How modern substations replaced copper with Ethernet (IEC 61850)
   - The 3 ms hard deadline for circuit breaker trip commands (GOOSE)
   - Why IEC 62351-6 mandates cryptographic signatures on every frame
   - The paradox: security verification creates a DoS surface

2. ATTACK: CRYPTO-INDUCED LATENCY DoS (8 min)
   - Threat model: attacker on the Layer-2 process bus (no keys needed)
   - Attack mechanism: flood valid-structure, invalid-signature GOOSE
   - Queueing theory: M/M/1 model showing server utilization rho >> 1
   - Measured results: 2,388 ms queue delay, 100% deadline violation
   - Why naive countermeasures fail:
     * Bigger buffers make it WORSE (4x latency increase)
     * More CPU threads still fail (rho_4 = 14.3 at 100K pps)

3. REAL HARDWARE VALIDATION (5 min)
   - ESP32 / Arduino silicon benchmarks (not desktop simulations)
   - The killer finding: ECDSA-P256 = 310 ms per verify (103x deadline)
   - RSA-2048 saturates at 1K pps, HMAC-SHA256 is sub-millisecond
   - Why the standard's recommended algorithms are the worst choice

4. PHYSICAL GRID CONSEQUENCES (5 min)
   - Equal-Area Criterion: rotor angle instability past t_crit = 201.6 ms
   - Low-inertia renewable grids: t_crit drops to 120 ms
   - Transformer thermal damage: 6.25x I²t surge under delayed clearing
   - Breaker-failure protection (ANSI 50BF) blinded by same attack
   - End state: cascading blackout from a Layer-2 packet flood

5. POST-QUANTUM CRYPTOGRAPHY MAKES IT WORSE (4 min)
   - NIST FIPS 204/205 benchmarks: ML-DSA, SLH-DSA, FALCON
   - SLH-DSA: 597 ms sign time + 7,856-byte signature (breaks MTU)
   - Lattice schemes (ML-DSA-44, FALCON-512): sub-ms, viable with PQAC
   - The PQC migration timeline vs. the grid's 30-year asset lifecycle

6. [LIVE DEMO] CIL-DoS ATTACK & PQAC DEFENSE (8 min)
   - Docker multi-container substation process bus testbed
   - Demo 1: Baseline — FIFO queue under 100K pps flood (watch
     latency spike past 2 seconds, trip commands stuck)
   - Demo 2: PQAC engaged — same flood, trip latency drops to
     sub-millisecond, 0% deadline miss (audience sees the save)
   - Browser-based real-time dashboard (latency graph, PQAC pipeline,
     packet inspector) — replaces terminal TUI for stage visibility
   - SCADA HMI blind-spot simulator: shows operator sees "all green"
     while protection is actually blinded by CIL-DoS
   - Open-source: audience can reproduce in 30 seconds (one command)

7. DEFENSE DEEP-DIVE: PQAC (3 min)
   - 3-stage O(1) admission control in < 0.2 microseconds per frame
   - Stage 1: SCD MAC allowlist pre-filter
   - Stage 2: RFC 1982 serial arithmetic + transition token gating
   - Stage 3: verify-before-commit (prevents state poisoning)
   - Results: 3,140x latency reduction, 0.00% deadline miss (49 trials)

8. TAKEAWAYS & CALL TO ACTION (2 min)
   - Disclosure to IEC TC 57 WG 15 (standards body)
   - Recommendations for substation engineers and vendors
   - Open-source release: toolkit, testbed, and all 49 experiment CSVs
```

*(~2,700 characters)*

---

### Problem Statement

```
IEC 62351-6 mandates cryptographic authentication for substation
protection communications (IEC 61850 GOOSE) to prevent spoofing. But
the standard ignores the computational cost on resource-constrained
protection relays. An attacker with Layer-2 LAN access — requiring no
cryptographic keys — can flood the process bus with invalid-signature
frames, forcing the relay CPU to waste cycles on verification. This
creates a new attack class (CIL-DoS) that weaponizes the security
standard itself to defeat the safety function it was designed to
protect: circuit breaker trip commands miss their 3 ms deadline 100% of
the time, potentially causing generator instability, transformer
damage, and cascading blackouts. No prior work has demonstrated this
full cyber-to-physical failure chain on real embedded hardware, nor
evaluated the impact of NIST Post-Quantum Cryptography on the problem.
```

---

### Audience Takeaways

```
1. Understand how IEC 62351 cryptographic verification creates an
   exploitable DoS surface on substation protection relays — and how to
   test your own IEC 61850 deployments using our open-source Docker
   testbed (one command, 30 seconds).

2. Learn why naive defenses (bigger buffers, more CPU threads, faster
   hardware) provably fail against CIL-DoS, and how the Priority Queue
   Admission Controller (PQAC) achieves sub-millisecond trip latency
   under 100K pps attack — with a design you can implement on existing
   relay firmware.

3. Gain concrete guidance on Post-Quantum Cryptography migration for
   ICS/SCADA environments: which NIST PQC algorithms are viable for
   real-time substation protection (ML-DSA, FALCON) and which will
   catastrophically break it (SLH-DSA), along with deployment
   recommendations for utilities planning 30-year asset lifecycles.
```

---

### Research Novelty

```
This work introduces the first systematic analysis of cryptographic
computational exhaustion as a denial-of-service vector against
safety-critical power grid protection. Specific novel contributions:

1. NEW ATTACK CLASS: CIL-DoS (Crypto-Induced Latency DoS) — the first
   demonstration that IEC 62351-6 security verification itself can be
   weaponized to defeat the safety function it protects, requiring zero
   cryptographic keys from the attacker.

2. REAL SILICON VALIDATION: All benchmarks run on actual embedded
   hardware (ESP32 Xtensa LX6 @ 240 MHz), not desktop simulations. The
   finding that ECDSA-P256 takes 310 ms per verification on
   representative IED silicon — 103x past the safety deadline without
   any attack — is new to the literature.

3. FULL CYBER-TO-PHYSICAL CHAIN: Prior ICS security work stops at
   packet delays. We model through to generator rotor angle divergence,
   transformer I²t thermal damage, and breaker-failure protection
   blinding — the actual grid consequences.

4. POST-QUANTUM IMPACT: First evaluation of NIST PQC standards
   (FIPS 204/205) in the IEC 61850 real-time context, showing hash-based
   PQC catastrophically worsens the attack surface.

5. WORKING DEFENSE + OPEN-SOURCE RELEASE: PQAC achieves 3,140x latency
   improvement with formal queueing-theoretic guarantees. The full
   toolkit, Docker testbed, and 49-experiment dataset are released
   open-source for immediate community reproduction.

6. ADAPTIVE ADVERSARY ANALYSIS: An intelligent attacker that defeats
   PQAC Stages 1 and 2 (MAC spoofing, stNum walking) still cannot
   bypass Stage 3 — proving the cryptographic guarantee holds against
   a knowledgeable adversary with full SCD knowledge.
```

---

### Prior Release & New Material

```
Has any portion been previously published or presented? YES

- An academic manuscript covering the same research has been submitted
  to IEEE Transactions on Smart Grid (October 7, 2026) and is currently
  under peer review. It has NOT been published or presented.

- The open-source toolkit is available on GitHub but has not been
  presented at any conference.

What's different in this submission:
- The Briefing is demo-forward and practitioner-oriented, focusing on
  live attack reproduction, defender takeaways, and PQC migration
  guidance — distinct from the mathematical focus of the journal paper.
- The live Docker demo, audience-reproducible testbed walkthrough, and
  ICS operator recommendations are new material not in the manuscript.
- The adaptive attacker module, browser-based demo dashboard, SCADA
  blind-spot simulator, Wireshark dissector, and MITRE CVE submission
  pathway are entirely new contributions not in the journal paper.

Estimated % of new material: 55%
```

---

### Plans to Publish Elsewhere

```
Yes. The academic paper is under review at IEEE Transactions on Smart
Grid (submitted October 7, 2026, decision expected Q1 2027). No
conference presentation or blog post is planned before Black Hat Asia.
We will notify cfp@blackhat.com of any publication status changes.
```

---

### New Vulnerabilities

```
Yes. CIL-DoS is a new vulnerability class affecting all IEC 61850
protection relays implementing IEC 62351-6 cryptographic
authentication. The vulnerability is inherent to the standard's
design — it arises from the computational cost of mandatory signature
verification on resource-constrained IED processors.

Technical details: An attacker with Layer-2 process bus access can
flood GOOSE frames (EtherType 0x88B8) at 10K–100K pps with valid
structure but invalid signatures. The relay must execute full modular
exponentiation (RSA) or elliptic curve math (ECDSA) to reject each
frame, saturating the CPU queue and delaying legitimate trip commands
past the 3 ms IEC 61850 safety deadline.

Affected systems: Any IEC 61850 substation deploying IEC 62351-6
digital signature authentication on GOOSE messages. This includes
protection relays from major vendors (ABB, Siemens, GE, SEL) when
configured for asymmetric authentication.

Potential impact: Delayed or prevented circuit breaker trip commands
during electrical faults, leading to generator instability, transformer
thermal damage, and potential cascading blackouts.
```

---

### Disclosure Status

```
Yes, partially disclosed. We have submitted findings to the academic
community via the IEEE Transactions on Smart Grid manuscript (under
review). We are preparing coordinated disclosure to IEC TC 57 WG 15
(the working group responsible for IEC 62351). No vendor-specific
notification has been made because the vulnerability is in the
standard's design, not a specific implementation. No patch is available;
the PQAC defense presented in this talk is our proposed mitigation.
```

---

### New Tools

```
Yes. GridPulse is an open-source (MIT License) toolkit including:

- CIL-DoS attack generator (Python + native C)
- Adaptive CIL-DoS attacker — intelligent evasion module that spoofs
  SCD allowlist MACs, walks stNum within plausibility window, and
  rate-shapes to evade PQAC Stages 1 & 2 (proves Stage 3 crypto
  guarantee holds against a knowledgeable adversary)
- PQAC defense implementation (C, with eBPF/XDP kernel filter)
- Docker multi-container substation process bus testbed
- ESP32/Arduino embedded silicon benchmarking sketch
- NIST PQC benchmarking suite (ML-DSA, SLH-DSA, FALCON via liboqs)
- 49-experiment reproducible dataset (CSV)
- Browser-based real-time demo dashboard (latency chart, PQAC
  3-stage pipeline visualization, packet inspector, operator console)
- SCADA HMI blind-spot simulator (shows operator "all green" while
  protection is actually blinded — demonstrates the human-factors gap)
- Wireshark Lua dissector for GOOSE CIL-DoS detection (EtherType
  0x88B8, rate-based flood detection, stNum anomaly alerts)

Purpose: Enables substation engineers and security researchers to
reproduce CIL-DoS attacks, validate the PQAC defense, and benchmark
cryptographic performance on their own hardware — all in an isolated
lab environment.

The tool is open-source (GitHub) and supports the research findings.
It is NOT a commercial product. Note: We are also submitting to Arsenal
for a dedicated tool demonstration.
```

---

### Demo Plans

```
Yes. The Briefing includes a live demonstration of the CIL-DoS attack
and PQAC defense using the GridPulse Docker testbed:

1. ATTACK DEMO: Launch a multi-container isolated substation process bus
   (publisher, subscriber, attacker) and initiate a 100K pps CIL-DoS
   flood against an undefended FIFO relay. The real-time terminal
   dashboard shows trip latency climbing past 2,000 ms — the audience
   sees legitimate protection commands stuck behind attack traffic.

2. DEFENSE DEMO: Enable PQAC on the same relay under the same 100K pps
   flood. The dashboard shows trip latency instantly dropping to
   sub-millisecond with 0% deadline miss — the audience sees the grid
   being saved in real time.

3. REPRODUCIBILITY: Show that the entire demo runs with a single
   docker compose command. Attendees can reproduce it on their laptops
   during the talk.

This demonstrates the issue (attack impact), not just a tool — the
demo tells the story of a grid going from vulnerable to protected.
```

---

### Follow-Up Session

```
Yes. We would offer a hands-on skill-building session where attendees:
- Run the GridPulse Docker testbed on their laptops
- Modify attack parameters (rate, algorithm, burst pattern)
- Observe PQAC tuning effects on trip latency
- Benchmark PQC algorithms on their own hardware
Format: Interactive workshop / tool demonstration (45–60 min)
```

---

### Speaker Presentation Experience

*(Fill in per speaker — placeholder below)*

```
Speaker 1: Dr. Sapna Vikram Mewundi
- Previous speaking: [List conferences]
- Previous Black Hat: [Yes/No + details]

Speaker 2: Prajwal Chowdary M.
- Previous speaking: [List conferences]
- Previous Black Hat: [Yes/No + details]
```

---

### Video Sample

```
[Provide a YouTube/Vimeo link to a 2-3 minute technical walkthrough
of the CIL-DoS attack and PQAC defense demo, or a previous conference
talk recording]
```

*(Recommendation: Record a 2-3 min screencast of the Docker demo
showing the attack spike and PQAC recovery — upload to YouTube as
unlisted.)*

---

### Language

```
English
```

---

### Company/Employer Affiliation

```
No. PES University is an academic institution and does not offer
commercial products or services related to ICS/SCADA security.
```

---

### Supporting Materials

```
[Link to the GridPulse GitHub repository — public, no login required]
[Link to the pre-print paper PDF — optional, if publicly available]
```

---

### Publication Timing / Embargo

```
Yes — you may publish the title, abstract, and speaker information
immediately upon acceptance.
```

---

### Message to the Review Board (optional)

```
GridPulse addresses a fundamental design tension in critical
infrastructure security: the standards mandating cryptographic
protection (IEC 62351) inadvertently create the conditions for a novel
denial-of-service attack against the very safety functions they aim to
protect. This is not a theoretical concern — our ESP32 benchmarks show
that the standard's recommended algorithm (ECDSA-P256) inherently
violates the safety deadline by 103x on representative IED hardware,
even without an attack.

We believe this research is timely given the global push toward
IEC 62351 adoption and the NIST PQC migration timeline. The work is
fully reproducible: the Docker testbed runs with a single command, and
all 49 experimental datasets are included. We are committed to
coordinated disclosure with IEC TC 57 WG 15 and welcome the review
board's guidance on responsible presentation of these findings.
```

---

## Speaker Bio Template

### Dr. Sapna Vikram Mewundi

```
Dr. Sapna Vikram Mewundi is an Associate Professor in the Department
of Computer Science and Engineering at PES University, Bengaluru, India.
Her research focuses on digital forensics, critical infrastructure
security, and cyber-physical systems. [Add: specific ICS/SCADA
experience, publications, industry collaborations, certifications].
```

### Prajwal Chowdary M.

```
Prajwal Chowdary M. is a security researcher at PES University,
Bengaluru, India, specializing in offensive security research targeting
industrial control systems and critical infrastructure. His work spans
protocol-level attack development, embedded systems security, and
post-quantum cryptography evaluation for operational technology
environments. [Add: specific experience, tools released, CTF/bug bounty
achievements if any].
```

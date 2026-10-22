# GridPulse Wireshark GOOSE CIL-DoS Dissector

Wireshark Lua plugin that parses IEC 61850 GOOSE frames and detects
Crypto-Induced Latency DoS (CIL-DoS) attack patterns in real time.

## Install

```bash
# Linux / macOS
mkdir -p ~/.local/lib/wireshark/plugins
cp goose_cildos_dissector.lua ~/.local/lib/wireshark/plugins/

# Windows
copy goose_cildos_dissector.lua %APPDATA%\Wireshark\plugins\
```

Restart Wireshark. The dissector activates automatically on EtherType 0x88B8.

## What It Detects

| Alert | Trigger | Severity |
|-------|---------|----------|
| CIL-DoS Flood | Source rate > 1000 pps (configurable) | Error |
| Abnormal Burst | Source rate > 200 pps | Warning |
| stNum Regression | stNum decreases (replay/spoof) | Warning |
| stNum Large Jump | stNum jumps > 16 (state injection) | Warning |
| Unknown Source | MAC not in known allowlist | Note |

## Display Filters

```
goose_cildos.rate > 1000              -- flood-rate sources only
goose_cildos.alert contains "FLOOD"   -- CIL-DoS flood frames
goose_cildos.stnum > 100              -- high state numbers
goose_cildos.verdict == "NORMAL"      -- clean traffic only
```

## Preferences

Edit → Preferences → Protocols → GOOSE CIL-DoS Analyzer:
- Flood threshold (default: 1000 pps)
- Burst threshold (default: 200 pps)
- stNum plausibility window (default: 16)

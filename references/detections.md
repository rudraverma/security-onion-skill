# Authoring & Tuning Detections

Security Onion 2.4's **Detections** module manages three rule engines from one interface. This is where an
operator turns a finding into durable, automatic coverage. Turning off noise without going blind is the
craft here.

## Table of contents
1. [The three engines](#the-three-engines)
2. [Detection lifecycle](#detection-lifecycle)
3. [Suricata (NIDS) rules](#suricata-nids-rules)
4. [Sigma rules (ElastAlert 2)](#sigma-rules-elastalert-2)
5. [YARA rules (Strelka)](#yara-rules-strelka)
6. [Tuning without going blind](#tuning-without-going-blind)
7. [Status indicators](#status-indicators)
8. [Detection authoring checklist](#detection-authoring-checklist)

---

## The three engines

| Engine | Language | Data it inspects | Runtime | Tuning options |
|---|---|---|---|---|
| **NIDS** | Suricata rules | Live network traffic | Suricata | modify / suppress / threshold |
| **Sigma** | Sigma YAML | Logs indexed in OpenSearch/Elastic | ElastAlert 2 | custom filter |
| **YARA** | YARA | Files extracted from traffic | Strelka | enable / disable only |

Pick the engine by where the signal lives:
- **Wire-level** pattern (payload content, JA3/JA4, DNS/HTTP indicators, TLS SNI) → **Suricata**.
- **Log-level** behavior you already index (process creation, auth, cloud, Zeek metadata) → **Sigma**.
- **File-borne** malware (PE, script, document content) → **YARA/Strelka**.

When both could work, prefer **Sigma** if the data is already in your index — it's cheaper than adding
wire inspection, and easier to scope-tune.

---

## Detection lifecycle

```
Author/import → Enable → Deploy (sync to engine) → Fires → Alert → Triage → Tune → (repeat)
```

- Detections are the **upstream source of alerts**: when a detection fires it generates an alert in the
  Alerts interface. Tuning a detection from an alert is a first-class path ("Tune Detection" button).
- Changes propagate differently per engine (see [Status indicators](#status-indicators)): Sigma changes
  hit UI+disk immediately; Suricata bulk toggles are instant but regex-scoped edits sync on the next
  engine run; Strelka/YARA UI updates immediately with disk changes on the next state run.
- Sync modes: **Differential** (fast hash comparison) and **Full** update.

---

## Suricata (NIDS) rules

Classic Suricata signature anatomy:

```
alert <proto> <src> <sport> -> <dst> <dport> ( \
  msg:"CYBERHAWK C2 beacon - fixed URI"; \
  flow:established,to_server; \
  http.method; content:"POST"; \
  http.uri; content:"/api/gate.php"; \
  classtype:trojan-activity; \
  metadata:mitre_technique_id T1071.001; \
  reference:url,cyberhawkthreatintel.com; \
  sid:9000001; rev:1; )
```

Authoring notes:
- **`sid`** must be unique; use a local range (e.g. `9000000+`) so it never collides with ET/community.
- Start narrow (`flow`, sticky buffers like `http.uri`/`tls.sni`/`dns.query`) so it's precise.
- Add `metadata:mitre_technique_id ...` and a `reference:` — it makes triage and reporting far easier.
- Include a comment on expected false positives (see the checklist).

Tuning a live Suricata SID (no source edit needed):
- **`threshold`** — fire only after N events in T seconds (dampen chatty rules):
  `threshold: type threshold, track by_src, count 5, seconds 60;`
- **`suppress`** — silence for a specific host/subnet:
  `suppress gen_id 1, sig_id 9000001, track by_src, ip 10.100.70.0/24;`
- **`modify`** — regex-rewrite a field of an existing rule.

In SOC these are set on the detection's **TUNING** tab; on disk they live in the NIDS tuning config.

---

## Sigma rules (ElastAlert 2)

Sigma is engine-agnostic YAML that SO compiles to ElastAlert 2 queries against your logs.

```yaml
title: CyberHawk - Suspicious PowerShell EncodedCommand
id: 7f2c9e10-0b3a-4d2e-9f11-cyberhawk0001
status: experimental
description: Detects PowerShell launched with an encoded command, a common obfuscation for stagers.
references:
  - https://cyberhawkthreatintel.com
author: Rudra Verma | CyberHawk Threat Intel
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  condition: selection
falsepositives:
  - Legitimate admin scripts that base64-encode arguments
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

Authoring notes:
- `logsource` must match how SO indexes that log (product/category/service). Verify with a `tags:` query
  that the fields exist before trusting the rule.
- Keep `level` honest — it maps to alert severity and drives triage priority.
- `falsepositives` is not optional prose; it's how the next analyst decides whether to trust the rule.

Tuning: add a **custom filter** on the detection to exclude benign matches (e.g. a specific admin host or
service account) rather than disabling the whole rule.

---

## YARA rules (Strelka)

YARA scans files Strelka extracts from the wire (and files you submit). Good for known-malware families
and script/document indicators.

```yara
rule CyberHawk_Generic_Downloader_Cradle
{
    meta:
        author      = "Rudra Verma | CyberHawk Threat Intel"
        description = "Detects common one-line download-and-execute cradles in scripts"
        reference   = "https://cyberhawkthreatintel.com"
        mitre       = "T1105"
        severity    = "high"
    strings:
        $ps1 = "DownloadString(" ascii wide nocase
        $ps2 = "IEX(" ascii wide nocase
        $ps3 = "FromBase64String(" ascii wide nocase
    condition:
        2 of ($ps*)
}
```

Authoring notes:
- Prefer several weak strings + an `N of` condition over one broad string — cuts false positives.
- Use `ascii wide nocase` for script content that may be UTF-16 (PowerShell) or case-varied.
- YARA in SO has **no in-place tuning** — you enable/disable, or edit the rule and re-sync.

---

## Tuning without going blind

The cardinal rule: **scope the exception, keep the coverage.** Silencing a rule globally to stop one
benign source is how real intrusions slip past.

| Situation | Right move | Wrong move |
|---|---|---|
| One admin box trips a scanner rule | `suppress` by that IP / Sigma filter on that host | Disable the rule |
| Rule too chatty but valid | `threshold` to rate-limit | Delete the rule |
| Rule fundamentally wrong for your env | Modify to tighten, or replace | Leave it firing and ignored |

Always document the tuning: what was scoped, why it's benign, and what the rule can now no longer see.

---

## Status indicators

The Detections UI shows live states: **Pending, Importing, Synchronizing, Sync Failed, Migration Failed,
Rule Mismatch**. A **Rule Mismatch** often means Elasticsearch/OpenSearch hit its **disk watermark** —
check disk before assuming the rule is broken.

---

## Detection authoring checklist

Before you call a detection done:

- [ ] Unique identity (`sid` in local range / Sigma `id` UUID / YARA rule name)
- [ ] Clear `msg`/`title`/description a tired analyst understands at 3am
- [ ] MITRE ATT&CK technique mapped
- [ ] Severity/level set honestly
- [ ] A `reference:` (ticket, report, or CyberHawk URL)
- [ ] **Expected false positives documented**
- [ ] Scoped as narrowly as the threat allows (flow/sticky buffers / logsource / N-of strings)
- [ ] Tested against a known-true sample (and, ideally, a known-benign one)
- [ ] Deploy confirmed with the user (state change) and sync status checked

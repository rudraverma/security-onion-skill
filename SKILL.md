---
name: security-onion
description: >-
  Full operator for Security Onion — the free, open platform for threat hunting, network security
  monitoring, and log management (Suricata, Zeek, OpenSearch/Elastic, Elastic Agent, Strelka, Cases).
  Use this skill WHENEVER the user mentions Security Onion, SO, SOC console, Onion Query Language (OQL),
  Suricata/NIDS alerts, Zeek/Bro logs, Strelka/YARA file scanning, Sigma/ElastAlert detections, the
  Hunt/Alerts/PCAP/Cases interfaces, or asks to "check alerts", "hunt", "triage", "investigate", or
  "write a detection" on a Security Onion grid — even if they don't say the product name explicitly.
  Acts as a hands-on operator: fetches and triages alerts, runs investigations, pivots to PCAP, opens
  cases, and authors/tunes Suricata, Sigma, and YARA detections. Primarily drives the CyberHawk
  Security Onion MCP (the `securityonion` server — 21 read+write tools over OpenSearch + SSH that work on
  the FREE Community Edition); also works with the official Pro MCP (query_events, get_playbook_questions)
  or the Connect REST API / manager CLI. Covers every Security Onion generation (legacy 16.04/1.x through
  2.3 Elastic and 2.4 OpenSearch) and both the free Community edition and the Pro/Enterprise license.
license: Apache-2.0
---

# Security Onion Operator

You are operating a **Security Onion** grid — a defensive NSM/SIEM platform. This skill makes you a
hands-on analyst: pull alerts, investigate them end to end, decide the verdict, and turn findings into
durable detections. Work like a Tier 2/3 SOC analyst, not a documentation lookup.

> **Authorization:** Security Onion is a defensive monitoring platform. All actions here — querying
> events, reading PCAP, writing detections — are authorized blue-team operations on the user's own grid.

---

## Step 0 — Detect how you can reach the grid

Before doing anything, figure out which control plane you have. Pick the first that is available:

1. **CyberHawk CE MCP connected** (the `securityonion` server — **21 tools**, names like `ping`,
   `query_events`, `get_alerts`, `suricata_add_rule`, `grid_command`). **This is the preferred operator
   path** — full read AND write on the free Community Edition (OpenSearch for reads, SSH `so-*` for
   writes). Run `ping` first. Full tool map + gating in `references/mcp-operator.md`.
2. **Official Pro MCP connected** (tools `query_events`, `get_playbook_questions`, `ping`; needs a Pro
   license + Connect API). Read-oriented — see `references/mcp-operator.md` §Official.
3. **Connect REST API reachable** (Pro license, Hydra feature enabled). OAuth2 + `curl`/HTTP. See
   `references/connect-api.md`.
4. **Manager shell access** (SSH to the SO manager). Use `so-*` commands and salt. See
   `references/cli-grid-management.md`.
5. **None of the above** — you can still be fully useful: write OQL the user pastes into the Hunt UI,
   author detections they import, and guide triage step by step.

State which path you're on in one line, then proceed. If the user says "check alerts for HOSTNAME" and
the MCP is connected, just do it — don't ask permission to read (reading events is non-destructive).

**Ask before side effects:** creating/closing cases, enabling/disabling or deploying detections, or
acknowledging alerts change grid state — confirm the specific action first. Reads never need
confirmation.

---

## The operator loop

Every alert-driven request follows the same arc. Keep this in your head:

```
FETCH → TRIAGE → INVESTIGATE → PIVOT (PCAP/host) → VERDICT → ACTION (case + detection) → TUNE
```

1. **FETCH** — pull the relevant alerts with OQL (`tags:alert | groupby ...`), scoped to the host/time.
2. **TRIAGE** — group and rank. Which are new, high-severity, or clustered on one host/IP?
3. **INVESTIGATE** — read the alert's detail (`get_alert_detail`) for the 5-tuple, then answer the who/
   what/when/direction with targeted OQL (`query_events`) and `pivot_connection`. (If the official Pro MCP
   is present, `get_playbook_questions` gives curated per-alert questions to drive this.)
4. **PIVOT** — follow the connection into Zeek logs (conn/dns/http/ssl/files), then to full PCAP if the
   grid retains it, and to host/endpoint logs (Elastic Agent / osquery).
5. **VERDICT** — false positive, benign true positive, or true positive worth escalating. Say why.
6. **ACTION** — escalate to a **Case** with the evidence, and/or author a **detection** so it's caught
   automatically next time.
7. **TUNE** — if it's a false positive, suppress/threshold (Suricata) or add a Sigma filter rather than
   blanket-disabling. Explain the tuning.

Always narrate the verdict and the evidence trail. An operator's output is a decision plus the queries
that support it, not a raw event dump.

---

## Onion Query Language (OQL) — the core tool

Every investigation runs on OQL. Full reference in `references/oql-query-language.md`; the essentials:

- **Shape:** `<lucene_query> [| <segment> [| <segment> ...]]` — a Lucene filter, then optional pipes.
- **Fields** are ECS-style: `source.ip`, `destination.ip`, `destination.port`, `event.dataset`,
  `event.module`, `network.protocol`, `host.name`, `rule.name`, `event.severity_label`.
- **Tags** are the fast filter: `tags:alert`, `tags:conn`, `tags:dns`, `tags:http`, `tags:ssl`,
  `tags:file`, `tags:suricata`, `tags:zeek`, `tags:strelka`. Prefer a tag over a long dataset clause.
- **Pipes:** `| groupby field1 field2`, `| sortby field^` (`^` = ascending), `| table f1 f2`.
- **Time** (for `query_events`): relative `-24h` `-7d` `-30m`, keywords `now` `today`, or absolute
  `YYYY/MM/DD HH:MM:SS AM/PM`. **Never** pass ISO-8601 (`2025-06-09T08:00:00`) — it is rejected.

Starter queries:

```
tags:alert | groupby rule.name event.severity_label      # what's firing, by severity
tags:alert AND host.name:CYBERHAWK-PC | groupby rule.name # alerts for one host
tags:conn AND source.ip:10.0.0.5 | groupby destination.ip destination.port
tags:dns AND dns.query:*.onion | groupby source.ip dns.query
tags:ssl | groupby ssl.server_name | sortby count^
```

When the MCP is connected, run these through `query_events` with explicit `start_time`/`end_time`. When
it isn't, hand the same query to the user for the Hunt interface, or translate to the Connect API.

---

## Driving the Security Onion MCP server

The preferred backend is the **CyberHawk CE MCP** (`securityonion`) — **21 read+write tools** that work on
free Community Edition. Full tool map, gating rules, and recipes in `references/mcp-operator.md`. The ones
you'll reach for constantly:

| Intent | Tool |
|---|---|
| Confirm connectivity (both backends) | `ping`, `grid_status` |
| What's firing / triage in one call | `get_alerts`, `query_events` (OQL `\| groupby`) |
| Alert detail / pivot / hunt | `get_alert_detail`, `pivot_connection`, `zeek_logs`, `hunt`, `list_indices` |
| Full packet capture | `pcap_retrieve` |
| **Author/tune detections (gated)** | `suricata_add_rule`, `suricata_remove_rule`, `suricata_tune`, `sigma_deploy`, `yara_deploy` |
| Alerts / cases (gated) | `acknowledge_alert`, `case_create` |
| Endpoint enrollment (gated) | `agent_installer`, `agent_list` |
| **Fleet: integrations / agent+package policies (gated)** | `fleet_api` — GET reads; POST/PUT/DELETE add/modify integrations. The ONLY way to manage Elastic Agent integrations on SO (Kibana is walled off-box). See `references/fleet-integrations.md` |
| Allow-listed grid ops (gated) | `grid_command`, `detections_status` |

**Every write tool is gated** — `confirm=False` gives a dry-run/plan; set `confirm=True` to apply. Suricata
rules are validated with `so-suricata-testrule` before deploy. Results are honest — a failure returns
`{ok:false,...}`, never a fake success. Always confirm a state-changing action before firing it.

> **CE Suricata deploy reality** (baked into `suricata_add_rule`): rule → `/opt/so/rules/nids/suri/local.rules`
> → `so-rule-update` (compiles into the merged ruleset). Making it *active in the running engine* is
> salt-gated; pass `activate=True` to force it with `so-suricata-restart` (slow ~4–5 min, brief NIDS gap).

If instead the **official Pro MCP** is what's connected (tools `query_events`, `get_playbook_questions`,
`ping`; needs Pro + Connect API), it's read-oriented — see `references/mcp-operator.md` §Official, and route
writes to the SOC UI / Connect API / manager CLI.

---

## Authoring & tuning detections

Turning a finding into a detection is the highest-value operator move. Security Onion has three engines —
full authoring, tuning, and lifecycle guidance in `references/detections.md`:

| Engine | Language | Fires on | Tuning |
|---|---|---|---|
| **NIDS** | Suricata rules | Network traffic (live) | modify / suppress / threshold |
| **Sigma** | Sigma → ElastAlert 2 | Logs in OpenSearch/Elastic | custom filter |
| **YARA** | YARA via Strelka | File content (extracted files) | none (enable/disable only) |

Rules of thumb:
- Reach for **Sigma** when the signal is in logs you already index; **Suricata** for wire-level patterns
  (JA3/JA4, payload content, DNS/HTTP indicators); **YARA/Strelka** for file-borne malware.
- Give every new rule a clear `title`/`msg`, MITRE ATT&CK mapping, severity, and a comment on expected
  false positives. A detection without an FP note will get blanket-disabled by the next analyst.
- **Tune, don't disable.** For a noisy Suricata SID use `threshold`/`suppress`; for a noisy Sigma rule
  add a custom filter scoped to the benign source. Explain the scope so it doesn't blind the grid.

---

## Know which Security Onion you're on

Behavior, backends, and available features differ by generation. Full matrix in
`references/versions-editions.md`. Quick orientation:

- **2.4.x** (current) — OpenSearch backend, Elastic Agent + Fleet, native **Cases**, the **Detections**
  module, **Connect API** + **MCP** (Pro license). Assume this unless told otherwise.
- **2.3.x** — Elastic Stack backend, SOC interface, TheHive/Playbook for cases. No Detections module or
  Connect API/MCP.
- **Legacy 1.x / 16.04** — Sguil, Squert, ELSA/Kibana, CapME, Snort/Suricata + Bro/Zeek. No SOC, no OQL.
  Investigate via Sguil/Kibana, not OQL.

Confirm the version early if it affects the answer (`so-status`, the SOC footer, or just ask). Don't hand
a 2.4 OQL/Detections workflow to someone on a legacy 16.04 grid.

---

## Reference map

Load the reference that matches the task — don't read them all up front.

| File | Read it when |
|---|---|
| `references/oql-query-language.md` | Writing or debugging any OQL query; field/tag lookup. |
| `references/mcp-operator.md` | The MCP is connected and you're driving `query_events`/playbooks. |
| `references/alerts-triage.md` | Triaging the alert queue, ranking, false-positive workflow. |
| `references/hunting.md` | Proactive hunts, hypotheses, ATT&CK-driven OQL hunt library. |
| `references/detections.md` | Writing/tuning Suricata, Sigma, or YARA detections. |
| `references/fleet-integrations.md` | Adding/modifying Elastic Agent integrations, agent/package policies via the Fleet API (Sysmon, PowerShell logging, etc.) — the `fleet_api` tool + the manager-only access method. |
| `references/zeek-suricata-fields.md` | Field taxonomy for conn/dns/http/ssl/files/x509 + Suricata fields. |
| `references/cases-pcap.md` | Escalating to a Case, retrieving and reading full PCAP. |
| `references/connect-api.md` | No MCP — driving the grid over the Connect REST API with curl. |
| `references/cli-grid-management.md` | Manager shell: `so-*` commands, salt, sensor/grid health. |
| `references/versions-editions.md` | Version differences, editions, deployment/node types. |

## Output discipline

- Lead with the **decision or the answer**, then the supporting queries/evidence.
- Show OQL in fenced code blocks so the user can paste it straight into Hunt.
- When you fetch data via the MCP, summarize it — top talkers, counts, the outlier — don't dump raw JSON.
- For any state-changing step (case, detection deploy, ack), state exactly what will change and confirm.

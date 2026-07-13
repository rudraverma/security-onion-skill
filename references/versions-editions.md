# Versions, Editions & Deployment Types

Security Onion's capabilities, backends, and even query language differ sharply across generations. Know
which grid you're on before you prescribe a workflow — a 2.4 OQL/Detections answer is useless on a legacy
16.04 box, and Connect API/MCP only exist on Pro 2.4.

## Table of contents
1. [Generation matrix](#generation-matrix)
2. [Security Onion 2.4 (current)](#security-onion-24-current)
3. [Security Onion 2.3](#security-onion-23)
4. [Legacy: Security Onion 1.x / 16.04 and earlier](#legacy-security-onion-1x--1604-and-earlier)
5. [Editions: Community vs Pro/Enterprise](#editions-community-vs-proenterprise)
6. [Deployment & node types](#deployment--node-types)
7. [How to identify the grid you're on](#how-to-identify-the-grid-youre-on)
8. [Operator implications](#operator-implications)

---

## Generation matrix

| Feature | Legacy 1.x / 16.04 | 2.3.x | 2.4.x (current) |
|---|---|---|---|
| Base OS | Ubuntu 14.04/16.04 | CentOS 7 / Ubuntu / OL | Oracle Linux 9 / Ubuntu 22.04 / Rocky/Alma |
| Search backend | ELSA → Elasticsearch | **Elasticsearch** (Elastic Stack) | **OpenSearch** (default) |
| Web UI | Sguil, Squert, Snorby, Kibana | **SOC** interface + Kibana | **SOC** interface + OpenSearch Dashboards |
| Query language | ELSA / Kibana Lucene | Hunt (OQL) | **OQL** (Hunt/Alerts/Dashboards) |
| NIDS | Snort / Suricata | Suricata | Suricata |
| Protocol analysis | Bro | Zeek | Zeek |
| File analysis | — | Strelka | Strelka |
| Endpoint | OSSEC / Wazuh | Wazuh / Beats | **Elastic Agent + Fleet** / osquery |
| Cases | Snorby / manual | **TheHive** integration | **Native Cases** |
| Detections mgmt | manual rule files | manual / partial | **Detections module** (Suricata+Sigma+YARA) |
| Connect API | — | — | **Yes (Pro)** |
| MCP server | — | — | **Yes, 2.4.160+ (Pro)** |
| Orchestration | packages/scripts | Docker + Salt | Docker + Salt |

---

## Security Onion 2.4 (current)

The current line. Assume this unless told otherwise.

- **OpenSearch** backend (SO moved off the Elastic license to OpenSearch as the default). Dashboards are
  OpenSearch Dashboards.
- **Elastic Agent + Fleet** for endpoint/log collection; osquery available.
- **Native Cases** — the built-in incident tracker (replaced the TheHive integration).
- **Detections module** — unified management of Suricata (NIDS), Sigma (ElastAlert 2), and YARA (Strelka).
- **Connect API** (Hydra) and the **MCP server** (2.4.160+) — Pro license only.
- Deployments and config are Docker + SaltStack managed.

Within 2.4, capabilities were added over point releases: MCP arrived at **2.4.160**; treat features as
present only from the release that introduced them.

---

## Security Onion 2.3

- **Elastic Stack** (Elasticsearch/Logstash/Kibana) backend.
- **SOC** interface with Hunt (OQL exists here) and Alerts.
- **TheHive/Cortex** for case management (integration, not native).
- **No Detections module**, **no Connect API/MCP**. Rule/detection management is more manual.
- Zeek + Suricata + Strelka + Wazuh/Beats.

OQL-style hunting works, but the Detections/Cases/MCP operator paths in this skill do not — route case
work to TheHive and rule work to the manual rule files.

---

## Legacy: Security Onion 1.x / 16.04 and earlier

The pre-2.0 architecture is fundamentally different:

- **Sguil** (real-time alert console), **Squert** (web alert triage), **ELSA** then Kibana for logs,
  **CapME** for PCAP, **Snorby** (older).
- **Snort or Suricata** for NIDS, **Bro** (pre-rename Zeek) for protocol analysis.
- **No SOC interface, no OQL, no Detections module, no Cases, no Connect API/MCP.**

Investigate via Sguil/Squert/Kibana and raw Bro logs. None of the OQL/MCP/Detections operator workflows
apply — this skill's value on legacy grids is conceptual (triage/hunt method), not tooling.

---

## Editions: Community vs Pro/Enterprise

Security Onion is **free and open source** — the full platform (NSM, IDS, Zeek, OpenSearch, Detections,
Cases, Hunt) is available at no cost in the **Community** edition. A paid **Pro license** from Security
Onion Solutions adds enterprise features and support.

| | Community (free) | Pro / Enterprise (licensed) |
|---|---|---|
| Full NSM/SIEM platform | ✅ | ✅ |
| SOC UI, Hunt/OQL, Alerts, Cases, Detections | ✅ | ✅ |
| **Connect API (Hydra)** | ❌ | ✅ |
| **MCP server** (needs Connect API) | ❌ | ✅ |
| Premium threat-intel feeds | ❌ | ✅ |
| Official support / SLAs, appliances, training | ❌ | ✅ |

**Operator consequence:** the MCP and Connect API only work on a **Pro** grid. On Community, drive the
grid through the **SOC UI** and the **manager CLI** (`references/cli-grid-management.md`) — everything in
this skill still applies except the API/MCP transport.

---

## Deployment & node types

Security Onion scales from a laptop to a distributed grid. Types you'll encounter:

| Type | Role |
|---|---|
| **Import** | Single box for offline PCAP/EVTX import & analysis (no live capture) |
| **Eval** | Single box, evaluation/testing — all components, low performance |
| **Standalone** | Single production box: manager + sensor + search on one node |
| **Manager** | Central management, config (salt), UI — no local search/capture |
| **Manager+Search** | Manager plus local search/indexing |
| **Search node** | Adds OpenSearch/Elastic indexing & storage capacity |
| **Forward node / Sensor** | Captures traffic (Zeek/Suricata/Steno), forwards to manager |
| **Heavy node** | Sensor that also stores/indexes locally |
| **Receiver** | Buffers/queues ingest (Redis/Kafka) for scale |
| **Fleet** | Elastic Agent/Fleet management for endpoints |
| **IDH** | Intrusion Detection Honeypot node |

Where you run a command matters: PCAP lives on **sensors**, indices on **search nodes**, salt/UI/API on the
**manager**.

---

## How to identify the grid you're on

```bash
so-status                       # 2.x only — if this exists you're on 2.x
cat /etc/soversion 2>/dev/null  # explicit version
sudo salt-call grains.get role  # this node's role
```
- SOC UI present + OQL Hunt → 2.3 or 2.4. **Detections module + Cases** in the left nav → **2.4**.
- OpenSearch Dashboards (not Kibana) → 2.4. Kibana → 2.3.
- Sguil/Squert → legacy 1.x/16.04.
- API Clients screen present + Hydra enabled → Pro with Connect API (MCP possible).

---

## Operator implications

- **Confirm generation before prescribing.** OQL, Detections, Cases, MCP = 2.4-centric.
- **Confirm edition before reaching for the API/MCP.** No Connect API on Community → use UI/CLI.
- **Confirm the point release for new features** (e.g. MCP ≥ 2.4.160).
- **Know your node roles** so you run commands and retrieve PCAP on the right box.

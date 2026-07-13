# **CyberHawk Threat Intel**

<p align="center">
  <img src="https://media.cyberhawkthreatintel.com/general/1771234479938-y9566.png" alt="CyberHawk Threat Intel" width="160"/>
</p>

<h1 align="center">security-onion</h1>
<p align="center">
  <strong>By <a href="https://www.cyberhawkthreatintel.com">CyberHawk Threat Intel</a></strong> · Rudra Verma | Senior Cyber Security Architect & Researcher
</p>

<p align="center">
  <em>A full operator skill for Security Onion — fetch alerts, investigate, hunt, pivot to PCAP, open cases, and write detections, straight from Claude.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Security%20Onion-2.4%20%7C%202.3%20%7C%20Legacy-16a34a?style=flat-square" alt="Security Onion"/>
  <img src="https://img.shields.io/badge/Engines-Suricata%20%7C%20Zeek%20%7C%20Sigma%20%7C%20YARA-0066cc?style=flat-square" alt="Engines"/>
  <img src="https://img.shields.io/badge/MCP-Operator%20Ready-8B5CF6?style=flat-square" alt="MCP Operator"/>
  <img src="https://img.shields.io/badge/Claude%20Code-Skill-8B5CF6?style=flat-square" alt="Claude Code Skill"/>
  <img src="https://img.shields.io/badge/by-CyberHawk%20Threat%20Intel-0066cc?style=flat-square" alt="CyberHawk"/>
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/References-10%20Files-green?style=flat-square" alt="References"/>
</p>

---

## ⚡ Install in one command

```bash
npx skills add rudraverma/security-onion-skill
```

That's it. The skill drops into `~/.claude/skills/security-onion/` and Claude picks it up automatically the
next time you mention Security Onion, an alert, a hunt, or a detection. No config, no build step.

<details>
<summary><strong>Manual / offline install</strong> (air-gapped SOC, no npx)</summary>

```bash
# Clone into your Claude skills directory
git clone https://github.com/rudraverma/security-onion-skill \
  ~/.claude/skills/security-onion

# Windows (PowerShell)
git clone https://github.com/rudraverma/security-onion-skill `
  "$env:USERPROFILE\.claude\skills\security-onion"
```

The skill is pure Markdown (`SKILL.md` + `references/`) — nothing to compile. Restart Claude Code (or your
IDE extension) and it's live.
</details>

---

## What Is This

**security-onion** is a [Claude Code](https://claude.ai/code) skill that turns Claude into a hands-on
**Security Onion operator** — not a documentation lookup, an analyst that actually works the grid.

Say *"check the alerts on CYBERHAWK-PC"* and Claude will pull the alerts, rank them by severity, walk the
investigation playbook, pivot into Zeek connection/DNS/TLS logs and full PCAP, reach a verdict, and offer
to open a case and author a detection so it's caught automatically next time.

It drives the official **[Security Onion MCP server](https://github.com/Security-Onion-Solutions/securityonion-mcp)**
(`query_events`, `get_playbook_questions`, `ping`) when it's connected, and falls back cleanly to the
**Connect REST API** or the **manager CLI** when it isn't — so it's useful on every grid, Community or Pro.

> **Who is this for?** SOC analysts, threat hunters, incident responders, and blue teams running Security
> Onion who want AI that speaks OQL, knows the Zeek/Suricata field taxonomy cold, and writes real Suricata,
> Sigma, and YARA detections — without hallucinating fields or query syntax.

---

## What Claude Can Do With It

| Capability | Example ask |
|---|---|
| **Fetch & triage alerts** | *"What alerts fired on CYBERHAWK-PC in the last 24h?"* |
| **Playbook-driven investigation** | *"Investigate alert `a1b2c3…` and give me a verdict."* |
| **Write OQL** | *"Show me every host that made DNS queries to `.onion` domains this week."* |
| **Threat hunt** | *"Hunt for C2 beaconing over HTTPS across the grid."* |
| **Pivot to PCAP** | *"Pull the packets for 10.100.70.50 → 203.0.113.10:443 and tell me what's in them."* |
| **Author detections** | *"Turn this beacon into a Suricata rule and a Sigma rule."* |
| **Tune false positives** | *"This NIDS rule is noisy from our scanner box — suppress it safely."* |
| **Escalate to a case** | *"Open a case for this with the IOCs and the timeline."* |
| **Grid health** | *"Why did ingest stop? Check the grid."* |

---

## Operator Loop

Every alert-driven task follows the same arc the skill encodes:

```
FETCH → TRIAGE → INVESTIGATE → PIVOT (PCAP/host) → VERDICT → ACTION (case + detection) → TUNE
```

Claude leads with the **decision and the evidence** (the OQL it ran, the packets it read), not a raw event
dump — and it confirms before any state change (opening a case, deploying a detection, acknowledging an
alert).

---

## Three Ways to Reach the Grid

The skill auto-detects your control plane and uses the best available:

| Path | When | What it uses |
|---|---|---|
| **MCP server** *(preferred)* | The `securityonion` MCP is connected (Pro + Connect API) | `query_events`, `get_playbook_questions`, `ping` |
| **Connect REST API** | Pro license, Hydra enabled, you have client ID/secret | OAuth2 + `curl` over `/connect/*` |
| **Manager CLI** | You have SSH to the manager (works on free Community) | `so-*` commands + SaltStack |

> **Pro vs Community:** the Connect API and MCP are **Pro/Enterprise** features. On the free **Community**
> edition, the skill operates through the **SOC UI** (Claude writes OQL you paste into Hunt) and the
> **manager CLI**. Everything in the skill still applies — only the transport changes.

---

## Connecting the Security Onion MCP (Pro grids)

If you have a Pro grid with the Connect API enabled, wire up the official MCP so Claude can query it live:

```bash
# 1. Install the MCP server
git clone https://github.com/Security-Onion-Solutions/securityonion-mcp
cd securityonion-mcp
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 2. Create an API Client in SOC → Administration → API Clients
#    Grant: events/read, playbooks/read  (add detections/read as needed)

# 3. Register it with Claude Code (one command)
claude mcp add securityonion -s user \
  -e SO_CLIENT_ID=YOURCLIENT \
  -e SO_CLIENT_SECRET=YOURSECRET \
  -e SO_API_ENDPOINT=https://yourmanager \
  -e SO_API_VERIFY_SSL=true \
  -- /path/to/securityonion-mcp/venv/bin/python /path/to/securityonion-mcp/security_onion_server.py
```

Then just ask Claude to *"ping Security Onion"* to confirm the connection. Full details, the Claude Desktop
JSON config, and every operator recipe are in [`references/mcp-operator.md`](references/mcp-operator.md).

> Requires Security Onion **2.4.160+** (MCP support), a **Pro license**, and the **Hydra** feature enabled.

---

## Coverage — Every Security Onion Generation

| Generation | Backend | UI / Query | This skill |
|---|---|---|---|
| **2.4.x** (current) | OpenSearch | SOC + OQL, **Detections**, **Cases**, **Connect API/MCP** | ✅ Full operator |
| **2.3.x** | Elastic Stack | SOC + OQL, TheHive cases | ✅ Hunt/triage (no MCP/Detections module) |
| **Legacy 1.x / 16.04** | ELSA → Elastic | Sguil / Squert / Kibana | ✅ Method & triage (no OQL/MCP) |

The skill confirms which generation and edition you're on before prescribing a workflow — no handing a 2.4
OQL/Detections answer to a legacy grid. See [`references/versions-editions.md`](references/versions-editions.md).

---

## Auto-Trigger

The skill activates automatically — you don't invoke it — whenever your message involves:

- **Security Onion**, SO, the SOC console, a grid, a sensor
- **Alerts / triage / investigate**, "check alerts", "what fired"
- **OQL / Onion Query Language / Hunt / Dashboards**
- **Suricata / NIDS**, **Zeek / Bro**, **Strelka / YARA**, **Sigma / ElastAlert** detections
- **PCAP**, packet capture, the Cases module
- Writing or **tuning a detection**, **threat hunting**, **beaconing / exfil / lateral movement** hunts

You can also force it with the `/security-onion` slash command.

---

## What's Inside

```
security-onion/
├── SKILL.md                              # Operator brain — the loop, OQL essentials, routing
├── README.md                             # This file
├── LICENSE                               # Apache 2.0
└── references/
    ├── oql-query-language.md             # Full OQL: syntax, tags, ECS fields, pipes, time, cookbook
    ├── mcp-operator.md                   # Driving the MCP: tools, install, config, recipes, limits
    ├── alerts-triage.md                  # Alert queue workflow: rank, investigate, verdict, route
    ├── hunting.md                        # ATT&CK-driven hunt library: C2, exfil, lateral movement
    ├── detections.md                     # Author/tune Suricata, Sigma, YARA — lifecycle & checklist
    ├── zeek-suricata-fields.md           # Field taxonomy for conn/dns/http/ssl/files/x509 + Suricata
    ├── cases-pcap.md                     # Cases module + PCAP retrieval and reading (tshark)
    ├── connect-api.md                    # No-MCP path: Connect REST API over OAuth2 + curl
    ├── cli-grid-management.md            # Manager shell: so-* commands, salt, sensor/grid health
    └── versions-editions.md              # Every generation, editions, deployment/node types
```

| File | Read it when |
|---|---|
| `references/oql-query-language.md` | Writing or debugging any OQL query; field/tag lookup |
| `references/mcp-operator.md` | The MCP is connected and you're driving `query_events`/playbooks |
| `references/alerts-triage.md` | Triaging the alert queue, ranking, false-positive workflow |
| `references/hunting.md` | Proactive hunts, hypotheses, ATT&CK-driven OQL hunt library |
| `references/detections.md` | Writing/tuning Suricata, Sigma, or YARA detections |
| `references/zeek-suricata-fields.md` | Field names for Zeek logs and Suricata alerts |
| `references/cases-pcap.md` | Escalating to a Case, retrieving and reading full PCAP |
| `references/connect-api.md` | No MCP — driving the grid over the Connect REST API |
| `references/cli-grid-management.md` | Manager shell operations and grid health |
| `references/versions-editions.md` | Version/edition differences, deployment & node types |

---

## Example Session

> **You:** Check the alerts on CYBERHAWK-PC and investigate anything high severity.
>
> **Claude:** *Reachable via the `securityonion` MCP.* Pulling alerts for the last 24h…
> 3 alerts — 1 `high` (`ET MALWARE JS/Agent CnC Checkin`), 2 `low` (policy). The high one repeats every
> ~10 min — beacon-like. Running the playbook:
> - DNS: host resolved `cdn-verify[.]top` just before each connection (rare TLD, newly seen)
> - Conn: 14 connections to `203.0.113.10:443`, ~2 KB each, fixed interval → classic beacon
> - TLS: JA3 `a0e9f5d64349fb13191bc781f81f42e1` — known malware client fingerprint
>
> **Verdict: true positive, C2 beacon.** Recommend: open a Case (IOCs below), and I've drafted a Suricata
> rule (JA3 + DNS indicator) and a Sigma rule. Want me to open the case and stage the detections?

---

## Disclaimer

This skill is for **authorized defensive security operations** on Security Onion grids you own or are
authorized to monitor. Security Onion is a defensive NSM/SIEM platform; all actions (querying events,
reading PCAP, writing detections) are blue-team operations. *Authorized security research & penetration
testing only. Unauthorized use is illegal.*

---

## Connect with CyberHawk Threat Intel

<p align="center">
  <a href="https://www.cyberhawkthreatintel.com">
    <img src="https://media.cyberhawkthreatintel.com/general/1771234479938-y9566.png" alt="CyberHawk Threat Intel" width="120"/>
  </a>
</p>

<p align="center">
  <strong>🦅 Sign up FREE → <a href="https://www.cyberhawkthreatintel.com">cyberhawkthreatintel.com</a></strong>
</p>

<p align="center">
  <a href="https://youtube.com/@cyberhawkconsultancy">YouTube @cyberhawkconsultancy</a> ·
  <a href="https://youtube.com/@cyberhawkk">YouTube @cyberhawkk</a> ·
  <a href="https://tiktok.com/@cyberhawkthreatintel">TikTok</a> ·
  <a href="https://x.com/cyberhawkintel">X @cyberhawkintel</a> ·
  <a href="https://t.me/cyberhawkthreatintel">Telegram</a>
</p>

<p align="center">
  <em>Rudra Verma | Senior Cyber Security Architect & Researcher | CyberHawk Threat Intel</em><br/>
  <em>Authorized security research & penetration testing only. Unauthorized use is illegal.</em>
</p>

<p align="center">
  #cyberhawkthreatintel &nbsp;#cyberhawkconsultancy &nbsp;#cyberhawkk &nbsp;#cybersecurity &nbsp;#ethicalhacking &nbsp;#pentesting &nbsp;#redteam &nbsp;#threatintel &nbsp;#infosec
</p>

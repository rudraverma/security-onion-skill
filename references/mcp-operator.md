# Driving the Security Onion MCP Server

There are two MCP options. Prefer the **CyberHawk CE MCP** — it works on the **free Community Edition** and
is a full operator (read **and** write). The **official** MCP is read-oriented and needs a Pro license.

## Table of contents
1. [CyberHawk CE MCP (primary — 21 tools)](#cyberhawk-ce-mcp-primary--21-tools)
2. [Read vs write, and gating](#read-vs-write-and-gating)
3. [The 21 tools](#the-21-tools)
4. [CE-specific behaviors you must know](#ce-specific-behaviors-you-must-know)
5. [Operator recipes](#operator-recipes)
6. [Official Pro MCP (secondary)](#official-pro-mcp-secondary)

---

## CyberHawk CE MCP (primary — 21 tools)

- **Repo:** https://github.com/rudraverma/securityonion-CE-mcp · **Server name:** `securityonion`
- **How it works:** hybrid backend — **OpenSearch** (HTTPS `:9200`) for all reads/hunts, **SSH** (`so-*`
  + sudo, host-key pinned) for all writes/operations. No Connect API, no Pro license required.
- **Requirements:** Security Onion 2.4.x; OpenSearch reachable on 9200; a sudo-capable SSH account on the
  manager. Config via env (`SO_API_ENDPOINT`, `SO_OS_USER/PASSWORD`, `SO_SSH_HOST/USER/PASSWORD`,
  `SO_SSH_HOSTKEY`, `SO_API_VERIFY_SSL`) — secrets live only in an untracked `.env.local`.
- **Run `ping` first** each session to confirm both backends are healthy.

---

## Read vs write, and gating

- **Reads are safe** and need no confirmation: `ping`, `grid_status`, `query_events`, `get_alerts`,
  `get_alert_detail`, `pivot_connection`, `zeek_logs`, `hunt`, `list_indices`, `detections_status`,
  `agent_list`.
- **Writes are gated:** every write tool takes `confirm=False` by default (returns a dry-run/plan) and only
  mutates when `confirm=True`. Validate-before-apply (Suricata rules pass `so-suricata-testrule` first),
  `grid_command` is a hard allow-list, and results are **honest** — a non-zero exit / non-2xx returns
  `{ok:false, error, detail}`, never a fabricated success. **Always confirm a state change with the user
  before setting `confirm=True`.**

---

## The 21 tools

**Connectivity & meta**
- `ping()` — checks both backends (OpenSearch cluster health + `so-status` over SSH). Run first.
- `grid_status()` — `so-status` per-container health. Read-only.

**Read / hunt (OpenSearch)**
- `query_events(oql_query, start_time="-24h", end_time="now", limit=100, groupby_field=None)` — the
  workhorse. OQL (Lucene + `| groupby` / `| table` / `| sortby`) → OpenSearch DSL. Returns agg buckets when
  grouping, else trimmed hits. Auto-excludes `metadata.raw_index:"logs-soc-so"`.
- `get_alerts(host=None, min_severity=None, since="-24h", top=20)` — one-call triage: top `rule.name`
  buckets with count, top severity, first/last seen.
- `get_alert_detail(rule_name=None, alert_id=None, since="-24h", limit=20)` — representative raw alert docs.
- `pivot_connection(src_ip, dst_ip=None, since="-6h", limit=50)` — Zeek conn records + `log.id.uid`s.
- `zeek_logs(dataset, filter="*", since="-24h", limit=100)` — dataset ∈ conn/dns/http/ssl/files/x509/notice.
- `hunt(query, since="-7d", groupby=None, limit=100)` — wide-window OQL hunt.
- `list_indices(pattern="*", top=30)` — `_cat/indices` summarized.
- `detections_status()` — `so-detections-runtime-status`. `agent_list()` — Elastic Agent policies + status.

**PCAP**
- `pcap_retrieve(uid=None, src_ip=None, dst_ip=None, src_port=None, dst_port=None, start=None, end=None)` —
  exports full packets via `so-pcap-export <steno-query> <name>` → `/nsm/pcapout/<name>.pcap`. Supply a
  5-tuple (uid alone isn't usable with so-pcap-export).

**Detections — author/tune/deploy (WRITE, gated)**
- `suricata_add_rule(rule_text, confirm=False, activate=False)` — validate → deploy (see CE path below).
  Enforces a unique sid in **1000000–1999999**.
- `suricata_remove_rule(sid, confirm=False, activate=False)` — remove a local rule by sid.
- `suricata_tune(sid, action, params, confirm=False)` — `action` ∈ suppress/threshold/disable;
  `params.reason` required. Writes `/opt/so/conf/suricata/threshold.conf`.
- `sigma_deploy(sigma_yaml, confirm=False)` — validates title/level/logsource/detection/MITRE/FP; on CE
  returns the validated rule + SOC-UI steps if no clean programmatic path (honest, no fake success).
- `yara_deploy(yara_rule, confirm=False)` — compile-checks inside the Strelka backend container.

**Alerts & cases (WRITE, gated, CE semantics)**
- `acknowledge_alert(alert_id, escalate=False, confirm=False)` — CE has no simple ES ack field; reports the
  SOC-UI/app path honestly rather than faking a writeback.
- `case_create(title, severity, description, observables=[], confirm=False)` — a `so-case` index exists but
  is SOC-app-managed; returns a pre-filled case for the SOC UI (non-destructive).

**Agents & grid (WRITE, gated)**
- `agent_installer(os, policy=None, confirm=False)` — `so-elastic-agent-gen-installers` for windows/linux/macos.
- `grid_command(command, confirm=False, reason="")` — hard allow-list of `so-*` (restart/reload/status);
  destructive ones (`so-restart/-stop/-start`) require `confirm` + `reason`. Never an arbitrary shell.

---

## CE-specific behaviors you must know

- **OQL time:** relative (`-24h`,`-7d`,`-30m`), `now`, `today`, or `YYYY/MM/DD HH:MM:SS AM/PM`.
  **ISO-8601 is rejected.** `start_time`/`end_time` are separate args.
- **Suricata deploy path (2.4.x CE):** rule → `/opt/so/rules/nids/suri/local.rules` → **`so-rule-update`**
  (idstools-rulecat compiles it into the merged ruleset). `so-rule-update` has a `pidof` self-guard, so the
  tool waits out any in-flight update and verifies the merged ruleset rather than trusting the exit code.
  **Activation into the running Suricata is salt-gated** — pass `activate=True` to force it with
  `so-suricata-restart` (slow ~4–5 min, brief NIDS gap).
- **Validation gate:** `so-suricata-testrule <rule> <pcap>` — validity is read from `N rules failed == 0`,
  not the exit code (a tiny test pcap causes a harmless pcap-read error).
- **idstools quirk:** idstools-rulecat can silently drop a local rule with certain `metadata:` formatting
  even though Suricata itself accepts it — the tool reports `not_in_merged` honestly if that happens.

---

## Operator recipes

**Session start / health**
```
ping()                                  # both backends green?
get_alerts(top=10)                      # what's firing right now
```

**"Check alerts for HOST"**
```
query_events("tags:alert AND host.name:HOST | groupby rule.name event.severity_label", "-24h", "now")
```

**Investigate → pivot → PCAP**
```
get_alert_detail(rule_name="<rule>")                       # read the 5-tuple
pivot_connection(src_ip="SRC", dst_ip="DST")               # Zeek conn + uids
pcap_retrieve(src_ip="SRC", dst_ip="DST")                  # full packets on the manager
```

**Turn a finding into a detection (gated)**
```
suricata_add_rule(rule_text, confirm=False)                # validate (dry-run)
suricata_add_rule(rule_text, confirm=True)                 # deploy to merged ruleset
# add activate=True to make it live in the running engine now (slow restart)
```

**Tame a noisy rule** → `suricata_tune(sid, "suppress", {"ip":"...", "reason":"..."}, confirm=True)`.

**Onboard an endpoint** → `agent_installer("windows", confirm=True)` → hand the installer + token to the user.

---

## Official Pro MCP (secondary)

The official [Security-Onion-Solutions/securityonion-mcp](https://github.com/Security-Onion-Solutions/securityonion-mcp)
needs a **Pro license + Connect API (Hydra)** and exposes ~3 **read-only** tools: `ping`, `query_events`
(same OQL/time rules as above), and `get_playbook_questions(alert_id=<rule.uuid>, playbook_index=None)`
(structured investigation questions per alert type). It **cannot** write — route acknowledgement, cases, and
detection deploys to the SOC UI / Connect API / manager CLI (`references/connect-api.md`,
`references/cli-grid-management.md`). If both MCPs are somehow present, prefer the CyberHawk CE MCP for its
write surface; use `get_playbook_questions` from the official one for playbook-driven investigation when
available.

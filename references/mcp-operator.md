# Driving the Security Onion MCP Server

The official MCP server ([Security-Onion-Solutions/securityonion-mcp](https://github.com/Security-Onion-Solutions/securityonion-mcp))
gives an LLM direct, read-oriented access to a Security Onion grid over the **Connect API**. When it is
connected to this client, prefer it over everything else for fetching and investigating.

## Table of contents
1. [Requirements](#requirements)
2. [Tools exposed](#tools-exposed)
3. [Installation](#installation)
4. [Configuration / connecting to a client](#configuration--connecting-to-a-client)
5. [Operator recipes](#operator-recipes)
6. [Limits — what the MCP cannot do yet](#limits--what-the-mcp-cannot-do-yet)

---

## Requirements

- **Security Onion 2.4.160+** with a **Pro license** and the **Connect API (Hydra)** feature enabled.
  The Connect API is an enterprise feature; the free Community edition does **not** expose it, so the MCP
  cannot connect there. See `references/connect-api.md` for enabling it.
- **Python 3.12+** on the machine running the MCP.
- A **Connect API Client** (ID + secret) created in `SOC → Administration → API Clients`, granted at
  minimum `events/read` and `playbooks/read` (add `detections/read` if you'll read detections).

---

## Tools exposed

The server exposes three MCP tools:

| Tool | Arguments | Returns |
|---|---|---|
| `ping` | none | Connectivity/auth check. Run first to confirm the grid is reachable. |
| `query_events` | `oql_query` (str), `start_time` (opt), `end_time` (opt), `limit` (int, default 100), `groupby_field` (opt) | Filtered, field-reduced event results. Your workhorse. |
| `get_playbook_questions` | `alert_id` (the alert's **`rule.uuid`**), `playbook_index` (opt, 0-based) | `playbooks[]`, each with `name`, `description`, and `questions[]` (question, context, answer_sources, suggested_query, time_range) — the structured investigation plan for that alert type. |

Notes on `query_events`:
- **Time is two separate args** — `start_time` and `end_time`, not a single range. Both follow OQL time
  rules: relative (`-24h`, `-7d`), keywords (`now`, `today`), or slash-absolute
  (`YYYY/MM/DD HH:MM:SS AM/PM`). **Never ISO-8601** — it errors.
- `groupby_field` appends `| groupby <field>` to your query automatically. You can also just write the
  `| groupby ...` inline in `oql_query` — either works.
- `limit` caps returned events (default 100). Raise it for broad pulls, but prefer `groupby` to summarize.
- The server auto-appends `AND NOT metadata.raw_index:"logs-soc-so"` to exclude SOC's own index, and
  **filters event payloads** to a default field set — responses are already trimmed and token-cheap.
- `alert_id` for `get_playbook_questions` is the **`rule.uuid`** of the alert (not `soc_id`/`event.id`).

---

## Installation

```bash
git clone https://github.com/Security-Onion-Solutions/securityonion-mcp
cd securityonion-mcp

# Linux/macOS
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Windows
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

---

## Configuration / connecting to a client

The server reads configuration from environment variables:

| Variable | Purpose |
|---|---|
| `SO_CLIENT_ID` | Connect API client identifier |
| `SO_CLIENT_SECRET` | Connect API client secret |
| `SO_API_ENDPOINT` | Manager URL, e.g. `https://yourmanager` |
| `SO_API_VERIFY_SSL` | `true` / `false` — verify the manager's TLS cert |
| `SO_CA_CERT` | Path to a custom CA cert (optional) |
| `SO_ENABLE_FILE_LOGGING` | Log to `securityonion-mcp.log` (optional) |

### Claude Code (single-command style)

```bash
claude mcp add securityonion -s user \
  -e SO_CLIENT_ID=YOURCLIENT \
  -e SO_CLIENT_SECRET=YOURSECRET \
  -e SO_API_ENDPOINT=https://yourmanager \
  -e SO_API_VERIFY_SSL=true \
  -- /path/to/securityonion-mcp/venv/bin/python /path/to/securityonion-mcp/security_onion_server.py
```

### Claude Desktop / other MCP clients (JSON)

```json
{
  "mcpServers": {
    "securityonion": {
      "command": "/path/to/securityonion-mcp/venv/bin/python",
      "args": ["/path/to/securityonion-mcp/security_onion_server.py"],
      "env": {
        "SO_CLIENT_ID": "YOURCLIENT",
        "SO_CLIENT_SECRET": "YOURSECRET",
        "SO_API_ENDPOINT": "https://yourmanager",
        "SO_API_VERIFY_SSL": "true"
      }
    }
  }
}
```

On Windows the `command` is the venv's `python.exe` (e.g. `C:\...\securityonion-mcp\venv\Scripts\python.exe`).

---

## Operator recipes

### Confirm you're live
Call `ping`. If it fails, the client secret, endpoint, SSL trust, or the Hydra feature is the problem —
check `references/connect-api.md`.

### "Check alerts for HOST"
```
query_events(oql_query="tags:alert AND host.name:HOST | groupby rule.name event.severity_label",
             start_time="-24h", end_time="now")
```
Summarize: how many, which rules, highest severity, whether they cluster in time.

### Investigate one alert (playbook-driven)
1. Get the alert's `rule.uuid` (from the drill-down, or `tags:alert ... | table @timestamp rule.name rule.uuid`).
2. `get_playbook_questions(alert_id="<rule.uuid>")`.
3. For each returned question, run its `suggested_query` (or a refined one) via `query_events`, using the
   question's suggested `time_range` to set `start_time`/`end_time`.
4. Answer each question in plain language, then give a verdict.

### Pivot from an alert to the connection and PCAP
```
query_events(oql_query="tags:conn AND source.ip:SRC AND destination.ip:DST | table @timestamp source.port destination.port network.bytes network.protocol",
             start_time="-6h", end_time="now")
```
Then hand the 5-tuple + time to the PCAP workflow in `references/cases-pcap.md`.

### Scope a hunt across the grid
Run the hunt library queries from `references/hunting.md` through `query_events` with a wide window
(`start_time="-7d"` or `-30d`, `end_time="now"`); `groupby` to find the outlier, then drill in.

---

## Limits — what the MCP cannot do yet

The MCP is **read-oriented**. As of 2.4.160 it can query events and pull playbook questions. It **cannot**
acknowledge/escalate alerts, create or close cases, or enable/disable/deploy detections. The SO team notes
future releases "will likely bring more functionality, such as the ability to acknowledge alerts."

When an action is required, route to:
- **Connect API** (`references/connect-api.md`) — programmatic case/detection operations with the right
  write scopes (`cases/write`, `detections/write`).
- **SOC UI** — click-driven case creation, detection tuning, acknowledgement.
- **Manager CLI** (`references/cli-grid-management.md`) — grid/rule operations via `so-*` + salt.

Always tell the user which control plane you used for a state change, and confirm before making it.

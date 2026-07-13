# Onion Query Language (OQL) Reference

OQL is the query language of the Security Onion Console (SOC) Hunt, Alerts, and Dashboards interfaces,
and the language the MCP `query_events` tool speaks. It is **Lucene** for the filter, plus a pipeline of
post-processing **segments**.

## Table of contents
1. [Query shape](#query-shape)
2. [Lucene filter syntax](#lucene-filter-syntax)
3. [Tags — the fast filter](#tags--the-fast-filter)
4. [Common ECS fields](#common-ecs-fields)
5. [Pipeline segments](#pipeline-segments)
6. [Time ranges](#time-ranges)
7. [Query cookbook](#query-cookbook)
8. [Gotchas](#gotchas)

---

## Query shape

```
<lucene_query> [| <segment> [| <segment> ...]]
```

The part before the first `|` is a Lucene query that filters documents. Each `|` segment then transforms
the result set (group, sort, tabulate). Segments run left to right. Multiple `groupby` segments produce
multiple independent aggregation tables.

Examples:
```
destination.port:80 AND tags:conn | groupby network.protocol destination.port
tags:alert | groupby event.module | sortby count^
```

---

## Lucene filter syntax

| Pattern | Example | Meaning |
|---|---|---|
| Field match | `destination.ip:10.0.0.1` | Field equals value |
| Range | `http.status_code:[400 TO 499]` | Inclusive range |
| Phrase | `message:"login failed"` | Exact multi-word phrase |
| Wildcard `*` | `dns.query:*.onion` | Zero or more chars |
| Wildcard `?` | `host.name:web?` | Exactly one char |
| Boolean | `source.ip:10.0.0.1 AND destination.port:443` | AND / OR / NOT |
| Grouping | `(source.ip:10.0.0.1 OR source.ip:10.0.0.2) AND destination.port:80` | Parentheses |
| Existence | `_exists_:destination.ip` | Field is present |
| Negation | `NOT tags:conn` | Exclude |

Notes:
- `AND`, `OR`, `NOT` must be uppercase.
- Leading wildcards (`*.onion`) work but are slow on large indices — scope by time and tag first.
- Values with spaces or special chars must be quoted: `rule.name:"ET MALWARE Win32/Agent"`.

---

## Tags — the fast filter

Tags are pre-computed labels that stand in for verbose `event.dataset`/`event.module` clauses. Prefer a
tag; it's shorter and index-friendly.

| Category | Tags |
|---|---|
| **Protocol (Zeek)** | `conn`, `dns`, `http`, `http2`, `ssl`, `ssh`, `file`, `smb_files`, `smb_mapping`, `stun`, `dhcp`, `quic`, `tunnel`, `x509` |
| **Security** | `alert`, `notice`, `weird`, `dpd`, `auth` |
| **System / agents** | `elastic-agent`, `kafka`, `syslog`, `access`, `fleet_server`, `audit`, `application` |
| **Analysis / engines** | `strelka`, `zeek`, `suricata`, `so-kratos`, `so-hydra`, `software` |
| **ICS/OT** | `ics`, `bsap_ip_header` |

`tags:alert` is the single most important filter — it selects every fired detection (Suricata + Sigma +
YARA) regardless of engine.

---

## Common ECS fields

Security Onion normalizes to Elastic Common Schema (ECS). The fields you'll use most:

| Field | Meaning |
|---|---|
| `source.ip` / `destination.ip` | Connection endpoints |
| `source.port` / `destination.port` | Ports |
| `network.protocol` / `network.transport` | App proto (dns, http…) / L4 (tcp, udp) |
| `event.dataset` | e.g. `conn`, `dns`, `alert` |
| `event.module` | e.g. `zeek`, `suricata`, `strelka` |
| `event.severity_label` | `low` / `medium` / `high` / `critical` |
| `rule.name` / `rule.uuid` / `rule.category` | Detection identity |
| `host.name` | Sensor or endpoint hostname |
| `observer.name` | Sensor that saw the event |
| `dns.query.name` (a.k.a. `dns.query`) | Queried domain |
| `http.virtual_host` / `url.full` / `http.uri` | HTTP host / URL |
| `ssl.server_name` / `tls.server.ja3s` / `tls.client.ja3` | TLS SNI / JA3(S) |
| `file.mime_type` / `file.name` / `hash.md5` / `hash.sha256` | File metadata (Zeek files.log / Strelka) |
| `user.name` | Account (auth, endpoint) |
| `soc_id` / `@timestamp` | Document id / event time |

> Field names drift slightly across Zeek versions and SO releases (e.g. `dns.query` vs
> `dns.query.name`). If a field returns nothing, run a bare `tags:<proto>` query and inspect a document
> to confirm the exact field, or check `references/zeek-suricata-fields.md`.

---

## Pipeline segments

| Segment | Syntax | Effect |
|---|---|---|
| `groupby` | `\| groupby field1 field2` | Aggregate counts by one or more fields (a table). Repeat for multiple tables. |
| `sortby` | `\| sortby field` / `\| sortby field^` | Sort descending; append `^` for ascending. |
| `table` | `\| table field1 field2` | Return selected fields as a flat table (no aggregation). |

`groupby` is what turns a firehose into an answer: `tags:conn AND host.name:X | groupby destination.ip`
tells you *who host X talked to*, ranked by volume.

---

## Time ranges

`query_events` (and the Hunt date picker) accept:

- **Relative:** `-5m`, `-30m`, `-6h`, `-24h`, `-7d`, `-30d`
- **Keywords:** `now`, `today`
- **Absolute:** `YYYY/MM/DD HH:MM:SS AM/PM` — e.g. `2026/07/13 09:30:00 AM`

**Do not** use ISO-8601 (`2026-07-13T09:30:00Z`) — it is rejected. Convert to the slash format above.

Default to a bounded window (`-24h`) rather than "all time"; large windows are slow and noisy.

---

## Query cookbook

```
# Alert overview by severity and rule
tags:alert | groupby event.severity_label rule.name

# Everything a host triggered
tags:alert AND host.name:CYBERHAWK-PC | groupby rule.name

# Top external destinations for an internal host
tags:conn AND source.ip:10.100.70.50 | groupby destination.ip destination.port | sortby count

# DNS to suspicious TLDs
tags:dns AND (dns.query:*.onion OR dns.query:*.top OR dns.query:*.xyz) | groupby source.ip dns.query

# Rare TLS server names (possible C2 / newly-seen infra)
tags:ssl | groupby ssl.server_name | sortby count^

# JA3 hunting — cluster clients by TLS fingerprint
tags:ssl | groupby tls.client.ja3 ssl.server_name

# Large outbound transfers (exfil hunt)
tags:conn AND network.transport:tcp | groupby source.ip destination.ip | sortby network.bytes

# HTTP to raw IPs (no Host resolution — beaconing / staging)
tags:http AND NOT _exists_:http.virtual_host | groupby destination.ip url.full

# Files Strelka scanned, by type
tags:strelka | groupby file.mime_type | sortby count

# Suricata alerts only, by category
tags:alert AND event.module:suricata | groupby rule.category rule.name
```

---

## Gotchas

- **ISO-8601 time is rejected** — use relative/slash formats.
- **Uppercase booleans** — `and`/`or` are treated as search terms, not operators.
- **Leading wildcards are slow** — always scope by `tags:` and a time window first.
- **Counts, not rows** — `groupby` returns aggregated counts; use `table` when you need individual events.
- **Field mismatch returns empty, not an error** — an empty result often means a wrong field name, not
  "no data". Verify the field against a sample document.
- **Case sensitivity** — keyword fields (IPs, `rule.name`) are exact; analyzed text fields may tokenize.

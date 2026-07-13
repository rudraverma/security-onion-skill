# Threat Hunting on Security Onion

Proactive hunting is looking for evil the detections *didn't* alert on. It's hypothesis-driven: form a
theory about attacker behavior, express it as OQL over Zeek/Suricata/host data, and chase the outliers.

## Table of contents
1. [The hunt loop](#the-hunt-loop)
2. [Where the data lives](#where-the-data-lives)
3. [ATT&CK-driven hunt library (OQL)](#attck-driven-hunt-library-oql)
4. [Beaconing / C2 hunts](#beaconing--c2-hunts)
5. [Exfiltration hunts](#exfiltration-hunts)
6. [Lateral movement hunts](#lateral-movement-hunts)
7. [From hunt hit to detection](#from-hunt-hit-to-detection)

---

## The hunt loop

```
HYPOTHESIS → SCOPE (data + time) → QUERY (OQL, groupby) → FIND OUTLIER → INVESTIGATE → DECIDE
```

A good hypothesis is specific and falsifiable: *"An attacker with a foothold is beaconing to C2 over
HTTPS on a fixed interval"* → hunt for low-variance connection timing to rare TLS destinations. A bad
hypothesis ("find anything weird") produces noise.

Hunt over **wider windows** than triage (`-7d`, `-30d`) — beacons and slow exfil hide in short windows.
Use `groupby` to collapse the firehose, then find the row that doesn't belong (rare, or anomalously
large/frequent).

---

## Where the data lives

| Signal | Tag / dataset | Hunt value |
|---|---|---|
| Connections | `tags:conn` | Who-talked-to-whom, bytes, duration — the backbone of most hunts |
| DNS | `tags:dns` | DGA, DoH, tunneling, rare TLDs, newly-seen domains |
| HTTP | `tags:http` | User-agents, URIs, raw-IP hosts, staging URLs |
| TLS | `tags:ssl` | JA3/JA3S, rare SNIs, self-signed certs, cert anomalies |
| Files | `tags:file` / `tags:strelka` | Extracted files, hashes, MIME types |
| x509 | `tags:x509` | Certificate issuers/subjects, validity anomalies |
| Alerts | `tags:alert` | Correlate hunt hits with what did fire |
| Host/endpoint | `event.module:*` (Elastic Agent/osquery) | Process, user, persistence context |

---

## ATT&CK-driven hunt library (OQL)

Run these through `query_events` (MCP) or the Hunt UI. Tune field names to your Zeek version if empty.

```
# T1071.001 Web C2 — HTTP to raw IPs (no Host header)
tags:http AND NOT _exists_:http.virtual_host | groupby destination.ip url.full | sortby count

# T1071.004 DNS C2 — high query volume from one host to one domain
tags:dns | groupby source.ip dns.query | sortby count

# T1568.002 DGA — many unique NXDOMAIN-ish lookups per host
tags:dns AND dns.response_code:NXDOMAIN | groupby source.ip | sortby count

# T1573 rare TLS destinations — possible custom C2 infra
tags:ssl | groupby ssl.server_name | sortby count^

# T1095 non-standard ports carrying app protocols
tags:conn AND NOT destination.port:(80 OR 443 OR 53) | groupby destination.port network.protocol | sortby count

# T1105 ingress tool transfer — executables pulled over HTTP
tags:file AND file.mime_type:*executable* | groupby source.ip destination.ip file.name

# T1046 internal scanning — one host hitting many internal peers
tags:conn AND destination.ip:10.0.0.0/8 | groupby source.ip | sortby count
```

---

## Beaconing / C2 hunts

Beacons betray themselves through **regularity** and **rare destinations**.

1. **Find rare external destinations:**
   ```
   tags:conn AND NOT destination.ip:10.0.0.0/8 | groupby destination.ip | sortby count^
   ```
   The *low-count, persistent-over-days* destinations are suspicious — a beacon makes few connections but
   keeps coming back.
2. **Confirm periodicity:** pull the timestamps for the suspect pair and look for fixed intervals:
   ```
   tags:conn AND source.ip:SRC AND destination.ip:DST | table @timestamp network.bytes destination.port
   ```
   Even jitter tends to cluster around a base interval.
3. **Fingerprint the client:** `tags:ssl AND source.ip:SRC | groupby tls.client.ja3` — a JA3 shared by
   many unrelated destinations, or matching a known malware JA3, is a strong signal.
4. **Check the DNS that preceded it:** rare/algorithmic domain just before the connections.

---

## Exfiltration hunts

Exfil = **outbound bytes** to somewhere unusual.

```
# Biggest outbound talkers to external IPs
tags:conn AND NOT destination.ip:10.0.0.0/8 | groupby source.ip destination.ip | sortby network.bytes

# Upload-heavy sessions (client sent far more than it received)
tags:conn | table source.ip destination.ip source.bytes destination.bytes

# DNS tunneling — abnormally long/high-entropy query names
tags:dns AND dns.query:??????????????????????????* | groupby source.ip dns.query

# Cloud/paste exfil destinations
tags:ssl AND (ssl.server_name:*pastebin* OR ssl.server_name:*mega.nz OR ssl.server_name:*anonfiles*)
```

Contextualize against baseline — a backup server sending gigabytes at 2am may be normal; a workstation
doing it is not.

---

## Lateral movement hunts

```
# SMB from a workstation to many hosts (spread)
tags:smb_mapping | groupby source.ip destination.ip | sortby count

# New/unusual admin-share or RPC access
tags:conn AND destination.port:(445 OR 135 OR 3389 OR 5985) | groupby source.ip destination.ip

# Kerberos/NTLM auth anomalies (if endpoint logs indexed)
tags:auth | groupby source.ip user.name destination.ip
```

Look for a single source fanning out to many destinations on admin ports — the classic post-compromise
spread pattern.

---

## From hunt hit to detection

A hunt that finds something real should not stay a one-off query. Convert it:
- **Reproducible network pattern** → Suricata rule (fixed URI, JA3, DNS indicator).
- **Log/behavior pattern** → Sigma rule (the OQL condition becomes the Sigma `detection`).
- **File indicator** → YARA rule for Strelka.

See `references/detections.md`. Every good hunt either finds evil (→ Case + detection) or raises your
confidence that a technique isn't present — both are wins. Record the hunt and its outcome so it becomes a
repeatable, scheduled hunt.

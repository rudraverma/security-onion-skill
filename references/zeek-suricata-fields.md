# Zeek & Suricata Field Taxonomy

Investigation speed comes from knowing which log has the answer and what the field is called. Security
Onion normalizes Zeek and Suricata into ECS, but the underlying log structure still guides the hunt.

## Table of contents
1. [Zeek log types and what they answer](#zeek-log-types-and-what-they-answer)
2. [conn.log — the connection backbone](#connlog--the-connection-backbone)
3. [dns.log](#dnslog)
4. [http.log](#httplog)
5. [ssl.log & x509.log](#ssllog--x509log)
6. [files.log & Strelka](#fileslog--strelka)
7. [Other Zeek logs](#other-zeek-logs)
8. [Suricata alert fields](#suricata-alert-fields)
9. [ECS field-name cheatsheet](#ecs-field-name-cheatsheet)

---

## Zeek log types and what they answer

| Log | Tag | Answers |
|---|---|---|
| conn | `conn` | Who talked to whom, how long, how many bytes, which direction |
| dns | `dns` | What was resolved, response codes, record types |
| http | `http` | URIs, methods, user-agents, hosts, status codes |
| ssl | `ssl` | TLS SNI, versions, JA3/JA3S, cert chain refs |
| x509 | `x509` | Certificate subject/issuer/validity |
| files | `file` | Files seen on the wire, hashes, MIME types |
| ssh | `ssh` | SSH client/server versions, auth outcome |
| smb_mapping / smb_files | `smb_mapping` / `smb_files` | SMB share access, file ops |
| dhcp | `dhcp` | Lease assignments (IP ↔ MAC ↔ hostname) |
| notice | `notice` | Zeek's own notices (scan detection, etc.) |
| weird | `weird` | Protocol anomalies Zeek couldn't parse cleanly |
| software | `software` | Software/versions Zeek fingerprinted |

---

## conn.log — the connection backbone

Most hunts start or end here. Key fields (ECS names):

| Field | Meaning |
|---|---|
| `source.ip` / `destination.ip` | Endpoints |
| `source.port` / `destination.port` | Ports |
| `network.transport` | `tcp` / `udp` / `icmp` |
| `network.protocol` | App proto Zeek identified (`dns`, `http`, `ssl`…) |
| `network.bytes` / `source.bytes` / `destination.bytes` | Volume (total / c2s / s2c) |
| `network.packets` | Packet count |
| `connection.state` (a.k.a. `conn_state`) | `S0` (no reply), `SF` (normal), `REJ`, `RSTO`… |
| `event.duration` | Connection length |

`connection.state` is a quick triage tell: many `S0` from one host = scanning; long `SF` with high s2c
bytes = possible download/exfil.

---

## dns.log

| Field | Meaning |
|---|---|
| `dns.query` / `dns.query.name` | Queried name |
| `dns.answers` / `dns.resolved_ip` | Returned answers |
| `dns.response_code` (`rcode_name`) | `NOERROR`, `NXDOMAIN`… |
| `dns.question.type` (`qtype_name`) | `A`, `AAAA`, `TXT`, `NULL`… |

`TXT`/`NULL` heavy traffic or long high-entropy names → tunneling. High `NXDOMAIN` volume → DGA.

---

## http.log

| Field | Meaning |
|---|---|
| `http.method` | GET/POST/… |
| `url.full` / `http.uri` | Requested URL/URI |
| `http.virtual_host` / `destination.domain` | Host header |
| `user_agent.original` | Client UA (fingerprint / anomaly) |
| `http.response.status_code` | 200/302/404… |
| `http.request.body.bytes` / `http.response.body.bytes` | Payload sizes |

Missing `http.virtual_host` (raw-IP host) + odd UA + fixed URI = beaconing pattern.

---

## ssl.log & x509.log

| Field | Meaning |
|---|---|
| `ssl.server_name` | SNI (the requested hostname) |
| `tls.version` | Negotiated TLS version |
| `tls.client.ja3` / `tls.server.ja3s` | Client/server TLS fingerprints |
| `ssl.established` | Handshake completed? |
| (x509) `x509.subject.common_name` / `x509.issuer.common_name` | Cert subject/issuer |
| (x509) `x509.not_before` / `x509.not_after` | Validity window |

Self-signed certs, brand-new validity windows, and rare JA3/JA3S values are prime C2 tells. JA3 is a
cross-connection pivot — the same malware client keeps the same JA3 across destinations.

---

## files.log & Strelka

| Field | Meaning |
|---|---|
| `file.name` | Filename if known |
| `file.mime_type` | Detected type (`application/x-dosexec` = PE) |
| `hash.md5` / `hash.sha1` / `hash.sha256` | Hashes for reputation lookups |
| `file.bytes` / `file.size` | Size |
| `source.ip` / `destination.ip` | Transfer endpoints |

Strelka (`tags:strelka`) enriches extracted files — YARA matches, PE metadata, embedded IOCs. Pivot a
suspicious `hash.sha256` to threat intel and to a Case.

---

## Other Zeek logs

- **ssh:** `ssh.version`, client/server strings, `ssh.auth.success` — brute force / unusual clients.
- **smb_mapping / smb_files:** share paths, file operations — lateral movement, staging.
- **dhcp:** map an IP to a MAC/hostname at a point in time (attribution when IPs rotate).
- **weird / notice:** Zeek's own anomaly and notice framework output — cheap hunting signal.

---

## Suricata alert fields

| Field | Meaning |
|---|---|
| `rule.name` / `alert.signature` | Signature message (`msg`) |
| `rule.uuid` / `alert.signature_id` (SID) | Rule identity |
| `rule.category` / `alert.category` | Classtype/category |
| `event.severity` / `event.severity_label` | Priority |
| `rule.metadata.mitre_technique_id` | ATT&CK mapping (if in the rule) |
| `source.ip` / `destination.ip` / ports | The flagged flow |

Pivot a Suricata `rule.uuid`/SID to the Detections module to tune it, and to `tags:conn`/PCAP for the
underlying traffic.

---

## ECS field-name cheatsheet

When a "natural" field name returns nothing, try the ECS form (or vice-versa):

| You might type | Also try |
|---|---|
| `dns.query` | `dns.query.name` |
| `conn_state` | `connection.state` |
| `id.orig_h` / `id.resp_h` | `source.ip` / `destination.ip` |
| `id.orig_p` / `id.resp_p` | `source.port` / `destination.port` |
| `orig_bytes` / `resp_bytes` | `source.bytes` / `destination.bytes` |
| `ja3` | `tls.client.ja3` |
| `server_name` | `ssl.server_name` |
| `uri` | `http.uri` / `url.full` |

> If in doubt, run a bare `tags:<proto>` query, open one document, and read the actual field names your
> Zeek/SO version emits. Field naming shifts between Zeek and SO releases.

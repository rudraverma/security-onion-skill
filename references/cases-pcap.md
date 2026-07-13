# Cases & PCAP

Where investigations become records and where the raw truth lives. Cases turn a verdict into a tracked
incident; PCAP is the packet-level ground truth you pivot to when logs aren't enough.

## Table of contents
1. [The Cases module](#the-cases-module)
2. [Escalating an alert to a case](#escalating-an-alert-to-a-case)
3. [Building a case out well](#building-a-case-out-well)
4. [PCAP retrieval](#pcap-retrieval)
5. [Reading PCAP](#reading-pcap)
6. [The alert → PCAP → case pivot](#the-alert--pcap--case-pivot)

---

## The Cases module

Security Onion 2.4 has a **native Cases** system (it replaced the older TheHive integration used in 2.3).
A case aggregates: the triggering alert(s), analyst observations, attached evidence (events, PCAP,
files), comments, and status. It's the container an incident lives in from detection to closure.

Case elements:
- **Title / severity / status** (New → In Progress → Closed, with a resolution).
- **Observables / IOCs** — IPs, domains, hashes extracted from the investigation.
- **Attached events** — pin the specific alerts and Zeek/Suricata events that matter.
- **Comments / timeline** — the analyst narrative and actions taken.

Creating, updating, and closing cases are **state changes** — do them through the SOC UI, the Connect API
(`cases/write`), or the CLI, and confirm the action with the user first. The MCP's read tools don't create
cases.

---

## Escalating an alert to a case

From the SOC **Alerts** interface an analyst clicks **Escalate**, which spawns (or appends to) a case with
the alert attached. Programmatically, use the Connect API with `cases/write` scope
(`references/connect-api.md`).

When you escalate, carry the evidence with it:
- The alert `rule.name` / `rule.uuid` and severity
- The 5-tuple (`source.ip`, `destination.ip`, ports, protocol) and time window
- The Zeek corroboration (DNS/HTTP/TLS/file rows you already pulled)
- Any file hashes and their reputation
- The PCAP reference (or the extracted PCAP file)

---

## Building a case out well

A good case reads as a story a second analyst (or an auditor) can follow without you:

1. **Summary** — one paragraph: what happened, to which host, verdict, confidence.
2. **Timeline** — timestamped sequence (DNS at T0, connection at T0+2s, file transfer at T0+5s…).
3. **Evidence** — the OQL queries you ran and their key results; attach/pin the events.
4. **IOCs** — every IP/domain/hash, ready to push to MISP or block lists.
5. **Impact & scope** — which hosts touched, whether it spread (link the hunt).
6. **Actions & recommendations** — what was contained/tuned, what detection was added, what's left.

This maps cleanly onto a CTI/incident report — see the `offensive-reporting`/CTI workflows if you're
producing an external writeup.

---

## PCAP retrieval

Security Onion retains **full packet capture** (via Stenographer) on sensors, subject to disk/retention.
Full PCAP availability depends on the deployment (sensors with capture enabled and disk headroom).

- **SOC PCAP interface:** from an alert or event, the **PCAP** pivot pulls the packets for that flow/time
  directly in the UI.
- **CLI on the sensor:** `so-pcap` tooling / `sensoroni` jobs retrieve raw PCAP for a time+5-tuple.
- **Scope tightly:** always give PCAP retrieval an exact 5-tuple and a narrow time window — full-take
  capture is large.

To build the pivot, get the exact flow from `conn`:
```
tags:conn AND source.ip:SRC AND destination.ip:DST | table @timestamp source.port destination.port network.transport network.bytes
```
Then request PCAP for that 5-tuple over `@timestamp ± a few minutes`.

---

## Reading PCAP

Once you have the `.pcap`:

```bash
# Quick protocol/endpoint overview
tshark -r flow.pcap -q -z conv,tcp
tshark -r flow.pcap -q -z io,phs

# Follow an HTTP conversation
tshark -r flow.pcap -Y 'http' -T fields -e http.request.method -e http.host -e http.request.uri

# Extract TLS SNI / JA3 context
tshark -r flow.pcap -Y 'tls.handshake.type == 1' -T fields -e tls.handshake.extensions_server_name

# Carve transferred objects (HTTP)
tshark -r flow.pcap --export-objects http,./carved/
```

Look for: the actual C2 payload/URI, credentials in cleartext protocols, transferred file content, and
anything the logs summarized but didn't show. PCAP is where you *prove* the verdict.

---

## The alert → PCAP → case pivot

The canonical operator flow:

```
Alert (tags:alert)  →  Zeek corroboration (tags:conn/dns/http/ssl/file)
     →  PCAP for the exact 5-tuple + time  →  confirm payload/verdict
     →  Case (attach alert + events + PCAP + IOCs + narrative)
     →  Detection to catch recurrence  →  Hunt for spread
```

Each arrow narrows uncertainty. Don't open a case on a hunch and don't close one without the packet-level
or host-level confirmation when the stakes justify it.

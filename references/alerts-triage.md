# Alert Triage Workflow

How to work the Security Onion **Alerts** queue like a SOC analyst: pull, rank, decide, and route. This
is the day-to-day operator loop.

## Table of contents
1. [The triage mindset](#the-triage-mindset)
2. [Step 1 — Pull the queue](#step-1--pull-the-queue)
3. [Step 2 — Rank and cluster](#step-2--rank-and-cluster)
4. [Step 3 — Investigate a single alert](#step-3--investigate-a-single-alert)
5. [Step 4 — Reach a verdict](#step-4--reach-a-verdict)
6. [Step 5 — Route the outcome](#step-5--route-the-outcome)
7. [Alert states in Security Onion](#alert-states-in-security-onion)
8. [False-positive handling](#false-positive-handling)

---

## The triage mindset

An alert is a *hypothesis*, not a conclusion. Your job is to confirm or refute it with evidence and
decide what happens next. Every alert ends in exactly one of: **false positive**, **benign true positive**
(real but expected), or **true positive** (escalate). Never leave an alert un-verdicted.

Rank by **impact × confidence**, not by raw count. One `high`/`critical` on a crown-jewel host beats a
hundred `low` policy alerts.

---

## Step 1 — Pull the queue

```
tags:alert | groupby event.severity_label rule.name
```

Scope it as the request demands:
```
tags:alert AND host.name:CYBERHAWK-PC | groupby rule.name          # one host
tags:alert AND event.severity_label:(high OR critical)             # only what matters
tags:alert AND event.module:suricata | groupby rule.category       # one engine
```

Use a bounded time window (`-24h` for a shift, `-1h` for "what's happening now").

---

## Step 2 — Rank and cluster

Look for structure in the groupby output:
- **New rule names** you haven't seen fire before — highest curiosity.
- **Clusters** — many alerts on one `source.ip`/`host.name`, or the same rule across many hosts (worm/
  scan vs targeted).
- **Severity** — sort `high`/`critical` to the top.
- **Time bursts** — `| groupby rule.name` then check if they're spread out (steady beacon) or bunched
  (single event).

Pick the top candidate and commit to investigating it fully before moving on. Half-triaging ten alerts is
worse than fully resolving three.

---

## Step 3 — Investigate a single alert

1. **Get the alert identity and 5-tuple.**
   ```
   tags:alert AND rule.name:"<name>" | table @timestamp soc_id source.ip destination.ip destination.port rule.uuid
   ```
2. **Pull the playbook questions** (if MCP/Connect available): `get_playbook_questions(alert_id="<rule.uuid>")`
   — the `alert_id` is the alert's `rule.uuid`. These are curated per alert type — answer each one.
3. **Answer with OQL.** Typical questions and the queries that answer them:
   - *Is this host normally this chatty?* → `tags:conn AND source.ip:SRC | groupby destination.ip`
   - *What else did the peer touch?* → `tags:conn AND destination.ip:DST | groupby source.ip`
   - *Was there DNS first?* → `tags:dns AND source.ip:SRC | table @timestamp dns.query`
   - *What did the HTTP/TLS look like?* → `tags:http AND source.ip:SRC | table url.full http.method` /
     `tags:ssl AND source.ip:SRC | table ssl.server_name tls.client.ja3`
   - *Any files transferred?* → `tags:file AND source.ip:SRC | table file.name file.mime_type hash.sha256`
4. **Pivot to PCAP** for the exact 5-tuple + time if the grid retains full packet capture (see
   `references/cases-pcap.md`).
5. **Check the host side** — if Elastic Agent/osquery is deployed, correlate process/user context.

Build a short narrative: *host X resolved Y, connected to Z:443 with JA3 abc, transferred N bytes,
Strelka saw file F (sha256 …).* That narrative is your verdict's evidence.

---

## Step 4 — Reach a verdict

| Verdict | Meaning | Next step |
|---|---|---|
| **False positive** | Rule fired on benign traffic | Tune the rule (threshold/suppress/filter), document why |
| **Benign true positive** | Real match, but expected (admin tool, scanner, backup) | Suppress for that context; note it |
| **True positive** | Genuine malicious/suspicious activity | Escalate to a Case, contain, hunt for spread |

State the verdict explicitly and cite the queries/evidence that support it.

---

## Step 5 — Route the outcome

- **True positive →** open a **Case** with the alert(s), 5-tuple, PCAP reference, and narrative
  (`references/cases-pcap.md`). Then **hunt for lateral spread** (`references/hunting.md`) and consider a
  **detection** to catch recurrence (`references/detections.md`).
- **False / benign →** **tune** the detection so it stops crying wolf, and record the rationale.

Acknowledging/escalating alerts and creating cases are **state changes** — do them via the Connect API,
SOC UI, or CLI, and confirm the action with the user first.

---

## Alert states in Security Onion

In the SOC Alerts interface, alerts move through **New → Acknowledged → Escalated** (and can be grouped/
filtered). Acknowledging removes an alert from the active queue without deleting it; escalating pushes it
into a **Case**. These transitions are grid state changes — route them through an authorized write path,
not a read query.

---

## False-positive handling

Do **not** blanket-disable a rule to silence one benign source — that blinds the grid to real hits.
Instead:

- **Suricata (NIDS):** add a `threshold`/`suppress` scoped to the benign `source`/`destination`, or
  `modify` the rule. See `references/detections.md`.
- **Sigma:** add a **custom filter** scoped to the benign field values (user, host, path).
- **YARA/Strelka:** enable/disable only — if a YARA rule is chronically noisy, disable it and, if needed,
  replace with a tighter rule.

Always document: *what* you tuned, *why* it's safe, and *what* it might now miss.

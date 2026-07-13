# Connect REST API — Operating Without the MCP

When the MCP isn't installed but the grid has a **Pro license** with the **Connect API (Hydra)** enabled,
you can drive Security Onion directly over REST. This is also the path for **write** actions the MCP can't
do (cases, detections, acknowledgements).

## Table of contents
1. [Requirements & enablement](#requirements--enablement)
2. [Creating an API client](#creating-an-api-client)
3. [Authentication (OAuth2 client credentials)](#authentication-oauth2-client-credentials)
4. [Permission scopes](#permission-scopes)
5. [Core endpoints & recipes](#core-endpoints--recipes)
6. [Manager-of-managers (subgrids)](#manager-of-managers-subgrids)

---

## Requirements & enablement

The Connect API is an **enterprise (Pro) feature**. To turn it on:

1. Apply a **license key that includes the API feature**.
2. Enable the **Hydra** feature in `SOC → Administration → Configuration`.
3. **Synchronize the grid** to apply.

The free **Community** edition does not expose the Connect API — on Community, operate through the SOC UI
and the manager CLI (`references/cli-grid-management.md`) instead.

---

## Creating an API client

`SOC → Administration → API Clients → Add`. You receive a **client ID** and **client secret** (shown
once — store as secrets, never in a repo). Grant only the scopes the automation needs (least privilege).

---

## Authentication (OAuth2 client credentials)

Exchange client credentials for a bearer token (tokens expire after ~2 hours — refresh as needed):

```bash
BASE="https://yourmanager"

TOKEN=$(curl -s -u "$SO_CLIENT_ID:$SO_CLIENT_SECRET" \
  -d 'grant_type=client_credentials' \
  "$BASE/oauth2/token" | jq -r '.access_token')

# Sanity check
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/connect/info" | jq
```

Use `-u` (HTTP Basic with ID:secret) for the token request, then `Authorization: Bearer $TOKEN` on every
subsequent call. Add `--cacert $SO_CA_CERT` (or `-k` only in a trusted lab) for self-signed managers.

> Never place the client secret or token in a URL/query string — always the `Authorization` header.

---

## Permission scopes

Scopes are granular `resource/action` pairs assigned per client. Common ones:

| Scope | Grants |
|---|---|
| `events/read` | Query events/alerts (OQL) |
| `playbooks/read` | Read playbooks & investigation questions |
| `detections/read` / `detections/write` | Read / create-modify detections |
| `cases/read` / `cases/write` | Read / create-update-close cases |
| `jobs/read` / `jobs/write` | PCAP/hunt job read / create |

Assign read scopes for a triage/hunt client; add the matching `/write` scope only for a client that must
change grid state.

---

## Core endpoints & recipes

The exact paths are visible in the grid's **Interactive API** view (`SOC → Administration → Interactive
API`). Typical operator recipes:

```bash
H=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")

# Query events / alerts with OQL (equivalent of MCP query_events)
curl -s "${H[@]}" "$BASE/connect/events" \
  --data-urlencode 'query=tags:alert AND host.name:CYBERHAWK-PC | groupby rule.name' \
  --data-urlencode 'range=-24h'

# Read detections
curl -s "${H[@]}" "$BASE/connect/detections?query=enabled:true"

# Create a case (write scope) — CONFIRM with the user first
curl -s "${H[@]}" -X POST "$BASE/connect/cases" -d '{
  "title": "C2 beacon from CYBERHAWK-PC",
  "severity": "high",
  "description": "JA3 <x> to <dst>:443 at fixed interval; see attached events."
}'

# Add an observable/IOC to a case
curl -s "${H[@]}" -X POST "$BASE/connect/cases/<caseId>/observables" -d '{
  "value": "203.0.113.10", "type": "ip", "description": "C2 endpoint"
}'
```

> Endpoint paths vary slightly by SO release. Treat the **Interactive API** page on the actual grid as the
> source of truth, and confirm the resource paths there before scripting write actions.

Before any `POST`/`PUT`/`DELETE` (case create/close, detection deploy, ack), state exactly what will
change and get the user's go-ahead — these are grid state changes.

---

## Manager-of-managers (subgrids)

In a manager-of-managers deployment, target a specific subgrid by adding a `gridId` query parameter to the
API URL. Omit it to act on the local grid.

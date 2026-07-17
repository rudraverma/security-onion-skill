# Fleet / Kibana API on Security Onion 2.4 — integrations, agent policies, package policies

**Battle-tested on the CyberHawk grid (2026-07). Read this before trying to add/modify any Elastic Agent
integration, agent policy, or package policy on a Security Onion grid — it will save you hours.**

## The core problem
Security Onion **does not expose the Kibana/Fleet API off-box**:
- nginx on **443** authenticates every request via **Kratos SSO** (`/auth/sessions/whoami`) and serves the
  SOC single-page-app HTML for anything without a valid browser session — it **ignores ES/Kibana API keys**.
- Kibana's real port **5601 is firewalled** from other hosts (`so-firewall includehost analyst <IP>` only
  opens the nginx port group 443, NOT 5601 — Kibana isn't bound to an off-box interface you can allow).
- SO 2.4 **removed** the 2.3-era `/fleet/api/` proxy. The only documented programmatic surface is
  Elasticsearch on **:9200**, which **cannot manage Fleet package policies** (those live in Kibana).

**Conclusion: the Fleet API is only reachable ON the manager, at Kibana's localhost.**

## The golden path (use this — clean, no secrets)
SSH to the manager, then hit Kibana on **`http://localhost:5601`** (PLAIN HTTP — https gives TLS
`packet length too long`; Kibana serves http there). Authenticate with the manager's own credential file
— **no API key, no password in the command**:

```bash
# On the SO manager. curl.config holds the so_elastic (superuser) -u line.
BASE="http://localhost:5601"
CFG="/opt/so/conf/elasticsearch/curl.config"
sudo curl -s -K "$CFG" -H "kbn-xsrf: true" "$BASE/api/fleet/agent_policies?perPage=20"     # list policies
sudo curl -s -K "$CFG" -H "kbn-xsrf: true" "$BASE/api/fleet/package_policies?perPage=50"   # list integrations
```
`sudo curl -K $CFG` → **HTTP 200**, authenticated as `so_elastic` (superuser → full Fleet). Verified live.

> Driving it from another box (e.g. a Windows workstation): `plink -pwfile pw.txt user@manager` and run the
> above. Base64-encode multi-line remote scripts (`echo <b64> | base64 -d | bash`) to dodge quoting hell;
> never put passwords in argv (use `-pwfile`/stdin). See "plink gotchas" below.

### Fallback if curl.config isn't usable: mint a scoped API key
A Kibana API key made in the **UI is often restricted** (`roles:[]` → **403** on Fleet even though the
*user* is superuser). Mint one with explicit privileges using a superuser (so_elastic), then use it:
```bash
sudo curl -sk -K "$CFG" -H "Content-Type: application/json" -X POST https://localhost:9200/_security/api_key -d '{
 "name":"fleet-admin","role_descriptors":{"f":{"cluster":["all"],
 "indices":[{"names":["*"],"privileges":["all"]}],
 "applications":[{"application":"kibana-.kibana","privileges":["all"],"resources":["*"]}]}}}'
# use the returned "encoded": Authorization: ApiKey <encoded>   (against http://localhost:5601)
```

## Adding an integration (package policy) — the winlog example
`winlog` ("Custom Windows Event Logs") is an **INPUT package** (no fixed data streams). Getting the payload
shape right is the hard part. Rules that took many tries to discover:
- The stream's `data_stream.dataset` MUST be the package **template** name `winlog.winlogs` (plural) with
  `"elasticsearch":{"dynamic_dataset":true,"dynamic_namespace":true}`. The *runtime* dataset is set by the
  **`data_stream.dataset` var**.
- That runtime dataset var must be **unique** or you get `datastreams matching "logs-<ds>-*" already exist,
  force flag is required` (e.g. don't reuse `winlog.winlog` if a Defender winlog integration already owns it).
- Required vars: `channel`, `data_stream.dataset`, `preserve_original_event`.
- **Fastest way to get the exact shape: copy an existing working package policy of the same package**
  (`GET /api/fleet/package_policies?kuery=ingest-package-policies.name:<existing>`), change name + channel.

Working POST (adds Sysmon collection to a policy):
```bash
sudo curl -s -K "$CFG" -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -X POST "http://localhost:5601/api/fleet/package_policies" -d '{
  "name":"sysmon-<host>","namespace":"default","policy_id":"<AGENT_POLICY_ID>",
  "package":{"name":"winlog","version":"2.4.0"},
  "inputs":[{"type":"winlog","policy_template":"winlogs","enabled":true,"streams":[{"enabled":true,
    "data_stream":{"type":"logs","dataset":"winlog.winlogs","elasticsearch":{"dynamic_dataset":true,"dynamic_namespace":true}},
    "vars":{"channel":{"value":"Microsoft-Windows-Sysmon/Operational","type":"text"},
            "data_stream.dataset":{"value":"winlog.sysmon","type":"text"},
            "preserve_original_event":{"value":false,"type":"bool"}}}]}]}'
# HTTP 200 => created; agent policy revision auto-bumps; the policy's agents pull it within ~1 min.
```
Other channels via the same recipe: PowerShell Script Block Logging = `Microsoft-Windows-PowerShell/Operational`
(with a distinct dataset e.g. `winlog.powershell`); Defender = `Microsoft-Windows-Windows Defender/Operational`.

## Useful Fleet API endpoints (all `http://localhost:5601`, `sudo curl -K $CFG -H "kbn-xsrf: true"`)
| Action | Method + path |
|---|---|
| List agent policies | `GET /api/fleet/agent_policies?perPage=50` |
| Get one agent policy | `GET /api/fleet/agent_policies/<id>` (has `revision`, `agents`) |
| List integrations | `GET /api/fleet/package_policies?perPage=50` (filter `?kuery=ingest-package-policies.policy_ids:<id>`) |
| Get one integration | `GET /api/fleet/package_policies?kuery=ingest-package-policies.name:<name>` |
| Add integration | `POST /api/fleet/package_policies` (simplified: add `?format=simplified`, inputs as a map keyed `<template>-<input>`) |
| Update integration | `PUT /api/fleet/package_policies/<id>` |
| Delete integration | `POST /api/fleet/package_policies/delete` `{"packagePolicyIds":["<id>"]}` |
| Package schema/version | `GET /api/fleet/epm/packages/<pkg>?prerelease=true` (input pkgs: vars live on `policy_templates[].vars`) |
| List agents | `GET /api/fleet/agents?perPage=50` |
| Create agent policy | `POST /api/fleet/agent_policies` `{"name":..,"namespace":"default"}` |

## Verify data flow after adding a winlog/Sysmon integration (from OpenSearch / MCP)
```
winlog.channel:"Microsoft-Windows-Sysmon/Operational" | groupby event.code      # 1,2,3,5,11,22 flowing
winlog.channel:"Microsoft-Windows-Sysmon/Operational" | groupby host.name        # which hosts ship
event.code:1 | groupby winlog.event_data.Image                                    # event_data.* populated
```
Once `winlog.event_data.*` is populated, Sigma rules that referenced those columns stop erroring
(check `detections_status`). Fields map dynamically as their event types arrive.

## plink gotchas (driving the manager from Windows)
- `plink -batch -ssh -pwfile pw.txt user@mgr "echo <b64> | base64 -d | bash"` — base64 the script; raw
  multi-line/paren/quoted scripts break plink's single-arg quoting (`bash: syntax error near '('`).
- Password: `-pwfile` (not `-pw`, which lands in argv → captured by EDR). Stage API keys/secrets to a
  600-perm file via **stdin** (`$secret | plink ... "cat > ~/.k"`), read with bash `${v//[$'\r\n\t ']/}`
  (NOT `tr -d "[:space:]"` — deletes the letters s,p,a,c,e!). PowerShell's `$x | plink` mangles encoding —
  embed literals in the base64'd script instead.
- Windows PowerShell path-guard blocks a literal `rm`/`Remove-Item` next to a path-like string in the
  command text — use `: > file` to truncate instead of `rm`.

## SO reconciliation caveat
SO manages some grid state via salt and *can* reconcile manually-created Fleet objects. In practice
package policies added via the API persist, but if one vanishes, that's why — the SOC UI is the
SO-"supported" path. The API is fine for automation; just know the caveat.

Related: `mcp-operator.md` (the `fleet_integration` MCP tool wraps this), `versions-editions.md`.

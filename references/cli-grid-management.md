# Manager CLI & Grid Management

When you have shell access to the Security Onion **manager**, the `so-*` command family and SaltStack give
you full control of the grid — status, rules, sensors, and services. Use this path on the free Community
edition (no Connect API) or for grid operations the API/UI doesn't cover.

## Table of contents
1. [Orientation](#orientation)
2. [Status & health](#status--health)
3. [Grid & node management](#grid--node-management)
4. [Rules & detections from the CLI](#rules--detections-from-the-cli)
5. [Services (so-* control)](#services-so--control)
6. [Salt — configuration engine](#salt--configuration-engine)
7. [Logs & data locations](#logs--data-locations)
8. [Safety](#safety)

---

## Orientation

Security Onion 2.x is a **containerized, salt-managed** platform. Almost every component runs as a Docker
container orchestrated by SaltStack from the manager. The `so-*` scripts wrap common operations. Most
require `sudo`.

Confirm what you're on before acting:
```bash
so-status                 # overall grid/service status
sudo salt-call grains.get role   # this node's role (manager, searchnode, sensor…)
cat /etc/soversion 2>/dev/null    # SO version (or check SOC footer)
```

---

## Status & health

```bash
so-status                       # service/container health across the node
sudo salt '*' test.ping         # are all grid nodes responding to salt?
sudo salt-call state.highstate test=True   # dry-run: what would config sync change?
docker ps                       # running SO containers
df -h /nsm                      # /nsm disk — PCAP + logs live here; watch watermarks
free -h                         # memory pressure (OpenSearch/Elastic is hungry)
```

`/nsm` filling up is the single most common cause of ingest/PCAP/detection problems — check it first when
something "stopped working" (also surfaces as the Detections **Rule Mismatch** / disk-watermark state).

---

## Grid & node management

Deployment/node types (see `references/versions-editions.md` for the full map):

```bash
sudo so-status                  # per-node health
sudo salt-key -L                # list/accept minion (node) keys
so-monitor-add / so-sensor-*    # sensor lifecycle helpers (varies by version)
```

Common node roles: **manager**, **manager+search**, **search node**, **forward node/sensor**, **heavy
node**, **receiver**, **fleet**, **IDH** (intrusion detection honeypot), **import/eval/standalone** for
single-box deployments.

---

## Rules & detections from the CLI

```bash
# Update NIDS (Suricata) & other rulesets
sudo so-rule-update

# Local Suricata rules / tuning live under the manager's salt-managed config:
#   /opt/so/saltstack/local/salt/idstools/  (local rules)
#   /opt/so/saltstack/local/salt/suricata/  (suricata config/tuning)
# Sigma & YARA content is managed via the Detections module (SOC UI) / salt pillars.

# After editing salt-managed rule config, apply it:
sudo salt-call state.apply suricata     # (or the relevant state)
```

Prefer the **Detections module** (SOC UI / Connect API) for enable/disable/tune where possible — CLI edits
must be salt-applied and can be overwritten by a highstate if placed outside the `local/` tree.

---

## Services (so-* control)

```bash
so-status                       # what's up/down
sudo so-suricata-restart        # restart a specific service (pattern: so-<svc>-restart)
sudo so-zeek-restart
sudo so-elasticsearch-restart   # or so-opensearch-* on 2.4
sudo so-kibana-restart          # or so-dashboards-* on 2.4
sudo so-restart                 # restart the whole SO stack (disruptive)
```

Service script names track the component and the SO version (Elastic vs OpenSearch naming on 2.3 vs 2.4).
Run `ls /usr/sbin/so-*` to see what exists on the box.

---

## Salt — configuration engine

All persistent config changes should go through salt's `local/` tree so they survive a highstate:

```bash
sudo salt-call state.highstate            # apply full config to this node
sudo salt '*' state.highstate             # apply across the grid (manager)
# Local overrides live under:
#   /opt/so/saltstack/local/pillar/       (pillar data — feature toggles, values)
#   /opt/so/saltstack/local/salt/         (custom states / local rules)
```

Editing under `/opt/so/saltstack/default/` is wrong — it gets overwritten. Always use `local/`.

---

## Logs & data locations

| Path | Contents |
|---|---|
| `/nsm/` | The data root — PCAP, Zeek logs, Suricata logs, indices |
| `/nsm/pcap/` | Full packet capture (Stenographer) |
| `/nsm/zeek/logs/` | Zeek logs (current + archived) |
| `/nsm/suricata/` | Suricata eve.json / logs |
| `/opt/so/log/` | SO component logs |
| `/opt/so/saltstack/local/` | Your local config overrides |

---

## Safety

- `so-restart`, `salt '*' state.highstate`, and rule reloads are **disruptive** to a live grid — confirm
  with the user and prefer a maintenance window.
- Never edit under `default/` — use `local/`.
- Check `/nsm` free space before blaming a rule or ingest problem.
- Read-only status commands (`so-status`, `salt '*' test.ping`, `df -h`) are always safe — start there.

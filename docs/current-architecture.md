# Current Architecture

Final deployment uses BIND9 + RPZ Komdigi + Web GUI monitoring only.

```text
Clients / Routers / LAN
        |
        v
BIND9 Recursive Resolver + RPZ
103.55.253.253
        |
        v
Komdigi RPZ secondary zone: trustpositifkominfo
```

## Active Services

```text
named       active
rpz-monitor active
nginx       active
```

## RPZ Source

```text
zone: trustpositifkominfo
type: secondary
masters:
  - 139.255.196.202
  - 182.23.79.202
```

## Web GUI Scope

Monitoring only:

```text
Dashboard status
Domain RPZ check
QPS/history graphs
Munin-style graphs
Live logs
```

No zone edit, no RPZ CRUD, no Unbound exporter.

## Removed Plan

Unbound hybrid/exporter plan was rolled back because Komdigi RPZ is very large:

```text
nodes: 18M+
AXFR text export: ~1.5GB
local-zone generated config: ~2.9GB+
```

Loading full RPZ into Unbound caused high CPU/RAM/IO pressure on current VM specs.

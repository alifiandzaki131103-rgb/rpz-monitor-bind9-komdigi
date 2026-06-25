# BIND9 RPZ Production Notes

Current production plan uses BIND9 + Komdigi RPZ + Web GUI monitoring only.

## RAM 16GB tuning

Komdigi RPZ is large:

```text
nodes: 18M+
zone file: ~1.7GB
```

For a 16GB RAM target, keep resolver cache small because RPZ memory is the main consumer.

Recommended `options` values:

```conf
options {
    response-policy { zone "trustpositifkominfo"; };

    // Memory guard for 16GB RAM target. RPZ itself still needs large memory.
    max-cache-size 512M;
    recursive-clients 600;
    tcp-clients 100;
};
```

Notes:

```text
RPZ tree memory is not controlled by max-cache-size.
max-cache-size only limits resolver cache.
No swap inside unprivileged LXC unless Proxmox/host allows it.
```

## Query logging

Full query logging is expensive under high QPS. If user needs it, keep rotation small.

Recommended controlled query log:

```conf
logging {
    channel query_log {
        file "/var/cache/bind/query.log" versions 2 size 20m;
        severity info;
        print-time yes;
        print-category yes;
        print-severity yes;
    };
    channel rpz_log {
        file "/var/cache/bind/rpz.log" versions 5 size 100m;
        severity info;
        print-time yes;
        print-category yes;
        print-severity yes;
    };

    category queries { query_log; };
    category rpz { rpz_log; };
};
```

Runtime commands:

```bash
rndc querylog on
rndc reconfig
rndc status | grep "query logging"
```

If load/IO spikes, disable query logging again:

```bash
rndc querylog off
```

## Disable aggressive RRL behind dnsdist

If BIND is only a backend behind dnsdist, do not use very low BIND RRL like:

```conf
rate-limit { responses-per-second 10; window 5; };
```

Behind dnsdist, BIND sees many requests from the dnsdist IP, so low RRL can drop/slip legitimate pooled traffic and spam logs.

Use dnsdist for frontend rate limiting instead.

## Avoid full RPZ export to Unbound

Full AXFR text export is around 1.5GB, and generated Unbound local-zone config can reach 2.9GB+. This caused high CPU/RAM/IO pressure on current VM specs.

Keep Unbound/exporter disabled unless using large RAM and staged rolling reloads.

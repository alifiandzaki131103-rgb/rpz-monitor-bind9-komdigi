# BIND9 RPZ Production Notes

Current production plan uses BIND9 + Komdigi RPZ + Web GUI monitoring only.

## Disable full query logging

Do not keep BIND `category queries` enabled under high QPS. Full query logging causes disk IO and load spikes.

Recommended logging:

```conf
logging {
    channel rpz_log {
        file "/var/cache/bind/rpz.log" versions 5 size 100m;
        severity info;
        print-time yes;
        print-category yes;
        print-severity yes;
    };

    // category queries disabled in production.
    category rpz { rpz_log; };
};
```

Runtime command:

```bash
rndc querylog off
rndc reconfig
rndc status | grep "query logging"
```

## Disable aggressive RRL behind dnsdist

If BIND is only a backend behind dnsdist, do not use very low BIND RRL like:

```conf
rate-limit { responses-per-second 10; window 5; };
```

Behind dnsdist, BIND sees many requests from the dnsdist IP, so low RRL can drop/slip legitimate pooled traffic and spam logs.

Use dnsdist for frontend rate limiting instead.

## Memory note

Komdigi RPZ is large:

```text
nodes: 18M+
zone file: ~1.7GB
```

BIND `named` can use most of RAM while holding RPZ in memory. This is expected. Size VM accordingly and avoid extra heavy exports/conversions.

## Avoid full RPZ export to Unbound

Full AXFR text export is around 1.5GB, and generated Unbound local-zone config can reach 2.9GB+. This caused high CPU/RAM/IO pressure on current VM specs.

Keep Unbound/exporter disabled unless using large RAM and staged rolling reloads.

# RPZ Monitor - BIND9 Komdigi

Web GUI read-only untuk monitoring performa DNS BIND9 dan cek domain masuk RPZ Komdigi.

## Fitur

- Dashboard status BIND/named
- CPU, RAM, disk, load average
- BIND statistics-channel check
- RPZ zone status via `rndc zonestatus trustpositifkominfo`
- Estimasi jumlah record zone
- Domain checker: cek domain di file RPZ + `dig @127.0.0.1`
- Query log dan RPZ log viewer
- Login admin
- Tidak punya fitur edit/reload/write zone

## Arsitektur

```text
Client DNS -> BIND9 recursive resolver -> RPZ slave trustpositifkominfo
                                     -> query/rpz logs
                                     -> statistics-channel 127.0.0.1:8053
                                     -> RPZ Monitor FastAPI + Nginx
```

## Server RPZ Komdigi

```text
139.255.196.202
182.23.79.202
zone: trustpositifkominfo
```

## Requirement

```bash
apt update
apt install -y bind9 bind9utils bind9-dnsutils dnsutils nginx python3 python3-venv sqlite3 curl git
```

## Konfigurasi BIND

`/etc/bind/named.conf.options`:

```conf
acl "trusted_clients" {
    127.0.0.1;
    localhost;
    10.0.0.0/8;
    172.16.0.0/12;
    192.168.0.0/16;
    YOUR_DNS_PUBLIC_IP;
};

options {
    directory "/var/cache/bind";
    recursion yes;
    allow-recursion { trusted_clients; };
    allow-query { trusted_clients; };
    forwarders { 1.1.1.1; 8.8.8.8; };
    dnssec-validation auto;
    listen-on { any; };
    listen-on-v6 { none; };
    response-policy { zone "trustpositifkominfo"; };
    rate-limit { responses-per-second 10; window 5; };
};

statistics-channels {
    inet 127.0.0.1 port 8053 allow { 127.0.0.1; };
};

logging {
    channel query_log {
        file "/var/cache/bind/query.log" versions 5 size 100m;
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

`/etc/bind/named.conf.local`:

```conf
zone "trustpositifkominfo" {
        type slave;
        file "db.trustpositifkominfo";
        masters {
                139.255.196.202;
                182.23.79.202;
        };
        allow-query { none; };
        allow-transfer { 127.0.0.1; };
};
```

Validasi:

```bash
named-checkconf
systemctl restart named
rndc status
rndc zonestatus trustpositifkominfo
curl http://127.0.0.1:8053/xml/v3/server
```

Catatan: jika transfer `SERVFAIL`, biasanya IP public server belum approved di portal Komdigi.

## Install Web GUI

```bash
useradd --system --home /opt/rpz-monitor --shell /usr/sbin/nologin rpzmon || true
mkdir -p /opt/rpz-monitor/data
cp -r app requirements.txt /opt/rpz-monitor/
chown -R rpzmon:rpzmon /opt/rpz-monitor
cd /opt/rpz-monitor
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

Buat `.env`:

```bash
cat > /opt/rpz-monitor/.env <<'EOF'
SECRET_KEY=change-this-long-random
ADMIN_USER=admin
ADMIN_PASSWORD=change-this-password
DB_PATH=/opt/rpz-monitor/data/rpz-monitor.db
RPZ_ZONE=trustpositifkominfo
BIND_STATS_URL=http://127.0.0.1:8053/xml/v3/server
QUERY_LOG=/var/cache/bind/query.log
RPZ_LOG=/var/cache/bind/rpz.log
ZONE_FILE=/var/cache/bind/db.trustpositifkominfo
EOF
chown rpzmon:rpzmon /opt/rpz-monitor/.env
chmod 600 /opt/rpz-monitor/.env
```

## Systemd

`/etc/systemd/system/rpz-monitor.service`:

```ini
[Unit]
Description=RPZ Monitoring Web GUI
After=network.target named.service

[Service]
User=rpzmon
Group=rpzmon
WorkingDirectory=/opt/rpz-monitor
EnvironmentFile=/opt/rpz-monitor/.env
ExecStart=/opt/rpz-monitor/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Aktifkan:

```bash
systemctl daemon-reload
systemctl enable rpz-monitor
systemctl start rpz-monitor
systemctl status rpz-monitor
```

## Nginx

`/etc/nginx/sites-available/rpz-monitor`:

```nginx
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Aktifkan:

```bash
ln -sf /etc/nginx/sites-available/rpz-monitor /etc/nginx/sites-enabled/rpz-monitor
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx
```

Akses:

```text
http://SERVER_IP/
```

## Security checklist

- Ganti `ADMIN_PASSWORD`
- Ganti `SECRET_KEY`
- Batasi `allow-query` dan `allow-recursion` ke prefix pelanggan/internal
- Jangan jadi open resolver publik
- Pasang HTTPS jika pakai domain
- Setelah deploy, ganti password root server

## Troubleshooting

Cek BIND:

```bash
systemctl status named
journalctl -u named -n 100 --no-pager
named-checkconf
rndc status
rndc zonestatus trustpositifkominfo
```

Cek transfer Komdigi manual:

```bash
dig AXFR @139.255.196.202 trustpositifkominfo +noidnout
dig AXFR @182.23.79.202 trustpositifkominfo +noidnout
```

Cek Web GUI:

```bash
systemctl status rpz-monitor
journalctl -u rpz-monitor -n 100 --no-pager
curl http://127.0.0.1:8080/health
```

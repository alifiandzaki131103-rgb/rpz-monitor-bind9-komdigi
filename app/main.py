import asyncio, json, os, re, subprocess, sqlite3, time, xml.etree.ElementTree as ET
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path

import httpx, psutil
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware

APP_NAME = "RPZ Monitor"
DB_PATH = os.getenv("DB_PATH", "/opt/rpz-monitor/data/rpz-monitor.db")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
ZONE = os.getenv("RPZ_ZONE", "trustpositifkominfo")
STATS_URL = os.getenv("BIND_STATS_URL", "http://127.0.0.1:8053/xml/v3/server")
QUERY_LOG = os.getenv("QUERY_LOG", "/var/cache/bind/query.log")
RPZ_LOG = os.getenv("RPZ_LOG", "/var/cache/bind/rpz.log")
ZONE_FILE = os.getenv("ZONE_FILE", "/var/cache/bind/db.trustpositifkominfo")
APP_TZ = os.getenv("APP_TZ", "Asia/Jakarta")
TZ = ZoneInfo(APP_TZ)

app = FastAPI(title=APP_NAME)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=False)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def now_local():
    return datetime.now(TZ)

def now_iso():
    return now_local().isoformat()

def format_local(ts):
    try:
        return datetime.fromtimestamp(int(ts), TZ).strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return str(ts)

def localize_bind_time(value):
    if not value or value == "-":
        return value
    try:
        dt = datetime.strptime(value, "%a, %d %b %Y %H:%M:%S GMT").replace(tzinfo=ZoneInfo("UTC"))
        return dt.astimezone(TZ).strftime("%a, %d %b %Y %H:%M:%S %Z")
    except Exception:
        return value

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$", re.I)
LAST_SAMPLE = {"ts": 0.0, "dns": {}, "cpu": None}


def db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    con.executescript("""
    create table if not exists users(id integer primary key, username text unique, password_hash text, role text, enabled integer, created_at text);
    create table if not exists domain_checks(id integer primary key, domain text, in_rpz integer, matched_record text, dig_result text, checked_by text, checked_at text);
    create table if not exists audit_login(id integer primary key, username text, ip_address text, result text, created_at text);
    create table if not exists qps_metrics(id integer primary key, ts integer not null, qps real not null, queries integer not null, created_at text not null);
    create index if not exists idx_qps_metrics_ts on qps_metrics(ts);
    create table if not exists dns_metrics(
      id integer primary key, ts integer not null, total_qps real not null, cache_hit_qps real not null,
      rpz_hit_qps real not null, prefetch_qps real not null, nxdomain_qps real not null, servfail_qps real not null,
      total_queries integer not null, cache_hits integer not null, rpz_hits integer not null, prefetch integer not null,
      nxdomain integer not null, servfail integer not null, created_at text not null
    );
    create index if not exists idx_dns_metrics_ts on dns_metrics(ts);
    create table if not exists cpu_metrics(
      id integer primary key, ts integer not null, user real not null, system real not null, idle real not null,
      iowait real not null, nice real not null, irq real not null, softirq real not null, steal real not null, created_at text not null
    );
    create index if not exists idx_cpu_metrics_ts on cpu_metrics(ts);
    """)
    row = con.execute("select id from users where username=?", (ADMIN_USER,)).fetchone()
    if not row:
        con.execute("insert into users(username,password_hash,role,enabled,created_at) values(?,?,?,?,?)", (ADMIN_USER, pwd_context.hash(ADMIN_PASSWORD), "admin", 1, now_iso()))
    con.commit(); con.close()

init_db()


def require_login(request: Request):
    return request.session.get("user")


def run(cmd, timeout=5):
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        return p.stdout.strip() + (("\n" + p.stderr.strip()) if p.stderr.strip() else "")
    except Exception as e:
        return str(e)


def service_active(name="named"):
    out = run(["systemctl", "is-active", name])
    return out.splitlines()[0] if out else "unknown"


def rndc_status():
    return run(["/usr/sbin/rndc", "status"], 5)


def zonestatus():
    return run(["/usr/sbin/rndc", "zonestatus", ZONE], 5)


def parse_zonestatus(text):
    data = {"raw": text, "ok": False}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            data[key.strip().replace(" ", "_").lower()] = value.strip()
    data["ok"] = "serial" in data and "nodes" in data
    for k in ["last_loaded", "next_refresh", "expires"]:
        if k in data:
            data[k + "_local"] = localize_bind_time(data[k])
    return data


def system_metrics():
    return {"cpu": psutil.cpu_percent(interval=0.1), "mem": psutil.virtual_memory().percent, "disk": psutil.disk_usage("/").percent, "load": os.getloadavg()}


def save_metric(table, cols, vals):
    con = db()
    try:
        last = con.execute(f"select ts from {table} order by ts desc limit 1").fetchone()
        if not last or int(vals[0]) > int(last["ts"]):
            marks = ",".join("?" for _ in vals)
            con.execute(f"insert into {table}({','.join(cols)}) values({marks})", vals)
            cutoff = int(time.time()) - (365 * 24 * 60 * 60)
            con.execute(f"delete from {table} where ts < ?", (cutoff,))
        con.commit()
    finally:
        con.close()


def get_counter_map():
    r = httpx.get(STATS_URL, timeout=3)
    root = ET.fromstring(r.text)
    counters = {}
    for group in root.iter():
        if not group.tag.endswith("counters"):
            continue
        ctype = group.attrib.get("type", "")
        for counter in group:
            if counter.tag.endswith("counter"):
                key = f"{ctype}:{counter.attrib.get('name')}"
                try:
                    value = int(counter.text or 0)
                except Exception:
                    value = 0
                counters[key] = max(counters.get(key, 0), value)
    return counters


def delta_rate(now, key, current, prev_dns):
    prev_ts = LAST_SAMPLE["ts"]
    prev = prev_dns.get(key, current)
    if prev_ts and now > prev_ts and current >= prev:
        return round((current - prev) / (now - prev_ts), 2)
    return 0.0


def collect_metrics():
    now = time.time(); ts = int(now)
    counters = get_counter_map()
    total = counters.get("nsstat:Requestv4", 0) + counters.get("nsstat:Requestv6", 0)
    cache_hits = max(
        counters.get("cachestats:CacheHits", 0),
        counters.get("resolver:CacheHits", 0),
        counters.get("resstats:CacheHits", 0),
        counters.get("resstat:CacheHits", 0),
    )
    rpz_hits = counters.get("nsstat:RPZRewrites", 0)
    prefetch = counters.get("nsstat:Prefetch", 0)
    nxdomain = counters.get("rcode:NXDOMAIN", counters.get("nsstat:QryNXDOMAIN", 0))
    servfail = counters.get("rcode:SERVFAIL", counters.get("nsstat:QrySERVFAIL", 0))
    prev_dns = LAST_SAMPLE.get("dns") or {}
    metrics = {
        "ts": ts,
        "total_qps": delta_rate(now, "total", total, prev_dns),
        "cache_hit_qps": delta_rate(now, "cache_hits", cache_hits, prev_dns),
        "rpz_hit_qps": delta_rate(now, "rpz_hits", rpz_hits, prev_dns),
        "prefetch_qps": delta_rate(now, "prefetch", prefetch, prev_dns),
        "nxdomain_qps": delta_rate(now, "nxdomain", nxdomain, prev_dns),
        "servfail_qps": delta_rate(now, "servfail", servfail, prev_dns),
        "total_queries": total,
        "cache_hits": cache_hits,
        "rpz_hits": rpz_hits,
        "prefetch": prefetch,
        "nxdomain": nxdomain,
        "servfail": servfail,
    }
    LAST_SAMPLE["ts"] = now
    LAST_SAMPLE["dns"] = {"total": total, "cache_hits": cache_hits, "rpz_hits": rpz_hits, "prefetch": prefetch, "nxdomain": nxdomain, "servfail": servfail}
    save_metric("dns_metrics", ["ts","total_qps","cache_hit_qps","rpz_hit_qps","prefetch_qps","nxdomain_qps","servfail_qps","total_queries","cache_hits","rpz_hits","prefetch","nxdomain","servfail","created_at"], [ts,metrics["total_qps"],metrics["cache_hit_qps"],metrics["rpz_hit_qps"],metrics["prefetch_qps"],metrics["nxdomain_qps"],metrics["servfail_qps"],total,cache_hits,rpz_hits,prefetch,nxdomain,servfail,now_iso()])
    save_metric("qps_metrics", ["ts","qps","queries","created_at"], [ts, metrics["total_qps"], total, now_iso()])
    cpu = psutil.cpu_times_percent(interval=0.1)
    cpu_m = {k: float(getattr(cpu, k, 0.0)) for k in ["user","system","idle","iowait","nice","irq","softirq","steal"]}
    save_metric("cpu_metrics", ["ts","user","system","idle","iowait","nice","irq","softirq","steal","created_at"], [ts,cpu_m["user"],cpu_m["system"],cpu_m["idle"],cpu_m["iowait"],cpu_m["nice"],cpu_m["irq"],cpu_m["softirq"],cpu_m["steal"],now_iso()])
    return metrics


def range_cfg(range_name):
    ranges = {
        "day": {"seconds": 86400, "bucket": 300, "label": "by day"},
        "week": {"seconds": 7*86400, "bucket": 1800, "label": "by week"},
        "month": {"seconds": 30*86400, "bucket": 7200, "label": "by month"},
        "year": {"seconds": 365*86400, "bucket": 86400, "label": "by year"},
        "1h": {"seconds": 3600, "bucket": 30, "label": "by hour"},
    }
    return ranges.get(range_name, ranges["day"])


def graph_rows(table, fields, range_name):
    cfg = range_cfg(range_name); since = int(time.time()) - cfg["seconds"]; bucket = cfg["bucket"]
    selects = ", ".join([f"avg({f}) as {f}" for f in fields])
    con = db()
    rows = con.execute(f"select (ts / ?) * ? as ts, {selects} from {table} where ts >= ? group by (ts / ?) order by ts asc", (bucket, bucket, since, bucket)).fetchall()
    con.close()
    return [{"ts": int(r["ts"]), **{f: round(float(r[f] or 0), 2) for f in fields}} for r in rows]


def series_stats(rows, fields):
    out = {}
    for f in fields:
        vals = [float(r[f]) for r in rows]
        out[f] = {"cur": round(vals[-1],2) if vals else 0, "min": round(min(vals),2) if vals else 0, "avg": round(sum(vals)/len(vals),2) if vals else 0, "max": round(max(vals),2) if vals else 0}
    return out


def bind_stats():
    try:
        m = collect_metrics()
        return {"ok": True, "queries": m["total_queries"], "qps": m["total_qps"], "status": "OK"}
    except Exception as e:
        return {"ok": False, "queries": 0, "qps": 0.0, "status": "ERROR", "error": str(e)}


def get_qps_history_range(range_name="1h"):
    rows = graph_rows("qps_metrics", ["qps"], range_name)
    return [{"ts": r["ts"], "time": format_local(r["ts"]), "qps": r["qps"], "queries": 0} for r in rows]


def get_total_qps_samples():
    con = db(); row = con.execute("select count(*) as c from qps_metrics").fetchone(); con.close(); return row["c"] if row else 0


def tail(path, n=80):
    try:
        p = Path(path)
        if not p.exists(): return []
        return p.read_text(errors="ignore").splitlines()[-n:]
    except Exception as e:
        return [str(e)]


def file_size(path):
    try:
        return Path(path).stat().st_size
    except Exception:
        return 0


def read_new_lines(path, offset, max_bytes=65536):
    try:
        p = Path(path)
        if not p.exists():
            return offset, []
        size = p.stat().st_size
        if size < offset:
            offset = 0
        with p.open("rb") as f:
            f.seek(offset)
            data = f.read(max_bytes)
            offset = f.tell()
        lines = data.decode(errors="ignore").splitlines()
        return offset, lines[-200:]
    except Exception as e:
        return offset, [str(e)]


def normalize_domain(d):
    return d.strip().lower().rstrip(".")


def dig_domain(domain):
    return run(["dig", "@127.0.0.1", domain, "A", "+tries=1", "+time=2", "+noall", "+answer", "+comments"], 4)


def check_domain_fast(domain):
    dig = dig_domain(domain)
    upper = dig.upper()
    blocked = "NXDOMAIN" in upper or "CNAME ." in dig or "0.0.0.0" in dig or "lamanlabuh.aduankonten.id" in dig.lower()
    reason = "DNS RPZ policy result" if blocked else "not blocked by local resolver result"
    return blocked, reason, dig


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    con = db(); row = con.execute("select * from users where username=? and enabled=1", (username,)).fetchone()
    ok = bool(row and pwd_context.verify(password, row["password_hash"]))
    con.execute("insert into audit_login(username,ip_address,result,created_at) values(?,?,?,?)", (username, request.client.host, "success" if ok else "failed", now_iso()))
    con.commit(); con.close()
    if not ok:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Login gagal"})
    request.session["user"] = username
    return RedirectResponse("/", status_code=303)

@app.post("/logout")
def logout(request: Request):
    request.session.clear(); return RedirectResponse("/login", status_code=303)

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    user = require_login(request)
    if not user: return RedirectResponse("/login")
    zone_raw = zonestatus()
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user, "active": service_active(), "rndc": rndc_status(), "zone": zone_raw, "zone_info": parse_zonestatus(zone_raw), "sys": system_metrics(), "stats": bind_stats(), "app_tz": APP_TZ, "now_local": now_local().strftime("%Y-%m-%d %H:%M:%S %Z"), "rpz_tail": tail(RPZ_LOG, 20)})

@app.get("/graphs", response_class=HTMLResponse)
def graphs_page(request: Request):
    user = require_login(request)
    if not user: return RedirectResponse("/login")
    return templates.TemplateResponse("graphs.html", {"request": request})

@app.get("/domain-check", response_class=HTMLResponse)
def domain_check_page(request: Request):
    user = require_login(request)
    if not user: return RedirectResponse("/login")
    return templates.TemplateResponse("domain_check.html", {"request": request, "result": None})

@app.post("/domain-check", response_class=HTMLResponse)
def domain_check(request: Request, domain: str = Form(...)):
    user = require_login(request)
    if not user: return RedirectResponse("/login")
    d = normalize_domain(domain)
    if not DOMAIN_RE.match(d):
        result = {"domain": d, "error": "Domain tidak valid"}
    else:
        in_rpz, match, dig = check_domain_fast(d)
        result = {"domain": d, "in_rpz": in_rpz, "match": match, "dig": dig}
        con = db(); con.execute("insert into domain_checks(domain,in_rpz,matched_record,dig_result,checked_by,checked_at) values(?,?,?,?,?,?)", (d, 1 if in_rpz else 0, match, dig, user, now_iso())); con.commit(); con.close()
    return templates.TemplateResponse("domain_check.html", {"request": request, "result": result})

@app.get("/logs", response_class=HTMLResponse)
def logs(request: Request):
    user = require_login(request)
    if not user: return RedirectResponse("/login")
    return templates.TemplateResponse("logs.html", {"request": request, "query": tail(QUERY_LOG, 120), "rpz": tail(RPZ_LOG, 120)})

@app.get("/api/logs")
def api_logs(request: Request, lines: int = 120):
    user = require_login(request)
    if not user: return {"error": "unauthorized"}
    safe_lines = max(10, min(lines, 500))
    return {"query": tail(QUERY_LOG, safe_lines), "rpz": tail(RPZ_LOG, safe_lines), "ts": int(time.time())}

@app.get("/api/logs/live")
async def api_logs_live(request: Request):
    user = require_login(request)
    if not user:
        return StreamingResponse(iter(["event: error\ndata: unauthorized\n\n"]), media_type="text/event-stream")

    async def event_stream():
        q_off = file_size(QUERY_LOG)
        r_off = file_size(RPZ_LOG)
        yield "event: hello\ndata: live\n\n"
        while True:
            if await request.is_disconnected():
                break
            q_off_new, q_lines = read_new_lines(QUERY_LOG, q_off)
            r_off_new, r_lines = read_new_lines(RPZ_LOG, r_off)
            q_off, r_off = q_off_new, r_off_new
            if q_lines or r_lines:
                payload = {"query": q_lines, "rpz": r_lines, "ts": int(time.time())}
                yield "data: " + json.dumps(payload) + "\n\n"
            else:
                yield ": keepalive\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(event_stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.get("/api/qps")
def api_qps(request: Request, range: str = "1h"):
    user = require_login(request)
    if not user: return {"error": "unauthorized"}
    stats = bind_stats()
    return {"current": stats, "history": get_qps_history_range(range), "range": range, "stored_samples": get_total_qps_samples()}

@app.get("/api/graphs/dns")
def api_graph_dns(request: Request, range: str = "day"):
    user = require_login(request)
    if not user: return {"error": "unauthorized"}
    collect_metrics()
    fields = ["total_qps", "cache_hit_qps", "prefetch_qps", "rpz_hit_qps", "nxdomain_qps", "servfail_qps"]
    rows = graph_rows("dns_metrics", fields, range)
    labels = {"total_qps":"total queries from clients","cache_hit_qps":"cache hits","prefetch_qps":"cache prefetch","rpz_hit_qps":"trust+ hits","nxdomain_qps":"NXDOMAIN","servfail_qps":"SERVFAIL"}
    return {"title": f"103.55.253.253 Trust-NG DNS traffic and cache hits - {range_cfg(range)['label']}", "range": range, "rows": rows, "fields": fields, "labels": labels, "stats": series_stats(rows, fields)}

@app.get("/api/graphs/cpu")
def api_graph_cpu(request: Request, range: str = "day"):
    user = require_login(request)
    if not user: return {"error": "unauthorized"}
    collect_metrics()
    fields = ["system", "user", "nice", "idle", "iowait", "irq", "softirq", "steal"]
    rows = graph_rows("cpu_metrics", fields, range)
    labels = {f:f for f in fields}
    return {"title": f"CPU usage - {range_cfg(range)['label']}", "range": range, "rows": rows, "fields": fields, "labels": labels, "stats": series_stats(rows, fields)}

@app.get("/health")
def health():
    return {"status": "ok", "named": service_active(), "time": time.time()}

import os, re, subprocess, sqlite3, time, xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

import httpx, psutil
from fastapi import FastAPI, Form, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
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

app = FastAPI(title=APP_NAME)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=False)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$", re.I)


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
    """)
    row = con.execute("select id from users where username=?", (ADMIN_USER,)).fetchone()
    if not row:
        con.execute("insert into users(username,password_hash,role,enabled,created_at) values(?,?,?,?,?)", (ADMIN_USER, pwd_context.hash(ADMIN_PASSWORD), "admin", 1, datetime.utcnow().isoformat()))
    con.commit(); con.close()

init_db()


def require_login(request: Request):
    if not request.session.get("user"):
        return None
    return request.session["user"]


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
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip().replace(" ", "_").lower()] = value.strip()
    data["ok"] = "serial" in data and "nodes" in data
    return data


def system_metrics():
    return {"cpu": psutil.cpu_percent(interval=0.1), "mem": psutil.virtual_memory().percent, "disk": psutil.disk_usage("/").percent, "load": os.getloadavg()}


def bind_stats():
    data = {"ok": False, "queries": 0, "status": "ERROR"}
    try:
        r = httpx.get(STATS_URL, timeout=3)
        data["ok"] = r.status_code == 200
        data["status"] = "OK" if data["ok"] else f"HTTP {r.status_code}"
        root = ET.fromstring(r.text)
        total = 0
        for counter in root.iter():
            if counter.tag.endswith("counter") and (counter.attrib.get("name", "").lower() in ["requestv4", "requestv6", "queries"]):
                try: total += int(counter.text or 0)
                except: pass
        data["queries"] = total
    except Exception as e:
        data["error"] = str(e)
        data["status"] = "ERROR"
    return data


def tail(path, n=80):
    try:
        p = Path(path)
        if not p.exists(): return []
        return p.read_text(errors="ignore").splitlines()[-n:]
    except Exception as e:
        return [str(e)]


def count_rpz_domains():
    p = Path(ZONE_FILE)
    if not p.exists(): return 0
    try:
        c = 0
        for line in p.read_text(errors="ignore").splitlines():
            s = line.strip()
            if s and not s.startswith(";") and " SOA " not in s and " NS " not in s:
                c += 1
        return c
    except Exception:
        return 0


def normalize_domain(d):
    return d.strip().lower().rstrip(".")


def check_zone_text(domain):
    p = Path(ZONE_FILE)
    if not p.exists(): return False, "zone file not found"
    candidates = [domain, "*." + domain]
    parts = domain.split(".")
    for i in range(1, len(parts)-1): candidates.append("*." + ".".join(parts[i:]))
    try:
        for line in p.read_text(errors="ignore").splitlines():
            s = line.strip().lower()
            for c in candidates:
                if s.startswith(c + " ") or s.startswith(c + "\t"):
                    return True, line.strip()
    except Exception as e:
        return False, str(e)
    return False, "not found in zone file"


def dig_domain(domain):
    return run(["dig", "@127.0.0.1", domain, "+noall", "+answer", "+comments"], 8)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    con = db(); row = con.execute("select * from users where username=? and enabled=1", (username,)).fetchone()
    ok = bool(row and pwd_context.verify(password, row["password_hash"]))
    con.execute("insert into audit_login(username,ip_address,result,created_at) values(?,?,?,?)", (username, request.client.host, "success" if ok else "failed", datetime.utcnow().isoformat()))
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
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user, "active": service_active(), "rndc": rndc_status(), "zone": zone_raw, "zone_info": parse_zonestatus(zone_raw), "sys": system_metrics(), "stats": bind_stats(), "rpz_tail": tail(RPZ_LOG, 20)})

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
        in_rpz, match = check_zone_text(d)
        dig = dig_domain(d)
        result = {"domain": d, "in_rpz": in_rpz, "match": match, "dig": dig}
        con = db(); con.execute("insert into domain_checks(domain,in_rpz,matched_record,dig_result,checked_by,checked_at) values(?,?,?,?,?,?)", (d, 1 if in_rpz else 0, match, dig, user, datetime.utcnow().isoformat())); con.commit(); con.close()
    return templates.TemplateResponse("domain_check.html", {"request": request, "result": result})

@app.get("/logs", response_class=HTMLResponse)
def logs(request: Request):
    user = require_login(request)
    if not user: return RedirectResponse("/login")
    return templates.TemplateResponse("logs.html", {"request": request, "query": tail(QUERY_LOG, 120), "rpz": tail(RPZ_LOG, 120)})

@app.get("/health")
def health():
    return {"status": "ok", "named": service_active(), "time": time.time()}

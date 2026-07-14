from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc
from core.db import get_db
from core.permissions import require_permission
from models.models import ServiceCheck, ServiceCheckHistory, MonitorTag, Tag, NotificationChannel, MonitorNotification, Maintenance, MaintenanceMonitor
from datetime import datetime, timedelta
import subprocess, socket, urllib.request, urllib.error, urllib.parse, time, json, ssl, uuid, hashlib
from urllib.parse import urlparse as _urlparse

router = APIRouter(prefix="/api/services", tags=["services"])

# ── Target normalisation ───────────────────────────────────────────────────────
def _normalize_target(type_: str, target: str) -> str:
    if not target:
        return target
    target = target.strip()
    if type_ in ("http", "keyword", "json-query", "websocket-upgrade") and not target.startswith(("http://","https://","ws://","wss://")):
        return f"http://{target}"
    return target

# ── Accepted status-code check ─────────────────────────────────────────────────
def _status_ok(code: int, accepted: str) -> bool:
    for part in (accepted or "200-299").split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                if int(lo) <= code <= int(hi):
                    return True
            except ValueError:
                pass
        else:
            try:
                if int(part) == code:
                    return True
            except ValueError:
                pass
    return False

# ── JSON path evaluation ───────────────────────────────────────────────────────
def _eval_json_path(data, path: str, operator: str, expected: str) -> bool:
    try:
        import re
        # Simple dot-notation path walker
        keys = path.strip("$.").split(".") if path and path not in ("$", "") else []
        val = data
        for k in keys:
            if k == "" :
                continue
            if isinstance(val, dict):
                val = val.get(k)
            elif isinstance(val, list):
                val = val[int(k)]
            else:
                return False
        val_str = str(val) if val is not None else ""
        exp = expected or ""
        if operator == "==":    return str(val) == exp
        if operator == "!=":    return str(val) != exp
        if operator == "contains": return exp in val_str
        try:
            fv, fe = float(val), float(exp)
            if operator == ">":  return fv > fe
            if operator == ">=": return fv >= fe
            if operator == "<":  return fv < fe
            if operator == "<=": return fv <= fe
        except (ValueError, TypeError):
            pass
        return False
    except Exception:
        return False

# ── Maintenance check ──────────────────────────────────────────────────────────
def _in_maintenance(db: Session, svc_id: str) -> bool:
    now = datetime.utcnow()
    rows = db.query(MaintenanceMonitor).filter(MaintenanceMonitor.service_id == svc_id).all()
    for mm in rows:
        m: Maintenance = db.query(Maintenance).filter(Maintenance.id == mm.maintenance_id, Maintenance.active == True).first()
        if not m:
            continue
        if m.strategy == "manual":
            return True
        if m.strategy == "single":
            if m.start_date and m.end_date and m.start_date <= now <= m.end_date:
                return True
    return False

# ── Core check logic ───────────────────────────────────────────────────────────
def run_check(svc: ServiceCheck) -> dict:
    t0      = time.time()
    status  = "down"
    latency = None
    msg     = ""
    timeout = max(1, int(svc.timeout_sec or 10))

    try:
        # ── PING ──────────────────────────────────────────────────────────────
        if svc.type == "ping":
            count = max(1, int(svc.ping_count or 1))
            r = subprocess.run(
                ["ping", "-c", str(count), "-W", str(timeout), svc.target or svc.hostname or ""],
                capture_output=True, timeout=timeout + 5,
            )
            if r.returncode == 0:
                status  = "up"
                latency = round((time.time() - t0) * 1000, 1)

        # ── HTTP / KEYWORD / JSON-QUERY ────────────────────────────────────
        elif svc.type in ("http", "keyword", "json-query"):
            url = svc.target or ""
            if not url.startswith(("http://","https://")):
                url = f"https://{url}"
            method = (svc.method or "GET").upper()

            # SSL context — MUST be passed to the HTTPS handler
            ctx = ssl.create_default_context()
            if svc.ignore_tls:
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE

            hdrs = {"User-Agent": "SmartMonitor/3.0"}
            if svc.headers_json:
                try: hdrs.update(json.loads(svc.headers_json))
                except Exception: pass

            # Auth
            if svc.auth_method == "basic" and svc.basic_auth_user:
                import base64
                cred = base64.b64encode(f"{svc.basic_auth_user}:{svc.basic_auth_pass or ''}".encode()).decode()
                hdrs["Authorization"] = f"Basic {cred}"
            elif svc.auth_method == "bearer" and svc.bearer_token:
                hdrs["Authorization"] = f"Bearer {svc.bearer_token}"

            # Cache busting
            if svc.cache_bust:
                sep = "&" if "?" in url else "?"
                url += f"{sep}_sm_cb={int(time.time())}"

            # Body
            body_data = None
            if svc.body:
                enc = svc.body_encoding or "json"
                if enc == "json":
                    body_data = svc.body.encode()
                    hdrs.setdefault("Content-Type", "application/json")
                elif enc == "form":
                    body_data = svc.body.encode()
                    hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
                else:
                    body_data = svc.body.encode()
                    hdrs.setdefault("Content-Type", "application/xml")

            max_hops = max(0, int(svc.max_redirects or 10))

            class _LimitRedirects(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg2, hdrs2, newurl):
                    if max_hops <= 0:
                        raise urllib.error.HTTPError(newurl, code, "Max redirects", hdrs2, fp)
                    return super().redirect_request(req, fp, code, msg2, hdrs2, newurl)

            # ← KEY FIX: pass ctx to HTTPSHandler so TLS settings actually apply
            https_handler = urllib.request.HTTPSHandler(context=ctx)
            opener = urllib.request.build_opener(https_handler, _LimitRedirects)

            req_obj = urllib.request.Request(url, data=body_data, headers=hdrs, method=method)
            code_val  = 0
            resp_body = b""
            cert_expiry_dt = None

            try:
                with opener.open(req_obj, timeout=timeout) as resp:
                    code_val = resp.status
                    need_body = svc.type in ("keyword","json-query") or svc.save_response or svc.save_error_response
                    if need_body:
                        resp_body = resp.read(100_000)
                    # ── Extract cert expiry if HTTPS ──────────────────────────
                    if url.startswith("https://") and not svc.ignore_tls:
                        try:
                            raw_sock = resp.fp.raw._sock if hasattr(resp, 'fp') and hasattr(resp.fp, 'raw') else None
                            if raw_sock is None:
                                # try alternate path
                                pass
                        except Exception:
                            pass
            except urllib.error.HTTPError as e:
                code_val = e.code
                if svc.save_error_response:
                    try: resp_body = e.read(100_000)
                    except Exception: pass
            except Exception as e:
                msg = str(e)[:150]
                latency = round((time.time() - t0) * 1000, 1)

            # Try cert expiry via separate SSL peek (lightweight)
            if url.startswith("https://"):
                try:
                    import datetime as _dt
                    _parsed_url = _urlparse(url)
                    _peek_host  = _parsed_url.hostname or ""
                    _peek_port  = _parsed_url.port or 443
                    # Use CERT_REQUIRED + default CAs so getpeercert() returns the full cert dict
                    _peek_ctx = ssl.create_default_context()
                    _peek_ctx.check_hostname = False
                    # CERT_REQUIRED lets Python parse the cert, but we ignore verify errors
                    _peek_ctx.verify_mode = ssl.CERT_REQUIRED
                    try:
                        with socket.create_connection((_peek_host, _peek_port), timeout=5) as _raw:
                            with _peek_ctx.wrap_socket(_raw, server_hostname=_peek_host) as _ssock:
                                _cert = _ssock.getpeercert()
                                if _cert and _cert.get("notAfter"):
                                    cert_expiry_dt = _dt.datetime.utcfromtimestamp(
                                        ssl.cert_time_to_seconds(_cert["notAfter"])
                                    )
                    except ssl.SSLCertVerificationError:
                        # Fallback: get raw DER and decode with internal parser
                        _peek_ctx2 = ssl.create_default_context()
                        _peek_ctx2.check_hostname = False
                        _peek_ctx2.verify_mode = ssl.CERT_NONE
                        with socket.create_connection((_peek_host, _peek_port), timeout=5) as _raw2:
                            with _peek_ctx2.wrap_socket(_raw2, server_hostname=_peek_host) as _ssock2:
                                _der = _ssock2.getpeercert(binary_form=True)
                                if _der:
                                    # Python internal: decode DER cert to dict
                                    _cert2 = ssl._ssl._test_decode_cert(_der)  # type: ignore[attr-defined]
                                    if _cert2 and _cert2.get("notAfter"):
                                        cert_expiry_dt = _dt.datetime.utcfromtimestamp(
                                            ssl.cert_time_to_seconds(_cert2["notAfter"])
                                        )
                except Exception:
                    pass

            latency = latency or round((time.time() - t0) * 1000, 1)
            accepted = svc.accepted_statuscodes or "200-299"
            if code_val and _status_ok(code_val, accepted):
                if svc.type == "keyword" and svc.keyword:
                    body_str = resp_body.decode("utf-8", errors="ignore")
                    found = svc.keyword in body_str
                    if svc.invert_keyword: found = not found
                    status = "up" if found else "down"
                    msg    = f"keyword {'found' if found else 'not found'}: {svc.keyword[:40]}"
                elif svc.type == "json-query" and svc.json_path:
                    try:
                        data = json.loads(resp_body.decode("utf-8", errors="ignore"))
                        ok = _eval_json_path(data, svc.json_path, svc.json_path_operator or "==", svc.expected_value or "")
                        status = "up" if ok else "down"
                        msg    = f"JSON query {'passed' if ok else 'failed'}"
                    except Exception as je:
                        status = "down"; msg = f"JSON parse error: {str(je)[:80]}"
                else:
                    status = "up"
                    msg    = f"{code_val} - OK"
            elif code_val:
                status = "down"
                msg    = f"{code_val} - {msg or 'Unexpected status'}"
            # Store cert expiry on svc (will be saved by caller)
            if cert_expiry_dt:
                svc.cert_expiry = cert_expiry_dt

        # ── TCP ────────────────────────────────────────────────────────────────
        elif svc.type == "tcp":
            raw = svc.target or ""
            if ":" in raw:
                host, port = raw.rsplit(":", 1)
            else:
                host = raw
                port = str(svc.port or 80)
            s = socket.create_connection((host.strip(), int(port.strip())), timeout=timeout)
            s.close()
            status  = "up"
            latency = round((time.time() - t0) * 1000, 1)

        # ── DNS ────────────────────────────────────────────────────────────────
        elif svc.type == "dns":
            host = (svc.target or svc.hostname or "").split()[0]
            resolver = svc.dns_resolve_server
            if resolver:
                # Use dig if resolver specified
                rtype = svc.dns_resolve_type or "A"
                r = subprocess.run(
                    ["dig", f"@{resolver}", host, rtype, "+short", "+time=5"],
                    capture_output=True, text=True, timeout=timeout + 2,
                )
                if r.returncode == 0 and r.stdout.strip():
                    status  = "up"
                    latency = round((time.time() - t0) * 1000, 1)
                else:
                    msg = r.stdout.strip() or r.stderr.strip() or "No result"
            else:
                socket.setdefaulttimeout(timeout)
                res = socket.getaddrinfo(host, None)
                socket.setdefaulttimeout(None)
                if res:
                    status  = "up"
                    latency = round((time.time() - t0) * 1000, 1)

        # ── PUSH (passive) ─────────────────────────────────────────────────────
        elif svc.type == "push":
            # Status is determined by last push time vs interval
            if svc.last_push:
                elapsed = (datetime.utcnow() - svc.last_push).total_seconds()
                grace   = (svc.interval_sec or 60) * 1.5
                status  = "up" if elapsed <= grace else "down"
                msg     = f"Last push {int(elapsed)}s ago"
                latency = round(elapsed * 1000, 1)
            else:
                status  = "pending"
                msg     = "Waiting for first push..."

        # ── SMTP ───────────────────────────────────────────────────────────────
        elif svc.type == "smtp":
            import smtplib
            host = svc.hostname or svc.target or ""
            port_n = int(svc.port or 25)
            sec = svc.smtp_security or "nostarttls"
            if sec == "secure":
                srv = smtplib.SMTP_SSL(host, port_n, timeout=timeout)
            else:
                srv = smtplib.SMTP(host, port_n, timeout=timeout)
                if sec == "starttls":
                    srv.starttls()
            srv.quit()
            status  = "up"
            latency = round((time.time() - t0) * 1000, 1)

        # ── PostgreSQL ─────────────────────────────────────────────────────────
        elif svc.type == "postgres":
            try:
                import psycopg2
                conn = psycopg2.connect(svc.db_connection_string or "", connect_timeout=timeout)
                if svc.db_query:
                    cur = conn.cursor()
                    cur.execute(svc.db_query)
                    cur.close()
                conn.close()
                status  = "up"
                latency = round((time.time() - t0) * 1000, 1)
            except ImportError:
                msg = "psycopg2 not installed"
            except Exception as e:
                msg = str(e)[:120]

        # ── MySQL / MariaDB ────────────────────────────────────────────────────
        elif svc.type == "mysql":
            try:
                import pymysql
                # Parse connection string or use individual fields
                cs = svc.db_connection_string or ""
                # pymysql.connect from URI
                conn = pymysql.connect(
                    host=svc.hostname or "localhost",
                    port=int(svc.port or 3306),
                    user=svc.basic_auth_user or "root",
                    password=svc.basic_auth_pass or "",
                    connect_timeout=timeout,
                )
                if svc.db_query:
                    cur = conn.cursor()
                    cur.execute(svc.db_query)
                    cur.close()
                conn.close()
                status  = "up"
                latency = round((time.time() - t0) * 1000, 1)
            except ImportError:
                msg = "pymysql not installed"
            except Exception as e:
                msg = str(e)[:120]

        # ── Redis ──────────────────────────────────────────────────────────────
        elif svc.type == "redis":
            try:
                import redis
                r = redis.from_url(svc.db_connection_string or f"redis://{svc.hostname or 'localhost'}:{svc.port or 6379}",
                                   socket_connect_timeout=timeout, socket_timeout=timeout)
                r.ping()
                r.close()
                status  = "up"
                latency = round((time.time() - t0) * 1000, 1)
            except ImportError:
                msg = "redis not installed"
            except Exception as e:
                msg = str(e)[:120]

        # ── MongoDB ────────────────────────────────────────────────────────────
        elif svc.type == "mongodb":
            try:
                from pymongo import MongoClient
                client = MongoClient(svc.db_connection_string or f"mongodb://{svc.hostname or 'localhost'}:{svc.port or 27017}",
                                     serverSelectionTimeoutMS=timeout * 1000)
                client.admin.command("ping")
                client.close()
                status  = "up"
                latency = round((time.time() - t0) * 1000, 1)
            except ImportError:
                msg = "pymongo not installed"
            except Exception as e:
                msg = str(e)[:120]

        # ── Docker container ───────────────────────────────────────────────────
        elif svc.type == "docker":
            r = subprocess.run(
                ["docker", "-H", svc.docker_host or "unix:///var/run/docker.sock",
                 "inspect", "--format", "{{.State.Running}}", svc.docker_container or ""],
                capture_output=True, text=True, timeout=timeout + 2,
            )
            if r.returncode == 0 and "true" in r.stdout.lower():
                status  = "up"
                latency = round((time.time() - t0) * 1000, 1)
            else:
                msg = r.stderr.strip() or "Container not running"

        # ── WebSocket Upgrade ──────────────────────────────────────────────────
        elif svc.type == "websocket-upgrade":
            url = (svc.target or "").replace("https://","wss://").replace("http://","ws://")
            parsed = _urlparse(url)
            host = parsed.hostname or ""
            port_n = parsed.port or (443 if parsed.scheme == "wss" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            use_ssl = parsed.scheme == "wss"
            sock = socket.create_connection((host, port_n), timeout=timeout)
            if use_ssl:
                ctx = ssl.create_default_context()
                if svc.ignore_tls:
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            import base64, os as _os
            ws_key = base64.b64encode(_os.urandom(16)).decode()
            handshake = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                f"Sec-WebSocket-Protocol: {svc.ws_subprotocol or ''}\r\n"
                "\r\n"
            )
            sock.sendall(handshake.encode())
            resp = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()
            if "101" in resp and "Switching Protocols" in resp:
                status  = "up"
                latency = round((time.time() - t0) * 1000, 1)
            else:
                msg = resp.split("\r\n")[0]

        # ── Manual ─────────────────────────────────────────────────────────────
        elif svc.type in ("manual", "group"):
            status  = svc.last_status or "unknown"
            latency = None

        else:
            msg = f"Unsupported type: {svc.type}"

    except subprocess.TimeoutExpired:
        msg = "Timeout"
    except socket.timeout:
        msg = "Connection timed out"
    except ConnectionRefusedError:
        msg = "Connection refused"
    except Exception as e:
        msg = str(e)[:120]

    # Upside-down mode
    if svc.upside_down and status in ("up", "down"):
        status = "down" if status == "up" else "up"

    return {"status": status, "latency": latency, "msg": msg}

# ── Notification dispatch ──────────────────────────────────────────────────────
def _send_notifications(db: Session, svc: ServiceCheck, text: str):
    # 1. Monitor-specific notifications
    links = db.query(MonitorNotification).filter(MonitorNotification.service_id == svc.id).all()
    channel_ids = [l.notification_id for l in links]
    # 2. Default notifications
    defaults = db.query(NotificationChannel).filter(
        NotificationChannel.is_default == True,
        NotificationChannel.active == True
    ).all()
    for d in defaults:
        if d.id not in channel_ids:
            channel_ids.append(d.id)
    for cid in channel_ids:
        ch = db.query(NotificationChannel).filter(NotificationChannel.id == cid, NotificationChannel.active == True).first()
        if ch:
            try:
                _dispatch_notification(ch, text)
            except Exception as e:
                print(f"[Notify] {ch.name} error: {e}")

def _dispatch_notification(ch: NotificationChannel, text: str):
    cfg = json.loads(ch.config_json or "{}")
    t = ch.type

    if t == "telegram":
        _notif_telegram(cfg.get("token",""), cfg.get("chat_id",""), text)

    elif t == "email":
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(text)
        msg["Subject"] = f"SmartMonitor Alert"
        msg["From"]    = cfg.get("from_email","")
        msg["To"]      = cfg.get("to_email","")
        srv = smtplib.SMTP(cfg.get("host","localhost"), int(cfg.get("port",587)), timeout=10)
        if cfg.get("secure"):
            srv.starttls()
        if cfg.get("username"):
            srv.login(cfg["username"], cfg.get("password",""))
        srv.sendmail(msg["From"], msg["To"].split(","), msg.as_string())
        srv.quit()

    elif t in ("slack", "discord", "teams", "webhook", "gotify_webhook"):
        url = cfg.get("webhook_url","") or cfg.get("url","")
        payload = json.dumps({"text": text, "content": text, "message": text}).encode()
        req = urllib.request.Request(url, data=payload, headers={"Content-Type":"application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=8)

    elif t == "pushover":
        payload = urllib.parse.urlencode({
            "token":   cfg.get("api_key",""),
            "user":    cfg.get("user_key",""),
            "message": text,
            "priority": cfg.get("priority","0"),
        }).encode() if False else json.dumps({
            "token": cfg.get("api_key",""),
            "user":  cfg.get("user_key",""),
            "message": text,
        }).encode()
        req = urllib.request.Request("https://api.pushover.net/1/messages.json",
            data=payload, headers={"Content-Type":"application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=8)

    elif t == "gotify":
        server = cfg.get("server_url","").rstrip("/")
        token  = cfg.get("app_token","")
        payload = json.dumps({"title":"SmartMonitor Alert","message":text,"priority": int(cfg.get("priority",5))}).encode()
        req = urllib.request.Request(f"{server}/message?token={token}",
            data=payload, headers={"Content-Type":"application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=8)

    elif t == "ntfy":
        server = cfg.get("server_url","https://ntfy.sh").rstrip("/")
        topic  = cfg.get("topic","smartmonitor")
        hdrs   = {"Content-Type":"text/plain"}
        if cfg.get("access_token"):
            hdrs["Authorization"] = f"Bearer {cfg['access_token']}"
        elif cfg.get("username"):
            import base64
            hdrs["Authorization"] = "Basic " + base64.b64encode(f"{cfg['username']}:{cfg.get('password','')}".encode()).decode()
        if cfg.get("priority"):
            hdrs["Priority"] = str(cfg["priority"])
        req = urllib.request.Request(f"{server}/{topic}",
            data=text.encode(), headers=hdrs, method="POST")
        urllib.request.urlopen(req, timeout=8)

    elif t == "pagerduty":
        payload = json.dumps({
            "routing_key": cfg.get("integration_key",""),
            "event_action": "trigger",
            "payload": {"summary": text, "severity": "critical", "source": "SmartMonitor"},
        }).encode()
        req = urllib.request.Request("https://events.pagerduty.com/v2/enqueue",
            data=payload, headers={"Content-Type":"application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=8)

    elif t == "opsgenie":
        key = cfg.get("api_key","")
        region = cfg.get("region","us")
        base = "https://api.eu.opsgenie.com" if region == "eu" else "https://api.opsgenie.com"
        payload = json.dumps({"message": text, "source": "SmartMonitor", "priority": "P3"}).encode()
        req = urllib.request.Request(f"{base}/v2/alerts",
            data=payload,
            headers={"Content-Type":"application/json","Authorization":f"GenieKey {key}"},
            method="POST")
        urllib.request.urlopen(req, timeout=8)

    elif t == "matrix":
        server = cfg.get("home_server","").rstrip("/")
        room   = cfg.get("internal_room_id","")
        token  = cfg.get("access_token","")
        txn_id = str(int(time.time()))
        payload = json.dumps({"msgtype":"m.text","body":text}).encode()
        req = urllib.request.Request(
            f"{server}/_matrix/client/r0/rooms/{room}/send/m.room.message/{txn_id}",
            data=payload,
            headers={"Content-Type":"application/json","Authorization":f"Bearer {token}"},
            method="PUT")
        urllib.request.urlopen(req, timeout=8)

    elif t == "apprise":
        url = cfg.get("appriseUrl","")
        payload = json.dumps({"title":"SmartMonitor Alert","body":text}).encode()
        req = urllib.request.Request(url, data=payload,
            headers={"Content-Type":"application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=8)

def _notif_telegram(token: str, chat_id: str, text: str):
    if not (token and chat_id):
        return
    url  = f"https://api.telegram.org/bot{token}/sendMessage"
    body = json.dumps({"chat_id": chat_id, "text": text, "parse_mode": "HTML"}).encode()
    req  = urllib.request.Request(url, data=body, headers={"Content-Type":"application/json"})
    urllib.request.urlopen(req, timeout=5)

# ── Legacy: send via global config.json (backward compat) ─────────────────────
def _send_telegram_legacy(text: str):
    try:
        cfg = json.load(open("/data/config.json"))
        if not cfg.get("telegram_enabled"):
            return
        _notif_telegram(cfg.get("telegram_token",""), cfg.get("telegram_chat_id",""), text)
    except Exception:
        pass

# ── Retry + save check ─────────────────────────────────────────────────────────
def run_check_and_save(db: Session, svc: ServiceCheck):
    if _in_maintenance(db, svc.id):
        svc.last_status = "maintenance"
        db.commit()
        return {"status":"maintenance","latency":None,"msg":"Under maintenance"}

    prev_status = svc.last_status
    result      = run_check(svc)
    now         = datetime.utcnow()
    raw_status  = result["status"]

    if raw_status == "down":
        svc.consecutive_failures = (svc.consecutive_failures or 0) + 1
        max_r = svc.max_retries or 0
        effective_status = "pending" if svc.consecutive_failures <= max_r else "down"
    else:
        svc.consecutive_failures = 0
        effective_status         = raw_status  # "up" or "maintenance" or "pending"

    db.add(ServiceCheckHistory(
        service_id=svc.id, timestamp=now,
        status=effective_status, latency_ms=result["latency"],
        msg=result.get("msg",""),
    ))
    svc.last_check      = now
    svc.last_status     = effective_status
    svc.last_latency_ms = result["latency"]
    db.commit()

    # Notifications on transition
    if prev_status not in ("down","pending") and effective_status == "down":
        alert = f"🔴 <b>{svc.name}</b> is DOWN\n{svc.type.upper()}: {svc.target or svc.hostname or ''}\n{result.get('msg','')}"
        _send_notifications(db, svc, alert)
        _send_telegram_legacy(alert)
    elif prev_status in ("down","pending") and effective_status == "up":
        lat = f" — {result['latency']:.0f}ms" if result["latency"] else ""
        alert = f"🟢 <b>{svc.name}</b> is UP{lat}"
        _send_notifications(db, svc, alert)
        _send_telegram_legacy(alert)
    elif effective_status == "down" and svc.resend_interval and svc.consecutive_failures:
        if svc.consecutive_failures % svc.resend_interval == 0:
            alert = f"🔴 <b>{svc.name}</b> still DOWN (retry #{svc.consecutive_failures})"
            _send_notifications(db, svc, alert)
            _send_telegram_legacy(alert)

    # Purge >30 days
    cutoff = now - timedelta(days=30)
    db.query(ServiceCheckHistory).filter(
        ServiceCheckHistory.service_id == svc.id,
        ServiceCheckHistory.timestamp  < cutoff,
    ).delete()
    db.commit()
    return result

# ── Stats helpers ──────────────────────────────────────────────────────────────
def _uptime_pct(history, hours):
    since = datetime.utcnow() - timedelta(hours=hours)
    rows  = [h for h in history if h.timestamp >= since and h.status not in ("pending","maintenance")]
    if not rows:
        return None
    return round(sum(1 for h in rows if h.status == "up") / len(rows) * 100, 2)

def _cert_expiry_days(svc: ServiceCheck):
    """Return days until TLS cert expires if we stored it, else None."""
    if not getattr(svc, 'cert_expiry', None):
        return None
    try:
        from datetime import timezone
        exp = svc.cert_expiry
        if hasattr(exp, 'tzinfo') and exp.tzinfo:
            delta = exp - datetime.now(timezone.utc)
        else:
            delta = exp - datetime.utcnow()
        return max(0, round(delta.total_seconds() / 86400, 1))
    except Exception:
        return None

def _cert_expiry_date(svc: ServiceCheck):
    if not getattr(svc, 'cert_expiry', None):
        return None
    try:
        return svc.cert_expiry.strftime("%Y-%m-%d")
    except Exception:
        return None

def _avg_latency(history, hours):
    since = datetime.utcnow() - timedelta(hours=hours)
    lats  = [h.latency_ms for h in history if h.timestamp >= since and h.latency_ms is not None]
    return round(sum(lats)/len(lats), 1) if lats else None

def _fmt(svc: ServiceCheck, history: list) -> dict:
    hb = [{"s": h.status, "t": h.timestamp.isoformat()+"Z", "l": h.latency_ms, "m": h.msg}
          for h in history[-90:]]
    tags = [{"id": mt.tag_id, "name": mt.tag.name, "color": mt.tag.color}
            for mt in svc.tags if mt.tag] if svc.tags else []
    notif_ids = [mn.notification_id for mn in svc.notifications] if svc.notifications else []
    return {
        "id": svc.id, "name": svc.name, "type": svc.type,
        "target":               svc.target,
        "hostname":             svc.hostname,
        "port":                 svc.port,
        "interval_sec":         svc.interval_sec,
        "timeout_sec":          svc.timeout_sec or 10,
        "max_retries":          svc.max_retries or 0,
        "resend_interval":      svc.resend_interval or 0,
        "description":          svc.description,
        "active":               svc.active,
        "parent_id":            svc.parent_id,
        # HTTP
        "keyword":              svc.keyword,
        "invert_keyword":       svc.invert_keyword or False,
        "accepted_statuscodes": svc.accepted_statuscodes or "200-299",
        "method":               svc.method or "GET",
        "headers_json":         svc.headers_json,
        "body":                 svc.body,
        "body_encoding":        svc.body_encoding or "json",
        "max_redirects":        svc.max_redirects if svc.max_redirects is not None else 10,
        "ignore_tls":           svc.ignore_tls if svc.ignore_tls is not None else True,
        "upside_down":          svc.upside_down or False,
        "cache_bust":           svc.cache_bust or False,
        "ip_family":            svc.ip_family,
        "save_response":        svc.save_response or False,
        "save_error_response":  svc.save_error_response if svc.save_error_response is not None else True,
        # Auth
        "auth_method":          svc.auth_method,
        "basic_auth_user":      svc.basic_auth_user,
        "bearer_token":         "***" if svc.bearer_token else None,
        "oauth_token_url":      svc.oauth_token_url,
        "oauth_client_id":      svc.oauth_client_id,
        "oauth_scopes":         svc.oauth_scopes,
        "oauth_audience":       svc.oauth_audience,
        "oauth_auth_method":    svc.oauth_auth_method,
        "auth_domain":          svc.auth_domain,
        "auth_workstation":     svc.auth_workstation,
        # Certificate
        "expiry_notification":        svc.expiry_notification or False,
        "domain_expiry_notification": svc.domain_expiry_notification or False,
        # JSON Query
        "json_path":            svc.json_path,
        "json_path_operator":   svc.json_path_operator or "==",
        "expected_value":       svc.expected_value,
        # DNS
        "dns_resolve_type":     svc.dns_resolve_type or "A",
        "dns_resolve_server":   svc.dns_resolve_server,
        # Push
        "push_token":           svc.push_token,
        # WebSocket
        "ws_subprotocol":       svc.ws_subprotocol,
        # Ping
        "ping_count":           svc.ping_count or 1,
        "ping_numeric":         svc.ping_numeric or False,
        # SMTP
        "smtp_security":        svc.smtp_security,
        # Database
        "db_connection_string": svc.db_connection_string,
        "db_query":             svc.db_query,
        # gRPC
        "grpc_url":             svc.grpc_url,
        "grpc_service_name":    svc.grpc_service_name,
        "grpc_method":          svc.grpc_method,
        "grpc_enable_tls":      svc.grpc_enable_tls or False,
        # Docker
        "docker_container":     svc.docker_container,
        "docker_host":          svc.docker_host,
        # MQTT
        "mqtt_topic":           svc.mqtt_topic,
        "mqtt_check_type":      svc.mqtt_check_type,
        "mqtt_success_msg":     svc.mqtt_success_msg,
        # Proxy
        "proxy_id":             svc.proxy_id,
        # Status
        "last_check":           svc.last_check.isoformat() if svc.last_check else None,
        "last_status":          svc.last_status,
        "last_latency_ms":      svc.last_latency_ms,
        # Stats
        "uptime_24h":   _uptime_pct(history, 24),
        "uptime_7d":    _uptime_pct(history, 24*7),
        "uptime_30d":   _uptime_pct(history, 24*30),
        "uptime_1y":    _uptime_pct(history, 24*365),
        "avg_latency":  _avg_latency(history, 24),
        "heartbeat":    hb,
        # TLS certificate expiry (computed if available)
        "cert_expiry_days": _cert_expiry_days(svc),
        "cert_expiry_date": _cert_expiry_date(svc),
        # Relations
        "tags":         tags,
        "notification_ids": notif_ids,
    }

def _load_history(db: Session, svc_id: str) -> list:
    since = datetime.utcnow() - timedelta(days=30)
    return (db.query(ServiceCheckHistory)
              .filter(ServiceCheckHistory.service_id == svc_id,
                      ServiceCheckHistory.timestamp >= since)
              .order_by(ServiceCheckHistory.timestamp)
              .all())

# ── Writable fields (PUT) ──────────────────────────────────────────────────────
_WRITABLE = {
    "name","type","target","hostname","port","interval_sec","timeout_sec","max_retries",
    "keyword","invert_keyword","accepted_statuscodes","description","active","parent_id",
    "method","headers_json","body","body_encoding","max_redirects","ignore_tls",
    "upside_down","cache_bust","ip_family","save_response","save_error_response","resend_interval",
    "auth_method","basic_auth_user","basic_auth_pass","bearer_token",
    "oauth_token_url","oauth_client_id","oauth_client_secret","oauth_scopes","oauth_audience","oauth_auth_method",
    "auth_domain","auth_workstation","tls_cert","tls_key","tls_ca",
    "expiry_notification","domain_expiry_notification",
    "json_path","json_path_operator","expected_value",
    "dns_resolve_type","dns_resolve_server",
    "ws_subprotocol","ping_count","ping_numeric",
    "smtp_security","db_connection_string","db_query",
    "grpc_url","grpc_service_name","grpc_method","grpc_enable_tls","grpc_body","grpc_protobuf",
    "docker_container","docker_host",
    "mqtt_username","mqtt_password","mqtt_topic","mqtt_check_type","mqtt_success_msg",
    "kafka_brokers","kafka_topic","kafka_message","kafka_ssl","kafka_sasl_mechanism","kafka_sasl_username","kafka_sasl_password",
    "proxy_id",
}

# ── Endpoints ──────────────────────────────────────────────────────────────────
@router.get("")
def list_services(user=Depends(require_permission("monitors", "view")), db: Session = Depends(get_db)):
    svcs = db.query(ServiceCheck).order_by(ServiceCheck.created_at).all()
    return [_fmt(s, _load_history(db, s.id)) for s in svcs]

@router.post("")
def create_service(data: dict, user=Depends(require_permission("monitors", "edit")), db: Session = Depends(get_db)):
    type_ = data.get("type", "http")
    target = _normalize_target(type_, data.get("target","") or "")
    # Generate push token for push monitors
    push_token = None
    if type_ == "push":
        push_token = str(uuid.uuid4()).replace("-","")[:32]
    svc = ServiceCheck(push_token=push_token)
    svc.name   = data.get("name","New Monitor")
    svc.type   = type_
    svc.target = target
    for f in _WRITABLE - {"name","type","target"}:
        if f in data and data[f] is not None:
            if f == "target":
                continue
            setattr(svc, f, data[f])
    db.add(svc)
    db.commit()
    db.refresh(svc)
    # Assign tags
    for tag_id in (data.get("tag_ids") or []):
        db.add(MonitorTag(service_id=svc.id, tag_id=tag_id))
    # Assign notifications
    for nid in (data.get("notification_ids") or []):
        db.add(MonitorNotification(service_id=svc.id, notification_id=nid))
    db.commit()
    db.refresh(svc)
    return _fmt(svc, [])

@router.put("/{svc_id}")
def update_service(svc_id: str, data: dict, user=Depends(require_permission("monitors", "edit")), db: Session = Depends(get_db)):
    svc = db.query(ServiceCheck).filter(ServiceCheck.id == svc_id).first()
    if not svc:
        raise HTTPException(404, "Not found")
    for f in _WRITABLE:
        if f in data:
            val = data[f]
            if f == "target":
                val = _normalize_target(data.get("type", svc.type), val or "")
            setattr(svc, f, val)
    # Update tags
    if "tag_ids" in data:
        db.query(MonitorTag).filter(MonitorTag.service_id == svc_id).delete()
        for tag_id in (data["tag_ids"] or []):
            db.add(MonitorTag(service_id=svc_id, tag_id=tag_id))
    # Update notifications
    if "notification_ids" in data:
        db.query(MonitorNotification).filter(MonitorNotification.service_id == svc_id).delete()
        for nid in (data["notification_ids"] or []):
            db.add(MonitorNotification(service_id=svc_id, notification_id=nid))
    db.commit()
    return _fmt(svc, _load_history(db, svc_id))

@router.delete("/{svc_id}")
def delete_service(svc_id: str, user=Depends(require_permission("monitors", "edit")), db: Session = Depends(get_db)):
    svc = db.query(ServiceCheck).filter(ServiceCheck.id == svc_id).first()
    if svc:
        db.delete(svc)
        db.commit()
    return {"ok": True}

@router.post("/{svc_id}/clone")
def clone_service(svc_id: str, user=Depends(require_permission("monitors", "edit")), db: Session = Depends(get_db)):
    svc = db.query(ServiceCheck).filter(ServiceCheck.id == svc_id).first()
    if not svc:
        raise HTTPException(404, "Not found")
    data = _fmt(svc, [])
    data.pop("id", None)
    data["name"] = f"{data['name']} (copy)"
    data.pop("heartbeat", None); data.pop("uptime_24h", None)
    data.pop("uptime_7d", None); data.pop("uptime_30d", None)
    data.pop("uptime_1y", None); data.pop("avg_latency", None)
    data.pop("last_check", None); data.pop("last_status", None)
    data.pop("last_latency_ms", None); data.pop("push_token", None)
    tag_ids  = [t["id"] for t in data.pop("tags", [])]
    notif_ids= data.pop("notification_ids", [])
    data["tag_ids"] = tag_ids
    data["notification_ids"] = notif_ids
    return create_service(data, user=user, db=db)

@router.post("/{svc_id}/check")
def check_now(svc_id: str, user=Depends(require_permission("monitors", "edit")), db: Session = Depends(get_db)):
    svc = db.query(ServiceCheck).filter(ServiceCheck.id == svc_id).first()
    if not svc:
        raise HTTPException(404, "Not found")
    result = run_check_and_save(db, svc)
    return {**_fmt(svc, _load_history(db, svc_id)), **result}

@router.post("/{svc_id}/pause")
def toggle_pause(svc_id: str, user=Depends(require_permission("monitors", "edit")), db: Session = Depends(get_db)):
    svc = db.query(ServiceCheck).filter(ServiceCheck.id == svc_id).first()
    if not svc:
        raise HTTPException(404, "Not found")
    svc.active = not svc.active
    db.commit()
    return {"active": svc.active}

@router.post("/{svc_id}/clear-history")
def clear_history(svc_id: str, user=Depends(require_permission("monitors", "edit")), db: Session = Depends(get_db)):
    db.query(ServiceCheckHistory).filter(ServiceCheckHistory.service_id == svc_id).delete()
    db.commit()
    return {"ok": True}

@router.post("/{svc_id}/manual-status")
def set_manual_status(svc_id: str, data: dict, user=Depends(require_permission("monitors", "edit")), db: Session = Depends(get_db)):
    svc = db.query(ServiceCheck).filter(ServiceCheck.id == svc_id).first()
    if not svc or svc.type != "manual":
        raise HTTPException(404, "Not found or not manual type")
    svc.last_status = data.get("status","up")
    db.commit()
    return _fmt(svc, _load_history(db, svc_id))

# ── Push endpoint (no auth) ────────────────────────────────────────────────────
@router.get("/push/{push_token}")
def push_receive(push_token: str, status: str = "up", msg: str = "OK", ping: float = None,
                 db: Session = Depends(get_db)):
    svc = db.query(ServiceCheck).filter(ServiceCheck.push_token == push_token).first()
    if not svc:
        raise HTTPException(404, "Token not found")
    svc.last_push      = datetime.utcnow()
    svc.last_check     = datetime.utcnow()
    svc.last_status    = status
    svc.last_latency_ms= float(ping) if ping else None
    db.add(ServiceCheckHistory(
        service_id=svc.id, timestamp=datetime.utcnow(),
        status=status, latency_ms=float(ping) if ping else None, msg=msg,
    ))
    db.commit()
    return {"ok": True, "monitor": svc.name}

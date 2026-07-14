from fastapi import APIRouter, Depends
from core.permissions import require_permission
import json, os

router = APIRouter(prefix="/api/config", tags=["config"])
CONFIG_PATH = "/data/config.json"

def _read():
    try:
        return json.load(open(CONFIG_PATH))
    except:
        return {"push_interval": 60}

def _write(data):
    os.makedirs("/data", exist_ok=True)
    json.dump(data, open(CONFIG_PATH, "w"))

@router.get("/interval")
def get_interval():
    return {"interval": _read().get("push_interval", 5)}

@router.put("/interval")
def set_interval(data: dict, user=Depends(require_permission("settings", "edit"))):
    val = max(60, min(1800, int(data.get("interval", 60))))
    cfg = _read()
    cfg["push_interval"] = val
    _write(cfg)
    return {"interval": val}

@router.get("/telegram")
def get_telegram(user=Depends(require_permission("settings", "view"))):
    cfg = _read()
    return {
        "enabled":  cfg.get("telegram_enabled", False),
        "token":    cfg.get("telegram_token", ""),
        "chat_id":  cfg.get("telegram_chat_id", ""),
    }

@router.put("/telegram")
def set_telegram(data: dict, user=Depends(require_permission("settings", "edit"))):
    cfg = _read()
    cfg["telegram_enabled"] = bool(data.get("enabled", False))
    cfg["telegram_token"]   = str(data.get("token", ""))
    cfg["telegram_chat_id"] = str(data.get("chat_id", ""))
    _write(cfg)
    return {"ok": True}

@router.post("/telegram/test")
def test_telegram(user=Depends(require_permission("settings", "edit"))):
    import urllib.request
    cfg = _read()
    token = cfg.get("telegram_token","")
    chat  = cfg.get("telegram_chat_id","")
    if not (token and chat):
        return {"ok": False, "error": "Token o chat_id no configurados"}
    try:
        import json as _json
        url  = f"https://api.telegram.org/bot{token}/sendMessage"
        body = _json.dumps({"chat_id": chat, "text": "✅ SmartMonitor conectado correctamente"}).encode()
        req  = urllib.request.Request(url, data=body, headers={"Content-Type":"application/json"})
        urllib.request.urlopen(req, timeout=5)
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@router.get("/email")
def get_email(user=Depends(require_permission("settings", "view"))):
    from core.notify import DEFAULT_HTML_TEMPLATE, DEFAULT_SUBJECT_TEMPLATE
    cfg = _read()
    if not cfg.get("smtp_html_template"):
        cfg["smtp_html_template"] = DEFAULT_HTML_TEMPLATE
        _write(cfg)
    return {
        "enabled":          cfg.get("smtp_enabled", False),
        "host":             cfg.get("smtp_host", ""),
        "port":             cfg.get("smtp_port", 587),
        "username":         cfg.get("smtp_username", ""),
        "password":         "•" * 12 if cfg.get("smtp_password") else "",
        "from_addr":        cfg.get("smtp_from", ""),
        "to_addrs":         cfg.get("smtp_to", ""),
        "cc_addrs":         cfg.get("smtp_cc", ""),
        "bcc_addrs":        cfg.get("smtp_bcc", ""),
        "html_template":    cfg.get("smtp_html_template") or DEFAULT_HTML_TEMPLATE,
        "default_template": DEFAULT_HTML_TEMPLATE,
        "subject_template": cfg.get("smtp_subject_template") or DEFAULT_SUBJECT_TEMPLATE,
    }

@router.put("/email")
def set_email(data: dict, user=Depends(require_permission("settings", "edit"))):
    from core.notify import DEFAULT_HTML_TEMPLATE
    cfg = _read()
    cfg["smtp_enabled"]  = bool(data.get("enabled", False))
    cfg["smtp_host"]     = str(data.get("host", ""))
    cfg["smtp_port"]     = int(data.get("port", 587) or 587)
    cfg["smtp_username"] = str(data.get("username", ""))
    # Solo sobrescribir la contraseña si el usuario envió una nueva
    # (el GET nunca la revela en texto plano, así que un valor vacío o
    # de solo-puntos significa "sin cambios").
    pwd = data.get("password", "")
    if pwd and not set(pwd) <= {"•"}:
        cfg["smtp_password"] = pwd
    cfg["smtp_from"] = str(data.get("from_addr", ""))
    cfg["smtp_to"]   = str(data.get("to_addrs", ""))
    cfg["smtp_cc"]   = str(data.get("cc_addrs", ""))
    cfg["smtp_bcc"]  = str(data.get("bcc_addrs", ""))
    if "html_template" in data:
        val = (data.get("html_template") or "").strip()
        cfg["smtp_html_template"] = val or DEFAULT_HTML_TEMPLATE
    if "subject_template" in data:
        cfg["smtp_subject_template"] = str(data.get("subject_template") or "")
    _write(cfg)
    return {"ok": True}

@router.post("/email/test")
def test_email(user=Depends(require_permission("settings", "edit"))):
    from core.notify import send_email
    ok, err = send_email(
        "✅ SmartMonitor — prueba de conexión",
        "Este es un correo de prueba enviado desde SmartMonitor.",
        context={"equipo": "Equipo de prueba", "detalle": "Conexión de prueba exitosa"},
    )
    return {"ok": ok, "error": err}

# ── Tipos de dispositivo (configurables: nombre + icono) ──────────────────
DEFAULT_DEVICE_TYPES = [
    {"name": "Laptop",  "icon": "laptop"},
    {"name": "Desktop", "icon": "desktop"},
    {"name": "Tablet",  "icon": "tablet"},
    {"name": "Other",   "icon": "other"},
]

@router.get("/device-types")
def get_device_types(user=Depends(require_permission("settings", "view"))):
    cfg = _read()
    if "device_types" not in cfg:
        cfg["device_types"] = DEFAULT_DEVICE_TYPES
        _write(cfg)
    return {"device_types": cfg.get("device_types", DEFAULT_DEVICE_TYPES)}

@router.put("/device-types")
def set_device_types(data: dict, user=Depends(require_permission("settings", "edit"))):
    raw = data.get("device_types", [])
    clean = []
    for t in raw:
        name = str((t or {}).get("name", "")).strip()
        icon = str((t or {}).get("icon", "other")).strip() or "other"
        if name:
            clean.append({"name": name, "icon": icon})
    cfg = _read()
    cfg["device_types"] = clean
    _write(cfg)
    return {"device_types": clean}

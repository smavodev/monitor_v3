from fastapi import APIRouter, HTTPException
import os, ssl, urllib.request, urllib.parse, json

# Llamada interna (mismo host, 127.0.0.1) al puerto TLS de Headscale: el
# certificado real es para el dominio publico (ver HEADSCALE_PUBLIC_URL), no
# para 127.0.0.1, asi que la verificacion de hostname fallaria aunque la
# conexion en si sea local y de confianza. Se desactiva solo para esta
# llamada interna, nunca para lo que ve el agente (que usa el dominio real).
_INTERNAL_SSL_CTX = ssl.create_default_context()
_INTERNAL_SSL_CTX.check_hostname = False
_INTERNAL_SSL_CTX.verify_mode = ssl.CERT_NONE

router = APIRouter(prefix="/api/agents/wireguard", tags=["wireguard"])

# Headscale (servidor de coordinacion WireGuard self-hosted) le da a cada
# equipo una IP unica de "tailnet", para que dns_blocker.py pueda identificarlo
# sin depender de la IP publica compartida de la oficina (ver Agent.tailnet_ip).
# URL interna: la usa este contenedor para llamar a la API de Headscale.
HEADSCALE_URL        = os.getenv("HEADSCALE_URL", "http://127.0.0.1:8090")
# URL publica: la que se le devuelve al agente para que se conecte desde
# afuera. Suelen ser distintas (ej. 127.0.0.1 puertas adentro vs la IP/dominio
# real puertas afuera) — si no se define, se asume que son la misma.
HEADSCALE_PUBLIC_URL = os.getenv("HEADSCALE_PUBLIC_URL", HEADSCALE_URL)
HEADSCALE_API_KEY    = os.getenv("HEADSCALE_API_KEY", "")
HEADSCALE_USER_ID    = os.getenv("HEADSCALE_USER_ID", "1")
# IP del propio servidor SmartMonitor dentro del tunel (el primer nodo
# registrado en Headscale) - es a donde cada agente debe apuntar su DNS
# cuando esta conectado. Fija por env var: es estable mientras no se borre
# y re-registre ese nodo desde cero en Headscale.
HEADSCALE_SERVER_TAILNET_IP = os.getenv("HEADSCALE_SERVER_TAILNET_IP", "")


@router.post("/preauthkey")
def create_preauthkey(data: dict):
    """Emite una pre-auth key de un solo uso para que un agente nuevo se
    registre en Headscale durante la instalacion. No requiere autenticacion
    de usuario (igual que /blocklist): la protege que expira en 1 hora y solo
    sirve una vez."""
    if not HEADSCALE_API_KEY:
        raise HTTPException(503, "Headscale no esta configurado en este servidor (falta HEADSCALE_API_KEY)")

    hostname = str(data.get("hostname", "")).strip()
    if not hostname:
        raise HTTPException(400, "Falta hostname")

    from datetime import datetime, timedelta, timezone
    expiration = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    body = json.dumps({
        "user": HEADSCALE_USER_ID,
        "reusable": False,
        "ephemeral": False,
        "expiration": expiration,
    }).encode()
    req = urllib.request.Request(
        f"{HEADSCALE_URL}/api/v1/preauthkey",
        data=body, method="POST",
        headers={
            "Authorization": f"Bearer {HEADSCALE_API_KEY}",
            "Content-Type": "application/json",
        },
    )
    try:
        ctx = _INTERNAL_SSL_CTX if HEADSCALE_URL.startswith("https://") else None
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            resp = json.loads(r.read())
    except Exception as e:
        raise HTTPException(502, f"No se pudo generar la pre-auth key en Headscale: {e}")

    return {
        "login_server": HEADSCALE_PUBLIC_URL,
        "authkey": resp["preAuthKey"]["key"],
        "server_tailnet_ip": HEADSCALE_SERVER_TAILNET_IP,
    }


def rename_headscale_node(tailnet_ip: str, new_name: str) -> bool:
    """Renombra el 'nombre visible' (givenName) del nodo en Headscale para
    que coincida con el display_name que se le puso en SmartMonitor - NO
    toca el hostname real de Tailscale (name), que es el que usa MagicDNS
    puertas adentro del tailnet. Headscale ya distingue ambos conceptos,
    igual que Agent.hostname vs Agent.display_name aca.

    Se identifica el nodo por su tailnet_ip (unica) en vez de por nombre,
    porque el hostname original puede no coincidir mas con el actual.
    Best-effort: si Headscale no esta configurado o falla, no rompe el
    guardado en SmartMonitor - solo queda desincronizado hasta el proximo
    intento de renombrar."""
    if not (HEADSCALE_API_KEY and tailnet_ip and new_name):
        return False
    ctx = _INTERNAL_SSL_CTX if HEADSCALE_URL.startswith("https://") else None
    try:
        req = urllib.request.Request(
            f"{HEADSCALE_URL}/api/v1/node",
            headers={"Authorization": f"Bearer {HEADSCALE_API_KEY}"},
        )
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
            nodes = json.loads(r.read()).get("nodes", [])
        node = next((n for n in nodes if tailnet_ip in (n.get("ipAddresses") or [])), None)
        if not node:
            return False
        safe_name = urllib.parse.quote(str(new_name), safe="")
        req2 = urllib.request.Request(
            f"{HEADSCALE_URL}/api/v1/node/{node['id']}/rename/{safe_name}",
            method="POST",
            headers={"Authorization": f"Bearer {HEADSCALE_API_KEY}"},
        )
        with urllib.request.urlopen(req2, timeout=10, context=ctx):
            pass
        return True
    except Exception:
        return False

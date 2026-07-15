from fastapi import APIRouter, HTTPException
import os, urllib.request, json

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
        with urllib.request.urlopen(req, timeout=10) as r:
            resp = json.loads(r.read())
    except Exception as e:
        raise HTTPException(502, f"No se pudo generar la pre-auth key en Headscale: {e}")

    return {
        "login_server": HEADSCALE_PUBLIC_URL,
        "authkey": resp["preAuthKey"]["key"],
    }

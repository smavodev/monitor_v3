from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import secrets

from core.db import get_db
from core.permissions import require_permission
from models.models import Agent, AgentUninstallCode, AgentPauseCode

router = APIRouter(prefix="/api/agents", tags=["uninstall-codes"])

# Sin 0/O/1/I/L (se prestan a confusion al leerlos/tipearlos a mano).
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_CODE_LEN = 8
_EXPIRY_MINUTES = 30
_MAX_ATTEMPTS = 5

def _generate_code() -> str:
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LEN))

def _format_code(code: str) -> str:
    return f"{code[:4]}-{code[4:]}"

@router.post("/{agent_id}/uninstall-code")
def generate_uninstall_code(agent_id: str, user=Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(404, "Agente no encontrado")

    # Invalida cualquier codigo anterior sin usar de este equipo - a lo sumo
    # uno vigente a la vez, para no dejar codigos viejos dando vueltas.
    db.query(AgentUninstallCode).filter(
        AgentUninstallCode.agent_id == agent_id,
        AgentUninstallCode.used_at.is_(None),
        AgentUninstallCode.invalidated == False,
    ).update({"invalidated": True})

    code = _generate_code()
    expires_at = datetime.utcnow() + timedelta(minutes=_EXPIRY_MINUTES)
    rec = AgentUninstallCode(
        agent_id=agent_id, code=code, expires_at=expires_at,
        created_by=(user.name or user.email) if user else None,
    )
    db.add(rec)
    db.commit()
    return {"code": _format_code(code), "expires_at": expires_at.isoformat(), "expires_in_minutes": _EXPIRY_MINUTES}

@router.post("/uninstall-code/validate")
def validate_uninstall_code(data: dict, db: Session = Depends(get_db)):
    """Sin autenticacion de panel a proposito: lo llama el instalador/
    desinstalador corriendo como admin local en el equipo del usuario final,
    que no tiene sesion - misma categoria que /api/agents/blocklist y
    /api/agents/wireguard/preauthkey. La proteccion real es que el codigo
    solo lo puede conseguir un admin con acceso al panel."""
    serial = str(data.get("serial") or "").strip()
    hostname = str(data.get("hostname") or "").strip()
    submitted = str(data.get("code") or "").strip().upper().replace("-", "").replace(" ", "")

    agent = None
    if serial:
        agent = db.query(Agent).filter(Agent.serial_number == serial).first()
    if not agent and hostname:
        agent = db.query(Agent).filter(Agent.hostname == hostname).first()
    if not agent:
        raise HTTPException(404, "Equipo no reconocido por el servidor")

    rec = (
        db.query(AgentUninstallCode)
        .filter(AgentUninstallCode.agent_id == agent.id, AgentUninstallCode.invalidated == False, AgentUninstallCode.used_at.is_(None))
        .order_by(AgentUninstallCode.created_at.desc())
        .first()
    )
    if not rec:
        raise HTTPException(403, "No hay ningún código de desinstalación vigente para este equipo")
    if rec.expires_at < datetime.utcnow():
        rec.invalidated = True
        db.commit()
        raise HTTPException(403, "El código expiró")

    if rec.code != submitted:
        rec.attempts = (rec.attempts or 0) + 1
        if rec.attempts >= _MAX_ATTEMPTS:
            rec.invalidated = True
        db.commit()
        raise HTTPException(403, "Código incorrecto")

    rec.used_at = datetime.utcnow()
    db.commit()
    return {"valid": True}

@router.post("/{agent_id}/pause")
def pause_agent_blocking(agent_id: str, data: dict, user=Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    """Pausa (o reanuda, con paused_until=null) solo el filtrado de contenido
    de este equipo - el monitoreo/metricas no se ven afectados en absoluto,
    ver get_blocklist() en routers/agents.py."""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(404, "Agente no encontrado")

    raw = data.get("paused_until")
    if raw:
        try:
            paused_until = datetime.fromisoformat(str(raw).replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            raise HTTPException(400, "Fecha inválida")
    else:
        paused_until = None

    agent.paused_until = paused_until
    db.commit()
    # "Z" explicito: paused_until es naive-UTC - sin esto, el navegador del
    # admin interpreta el ISO string como su hora LOCAL, no UTC, y el estado
    # "Pausado hasta" del panel queda mal por el offset de su zona horaria
    # (mismo bug que ya se corrigio en generate_pause_code/expires_at).
    return {"paused_until": (paused_until.isoformat() + "Z") if paused_until else None}


# ── Pausa por codigo (tipo Kaspersky): la dispara el propio usuario del
# equipo desde el tray del agente, no el panel - mismo patron de codigo de
# un solo uso que arriba, pero de vigencia mas corta y pensado para pedirse
# varias veces al dia. Mientras esta pausado, resolve_should_block() (ver
# routers/agents.py) ya deja de bloquear sin ningun cambio adicional - esa
# funcion es el unico punto de verdad y ya respeta agent.paused_until.
_PAUSE_CODE_EXPIRY_MINUTES = 10   # vigencia del CODIGO para canjearlo (no de la pausa en si)
_PAUSE_MAX_DURATION_MINUTES = 8 * 60  # techo por pedido, aunque el cliente pida mas
_PAUSE_UNTIL_REBOOT_CAP_MINUTES = 24 * 60  # red de seguridad si el equipo nunca reinicia

def _find_agent_by_serial_or_hostname(db: Session, serial: str, hostname: str):
    agent = None
    if serial:
        agent = db.query(Agent).filter(Agent.serial_number == serial).first()
    if not agent and hostname:
        agent = db.query(Agent).filter(Agent.hostname == hostname).first()
    return agent

@router.post("/{agent_id}/pause-code")
def generate_pause_code(agent_id: str, user=Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    """Genera un codigo para que el usuario del equipo pause el bloqueo un
    rato el mismo - se lo comparte un administrador (ver boton en el panel)."""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(404, "Agente no encontrado")

    db.query(AgentPauseCode).filter(
        AgentPauseCode.agent_id == agent_id,
        AgentPauseCode.used_at.is_(None),
        AgentPauseCode.invalidated == False,
    ).update({"invalidated": True})

    code = _generate_code()
    expires_at = datetime.utcnow() + timedelta(minutes=_PAUSE_CODE_EXPIRY_MINUTES)
    rec = AgentPauseCode(
        agent_id=agent_id, code=code, expires_at=expires_at,
        created_by=(user.name or user.email) if user else None,
    )
    db.add(rec)
    db.commit()
    # "Z" explicito: expires_at es naive-UTC (datetime.utcnow()) - sin esto,
    # el navegador del admin interpreta el ISO string como su hora LOCAL, no
    # UTC, y el contador en vivo del panel queda mal por el offset de su
    # zona horaria (confirmado leyendo el codigo al agregar el contador).
    return {"code": _format_code(code), "expires_at": expires_at.isoformat() + "Z", "expires_in_minutes": _PAUSE_CODE_EXPIRY_MINUTES}

@router.post("/pause-code/validate")
def validate_pause_code(data: dict, db: Session = Depends(get_db)):
    """Sin autenticacion de panel a proposito, misma categoria que
    /uninstall-code/validate: lo llama el tray del agente corriendo en la
    sesion del usuario final. La proteccion real es que el codigo solo lo
    puede conseguir un administrador con acceso al panel.

    duration_minutes: cuanto pausar (se recorta a _PAUSE_MAX_DURATION_MINUTES).
    until_reboot: si viene true, ignora duration_minutes - el agente limpia
    la pausa el solo al arrancar (ver /clear-reboot-pause), con un techo de
    _PAUSE_UNTIL_REBOOT_CAP_MINUTES como red de seguridad si el equipo nunca
    reinicia."""
    serial = str(data.get("serial") or "").strip()
    hostname = str(data.get("hostname") or "").strip()
    submitted = str(data.get("code") or "").strip().upper().replace("-", "").replace(" ", "")
    until_reboot = bool(data.get("until_reboot"))
    try:
        duration_minutes = int(data.get("duration_minutes") or 0)
    except (TypeError, ValueError):
        duration_minutes = 0

    agent = _find_agent_by_serial_or_hostname(db, serial, hostname)
    if not agent:
        raise HTTPException(404, "Equipo no reconocido por el servidor")

    rec = (
        db.query(AgentPauseCode)
        .filter(AgentPauseCode.agent_id == agent.id, AgentPauseCode.invalidated == False, AgentPauseCode.used_at.is_(None))
        .order_by(AgentPauseCode.created_at.desc())
        .first()
    )
    if not rec:
        raise HTTPException(403, "No hay ningún código de pausa vigente para este equipo")
    if rec.expires_at < datetime.utcnow():
        rec.invalidated = True
        db.commit()
        raise HTTPException(403, "El código expiró")
    if rec.code != submitted:
        rec.attempts = (rec.attempts or 0) + 1
        if rec.attempts >= _MAX_ATTEMPTS:
            rec.invalidated = True
        db.commit()
        raise HTTPException(403, "Código incorrecto")

    rec.used_at = datetime.utcnow()

    if until_reboot:
        minutes = _PAUSE_UNTIL_REBOOT_CAP_MINUTES
        agent.pause_until_reboot = True
    else:
        minutes = max(1, min(duration_minutes or 5, _PAUSE_MAX_DURATION_MINUTES))
        agent.pause_until_reboot = False
    agent.paused_until = datetime.utcnow() + timedelta(minutes=minutes)
    db.commit()
    return {"paused_until": agent.paused_until.isoformat() + "Z", "until_reboot": until_reboot}

@router.post("/clear-reboot-pause")
def clear_reboot_pause(data: dict, db: Session = Depends(get_db)):
    """Llamado por el agente en cada arranque del Servicio (antes del loop
    principal) - si la pausa activa era "hasta reiniciar", la termina aca.
    Si no hay ninguna pausa de ese tipo, no hace nada (no falla ni molesta,
    el agente llama esto siempre al arrancar, haya o no pausa)."""
    serial = str(data.get("serial") or "").strip()
    hostname = str(data.get("hostname") or "").strip()
    agent = _find_agent_by_serial_or_hostname(db, serial, hostname)
    if not agent or not agent.pause_until_reboot:
        return {"cleared": False}
    agent.pause_until_reboot = False
    agent.paused_until = None
    db.commit()
    return {"cleared": True}

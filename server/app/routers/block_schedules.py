from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from zoneinfo import ZoneInfo
from core.db import get_db, get_current_user
from core.permissions import require_permission
from models.models import BlockSchedule, Agent, Sede

router = APIRouter(prefix="/api/block-schedules", tags=["block-schedules"])

WEEKDAY_KEYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
DEFAULT_DAYS = {
    "mon": ["06:00", "19:00"], "tue": ["06:00", "19:00"], "wed": ["06:00", "19:00"],
    "thu": ["06:00", "19:00"], "fri": ["06:00", "19:00"], "sat": ["06:00", "13:00"],
}

def _validate_days(days: dict) -> dict:
    clean = {}
    for key, rng in (days or {}).items():
        if key not in WEEKDAY_KEYS:
            raise HTTPException(400, f"Día inválido: {key}")
        if not (isinstance(rng, list) and len(rng) == 2):
            raise HTTPException(400, f"Rango inválido para {key}")
        start, end = rng
        for t in (start, end):
            if not isinstance(t, str) or len(t) != 5 or t[2] != ':':
                raise HTTPException(400, f"Hora inválida en {key}: {t} (usa HH:MM)")
        if start >= end:
            raise HTTPException(400, f"En {key} la hora de inicio debe ser antes que la de fin")
        clean[key] = [start, end]
    return clean

def seed_default_schedule(db: Session):
    existing = db.query(BlockSchedule).filter(
        BlockSchedule.agent_id.is_(None), BlockSchedule.sede_id.is_(None)
    ).first()
    if existing:
        return
    db.add(BlockSchedule(agent_id=None, sede_id=None, enabled=True, timezone="America/Lima", days=DEFAULT_DAYS))
    db.commit()

def _local_now(tz: Optional[str]) -> datetime:
    """'Ahora' como hora de pared naive en la zona horaria dada, para comparar
    contra expires_at (que se guarda naive, en la hora local de esa zona)."""
    try:
        return datetime.now(ZoneInfo(tz or "America/Lima")).replace(tzinfo=None)
    except Exception:
        return datetime.utcnow()

def resolve_schedule_for_agent(agent: Optional[Agent], db: Session) -> Optional[BlockSchedule]:
    if agent:
        s = db.query(BlockSchedule).filter(BlockSchedule.agent_id == agent.id).first()
        if s and (s.expires_at is None or s.expires_at > _local_now(s.timezone)):
            return s
        if agent.sede_id:
            s = db.query(BlockSchedule).filter(BlockSchedule.sede_id == agent.sede_id).first()
            if s:
                return s
    return db.query(BlockSchedule).filter(
        BlockSchedule.agent_id.is_(None), BlockSchedule.sede_id.is_(None)
    ).first()

def _purge_expired(db: Session):
    candidates = db.query(BlockSchedule).filter(
        BlockSchedule.agent_id.isnot(None), BlockSchedule.expires_at.isnot(None),
    ).all()
    changed = False
    for s in candidates:
        if s.expires_at <= _local_now(s.timezone):
            db.delete(s)
            changed = True
    if changed:
        db.commit()

def _parse_expires(v: Optional[str]) -> Optional[datetime]:
    if not v:
        return None
    try:
        return datetime.fromisoformat(v + "T23:59:59" if len(v) == 10 else v)
    except Exception:
        raise HTTPException(400, "Fecha de expiración inválida")

def is_within_schedule(schedule: Optional[BlockSchedule]) -> bool:
    if not schedule:
        return True  # sin horario configurado: no restringir (fail-open)
    if not schedule.enabled:
        return False
    tz = schedule.timezone or "America/Lima"
    try:
        now = datetime.now(ZoneInfo(tz))
    except Exception:
        now = datetime.utcnow()
    rng = (schedule.days or {}).get(WEEKDAY_KEYS[now.weekday()])
    if not rng:
        return False
    cur = now.strftime("%H:%M")
    return rng[0] <= cur <= rng[1]

class ScheduleUpdate(BaseModel):
    enabled: Optional[bool] = None
    timezone: Optional[str] = None
    days: Optional[dict] = None
    expires_at: Optional[str] = None

class ScheduleCreate(BaseModel):
    agent_id: Optional[str] = None
    sede_id: Optional[str] = None
    enabled: bool = True
    timezone: str = "America/Lima"
    days: dict = {}
    expires_at: Optional[str] = None

def _fmt(s: BlockSchedule, db: Session) -> dict:
    scope = "agent" if s.agent_id else ("sede" if s.sede_id else "global")
    target = "Global (todos los equipos)"
    if s.agent_id:
        a = db.query(Agent).filter(Agent.id == s.agent_id).first()
        target = (a.display_name or a.hostname) if a else "(equipo eliminado)"
    elif s.sede_id:
        sede = db.query(Sede).filter(Sede.id == s.sede_id).first()
        target = sede.name if sede else "(área eliminada)"
    return {
        "id": s.id, "scope": scope, "agent_id": s.agent_id, "sede_id": s.sede_id,
        "target": target, "enabled": s.enabled, "timezone": s.timezone,
        "days": s.days or {}, "created_at": s.created_at.isoformat() if s.created_at else None,
        "expires_at": s.expires_at.isoformat() if s.expires_at else None,
    }

@router.get("/default")
def get_default_schedule(user=Depends(require_permission("parental_schedule", "view")), db: Session = Depends(get_db)):
    seed_default_schedule(db)
    s = db.query(BlockSchedule).filter(BlockSchedule.agent_id.is_(None), BlockSchedule.sede_id.is_(None)).first()
    return _fmt(s, db)

@router.put("/default")
def update_default_schedule(data: ScheduleUpdate, user=Depends(require_permission("parental_schedule", "edit")), db: Session = Depends(get_db)):
    seed_default_schedule(db)
    s = db.query(BlockSchedule).filter(BlockSchedule.agent_id.is_(None), BlockSchedule.sede_id.is_(None)).first()
    if data.enabled is not None:
        s.enabled = data.enabled
    if data.timezone is not None:
        s.timezone = data.timezone
    if data.days is not None:
        s.days = _validate_days(data.days)
    db.commit()
    db.refresh(s)
    return _fmt(s, db)

@router.get("/inherited/{agent_id}")
def get_inherited_schedule(agent_id: str, user=Depends(require_permission("parental_schedule", "view")), db: Session = Depends(get_db)):
    """Horario que le tocaría a un equipo si NO tuviera su propia excepción
    (el de su área, o si no tiene área, el global). Sirve para precargar el
    formulario al crear una excepción nueva."""
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(404, "Equipo no encontrado")
    if agent.sede_id:
        s = db.query(BlockSchedule).filter(BlockSchedule.sede_id == agent.sede_id).first()
        if s:
            return _fmt(s, db)
    seed_default_schedule(db)
    s = db.query(BlockSchedule).filter(BlockSchedule.agent_id.is_(None), BlockSchedule.sede_id.is_(None)).first()
    return _fmt(s, db)

@router.get("/overrides")
def list_overrides(user=Depends(require_permission("parental_schedule", "view")), db: Session = Depends(get_db)):
    _purge_expired(db)
    rows = db.query(BlockSchedule).filter(
        (BlockSchedule.agent_id.isnot(None)) | (BlockSchedule.sede_id.isnot(None))
    ).order_by(BlockSchedule.created_at.desc()).all()
    return [_fmt(s, db) for s in rows]

@router.post("/overrides")
def create_override(data: ScheduleCreate, user=Depends(require_permission("parental_schedule", "edit")), db: Session = Depends(get_db)):
    if bool(data.agent_id) == bool(data.sede_id):
        raise HTTPException(400, "Elige exactamente un equipo o un área para la excepción")
    if data.agent_id and not db.query(Agent).filter(Agent.id == data.agent_id).first():
        raise HTTPException(404, "Equipo no encontrado")
    if data.sede_id and not db.query(Sede).filter(Sede.id == data.sede_id).first():
        raise HTTPException(404, "Área no encontrada")
    existing = db.query(BlockSchedule).filter(
        BlockSchedule.agent_id == data.agent_id, BlockSchedule.sede_id == data.sede_id
    ).first() if (data.agent_id or data.sede_id) else None
    if existing:
        raise HTTPException(400, "Ya existe una excepción de horario para ese alcance, edítala en vez de crear otra")
    s = BlockSchedule(
        agent_id=data.agent_id, sede_id=data.sede_id, enabled=data.enabled,
        timezone=data.timezone, days=_validate_days(data.days),
        expires_at=_parse_expires(data.expires_at),
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return _fmt(s, db)

@router.put("/overrides/{sched_id}")
def update_override(sched_id: str, data: ScheduleUpdate, user=Depends(require_permission("parental_schedule", "edit")), db: Session = Depends(get_db)):
    s = db.query(BlockSchedule).filter(BlockSchedule.id == sched_id).first()
    if not s or (not s.agent_id and not s.sede_id):
        raise HTTPException(404, "Excepción de horario no encontrada")
    if data.enabled is not None:
        s.enabled = data.enabled
    if data.timezone is not None:
        s.timezone = data.timezone
    if data.days is not None:
        s.days = _validate_days(data.days)
    s.expires_at = _parse_expires(data.expires_at)
    db.commit()
    db.refresh(s)
    return _fmt(s, db)

@router.delete("/overrides/{sched_id}")
def delete_override(sched_id: str, user=Depends(require_permission("parental_schedule", "edit")), db: Session = Depends(get_db)):
    s = db.query(BlockSchedule).filter(BlockSchedule.id == sched_id).first()
    if not s or (not s.agent_id and not s.sede_id):
        raise HTTPException(404, "Excepción de horario no encontrada")
    db.delete(s)
    db.commit()
    return {"ok": True}

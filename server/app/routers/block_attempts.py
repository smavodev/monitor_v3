from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel
from typing import Optional
from datetime import timedelta, datetime

from core.db import get_db
from core.permissions import require_permission
from models.models import BlockAttempt, BlockAttemptConfig, Agent, Sede, BlockedSite
from routers.block_schedules import _local_now

router = APIRouter(prefix="/api", tags=["block-attempts"])

CONFIG_ID = "default"

def seed_default_config(db: Session):
    if db.query(BlockAttemptConfig).filter(BlockAttemptConfig.id == CONFIG_ID).first():
        return
    db.add(BlockAttemptConfig(id=CONFIG_ID, retention_days=None))
    db.commit()

def purge_expired(db: Session):
    cfg = db.query(BlockAttemptConfig).filter(BlockAttemptConfig.id == CONFIG_ID).first()
    if not cfg or not cfg.retention_days:
        return
    cutoff = _local_now(None).date() - timedelta(days=cfg.retention_days)
    db.query(BlockAttempt).filter(BlockAttempt.date < cutoff).delete()
    db.commit()

def upsert_attempts(db: Session, agent_id: str, entries, now=None):
    """Inserta/incrementa filas de BlockAttempt. `entries` es un iterable de
    tuplas (domain, count, blocked). La usa dns_blocker.py al resolver DNS,
    que es la fuente de verdad de los intentos de acceso."""
    now = now or _local_now(None)
    today = now.date()
    for domain, count, blocked in entries:
        if count <= 0 or not domain:
            continue
        row = db.query(BlockAttempt).filter(
            BlockAttempt.agent_id == agent_id,
            BlockAttempt.domain == domain,
            BlockAttempt.date == today,
            BlockAttempt.blocked == blocked,
        ).first()
        if row:
            row.count += count
            row.last_seen = now
        else:
            db.add(BlockAttempt(agent_id=agent_id, domain=domain, date=today,
                                 blocked=blocked, count=count, last_seen=now))

def _find_exception(domain: str, agent: Optional[Agent], exceptions: list):
    """De las excepciones vigentes, busca la que probablemente dejó pasar este
    dominio (coincidencia exacta o de subdominio), priorizando Equipo > Área >
    Global — igual que la prioridad de resolve_domains_for_agent."""
    def matches(s):
        d = s.domain.lower()
        return domain == d or domain.endswith('.' + d)
    candidates = [s for s in exceptions if matches(s)]
    if not candidates:
        return None
    if agent:
        for s in candidates:
            if s.agent_id == agent.id:
                return s
        if agent.sede_id:
            for s in candidates:
                if s.sede_id == agent.sede_id:
                    return s
    for s in candidates:
        if s.agent_id is None and s.sede_id is None:
            return s
    return candidates[0]

def _fmt(r: BlockAttempt, agents_by_id: dict, sedes_by_id: dict, exceptions: list):
    a = agents_by_id.get(r.agent_id)
    sede_name = None
    if a and a.sede_id:
        s = sedes_by_id.get(a.sede_id)
        sede_name = s.name if s else None
    has_exception, exc_reason, exc_expires = False, None, None
    if not r.blocked:
        exc = _find_exception(r.domain, a, exceptions)
        if exc:
            has_exception = True
            exc_reason = exc.reason
            exc_expires = exc.expires_at.isoformat() if exc.expires_at else None
    return {
        "id": r.id, "agent_id": r.agent_id,
        "agent_name": (a.display_name or a.hostname) if a else "—",
        "tailnet_ip": (a.tailnet_ip if a else None),
        "sede_name": sede_name,
        "domain": r.domain, "count": r.count, "blocked": r.blocked,
        "has_exception": has_exception, "exception_reason": exc_reason, "exception_expires": exc_expires,
        "date": r.date.isoformat(), "last_seen": r.last_seen.isoformat(),
    }

@router.get("/block-attempts")
def list_block_attempts(
    agent_id: Optional[str] = Query(None),
    sede_id: Optional[str] = Query(None),  # "__none__" = equipos sin área asignada
    days: int = Query(7, ge=1, le=365),
    status: Optional[str] = Query(None),  # "blocked" | "allowed" | None (todos)
    user=Depends(require_permission("parental_attempts", "view")), db: Session = Depends(get_db),
):
    now = _local_now(None)
    since_date = now.date() - timedelta(days=days - 1)

    # Total "global" = mismo rango de días, sin los demás filtros (área/equipo/
    # estado) — sirve de referencia de "cuántos hay en total" junto al filtrado.
    total_count = db.query(BlockAttempt).filter(BlockAttempt.date >= since_date).count()

    q = db.query(BlockAttempt).filter(BlockAttempt.date >= since_date)
    if agent_id:
        q = q.filter(BlockAttempt.agent_id == agent_id)
    elif sede_id == "__none__":
        ids = [a.id for a in db.query(Agent).filter(Agent.sede_id.is_(None)).all()]
        q = q.filter(BlockAttempt.agent_id.in_(ids))
    elif sede_id:
        ids = [a.id for a in db.query(Agent).filter(Agent.sede_id == sede_id).all()]
        q = q.filter(BlockAttempt.agent_id.in_(ids))
    if status == "blocked":
        q = q.filter(BlockAttempt.blocked == True)
    elif status == "allowed":
        q = q.filter(BlockAttempt.blocked == False)
    # Más recientes primero de verdad: por el momento real del último intento,
    # no por fecha+cantidad (eso no reflejaba qué pasó más recientemente).
    rows = q.order_by(BlockAttempt.last_seen.desc()).all()

    agents_by_id = {a.id: a for a in db.query(Agent).all()}
    sedes_by_id = {s.id: s for s in db.query(Sede).all()}
    exceptions = db.query(BlockedSite).filter(
        BlockedSite.active == True, BlockedSite.is_exception == True,
    ).all()
    exceptions = [e for e in exceptions if e.expires_at is None or e.expires_at > now]

    # Promedio de intentos/minuto del conjunto filtrado — no hay timestamp por
    # intento individual (se agrega por día), así que se aproxima como
    # intentos totales / minutos transcurridos desde el inicio del rango.
    since_dt = datetime.combine(since_date, datetime.min.time())
    minutes_elapsed = max((now - since_dt).total_seconds() / 60, 1)
    total_attempts_filtered = sum(r.count for r in rows)
    rate_per_minute = round(total_attempts_filtered / minutes_elapsed, 3)

    return {
        "items": [_fmt(r, agents_by_id, sedes_by_id, exceptions) for r in rows],
        "filtered_count": len(rows),
        "total_count": total_count,
        "rate_per_minute": rate_per_minute,
    }

class RetentionUpdate(BaseModel):
    retention_days: Optional[int] = None

@router.get("/block-attempts/retention")
def get_retention(user=Depends(require_permission("parental_attempts", "view")), db: Session = Depends(get_db)):
    cfg = db.query(BlockAttemptConfig).filter(BlockAttemptConfig.id == CONFIG_ID).first()
    return {"retention_days": cfg.retention_days if cfg else None}

@router.put("/block-attempts/retention")
def update_retention(data: RetentionUpdate, user=Depends(require_permission("parental_attempts", "edit")), db: Session = Depends(get_db)):
    if data.retention_days is not None and data.retention_days < 1:
        raise HTTPException(400, "retention_days debe ser mayor a 0")
    cfg = db.query(BlockAttemptConfig).filter(BlockAttemptConfig.id == CONFIG_ID).first()
    if not cfg:
        cfg = BlockAttemptConfig(id=CONFIG_ID)
        db.add(cfg)
    cfg.retention_days = data.retention_days
    db.commit()
    return {"retention_days": cfg.retention_days}

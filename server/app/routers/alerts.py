from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from core.db import get_db
from core.permissions import require_permission
from models.models import AlertConfig, Agent

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

def _get_or_create(db: Session, agent_id=None):
    cfg = db.query(AlertConfig).filter(AlertConfig.agent_id == agent_id).first()
    if not cfg:
        cfg = AlertConfig(agent_id=agent_id)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg

def _fmt(cfg):
    return {
        "agent_id":      cfg.agent_id,
        "cpu_threshold": cfg.cpu_threshold,
        "ram_threshold": cfg.ram_threshold,
        "disk_threshold":cfg.disk_threshold,
        "temp_threshold":cfg.temp_threshold,
    }

@router.get("/config/global")
def get_global(user=Depends(require_permission("alerts", "view")), db: Session=Depends(get_db)):
    return _fmt(_get_or_create(db, None))

@router.put("/config/global")
def set_global(data: dict, user=Depends(require_permission("alerts", "edit")), db: Session=Depends(get_db)):
    cfg = _get_or_create(db, None)
    for field in ("cpu_threshold","ram_threshold","disk_threshold","temp_threshold"):
        if field in data:
            setattr(cfg, field, float(data[field]))
    db.commit()
    return _fmt(cfg)

@router.get("/config/{agent_id}")
def get_agent(agent_id: str, user=Depends(require_permission("alerts", "view")), db: Session=Depends(get_db)):
    cfg = db.query(AlertConfig).filter(AlertConfig.agent_id == agent_id).first()
    if cfg:
        return {**_fmt(cfg), "custom": True}
    return {**_fmt(_get_or_create(db, None)), "custom": False}

@router.put("/config/{agent_id}")
def set_agent(agent_id: str, data: dict, user=Depends(require_permission("alerts", "edit")), db: Session=Depends(get_db)):
    if not db.query(Agent).filter(Agent.id == agent_id).first():
        raise HTTPException(404, "Agente no encontrado")
    cfg = _get_or_create(db, agent_id)
    for field in ("cpu_threshold","ram_threshold","disk_threshold","temp_threshold"):
        if field in data:
            setattr(cfg, field, float(data[field]))
    db.commit()
    return {**_fmt(cfg), "custom": True}

@router.delete("/config/{agent_id}")
def del_agent(agent_id: str, user=Depends(require_permission("alerts", "edit")), db: Session=Depends(get_db)):
    cfg = db.query(AlertConfig).filter(AlertConfig.agent_id == agent_id).first()
    if cfg:
        db.delete(cfg)
        db.commit()
    return {"ok": True}

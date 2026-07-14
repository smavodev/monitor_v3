from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from core.db import get_db
from core.permissions import require_permission
from models.models import Maintenance, MaintenanceMonitor
from datetime import datetime

router = APIRouter(prefix="/api/maintenance", tags=["maintenance"])

def _fmt(m: Maintenance) -> dict:
    monitor_ids = [mm.service_id for mm in m.monitors]
    return {
        "id": m.id, "title": m.title, "description": m.description,
        "status": m.status, "strategy": m.strategy, "active": m.active,
        "start_date": m.start_date.isoformat() if m.start_date else None,
        "end_date":   m.end_date.isoformat()   if m.end_date   else None,
        "start_time": m.start_time, "end_time": m.end_time,
        "timezone": m.timezone,
        "weekdays": m.weekdays, "days_of_month": m.days_of_month,
        "interval_days": m.interval_days, "cron_expr": m.cron_expr,
        "monitor_ids": monitor_ids,
        "created_at": m.created_at.isoformat() if m.created_at else None,
    }

def _parse_dt(s):
    if not s: return None
    try: return datetime.fromisoformat(s.replace("Z",""))
    except Exception: return None

@router.get("")
def list_maintenance(user=Depends(require_permission("maintenance", "view")), db: Session = Depends(get_db)):
    return [_fmt(m) for m in db.query(Maintenance).order_by(Maintenance.created_at.desc()).all()]

@router.post("")
def create_maintenance(data: dict, user=Depends(require_permission("maintenance", "edit")), db: Session = Depends(get_db)):
    m = Maintenance(
        title=data.get("title","Maintenance"),
        description=data.get("description"),
        strategy=data.get("strategy","manual"),
        active=data.get("active", True),
        start_date=_parse_dt(data.get("start_date")),
        end_date=_parse_dt(data.get("end_date")),
        start_time=data.get("start_time"),
        end_time=data.get("end_time"),
        timezone=data.get("timezone","UTC"),
        weekdays=data.get("weekdays"),
        days_of_month=data.get("days_of_month"),
        interval_days=data.get("interval_days"),
        cron_expr=data.get("cron_expr"),
        status="active" if data.get("strategy","manual") == "manual" else "scheduled",
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    for svc_id in (data.get("monitor_ids") or []):
        db.add(MaintenanceMonitor(maintenance_id=m.id, service_id=svc_id))
    db.commit()
    db.refresh(m)
    return _fmt(m)

@router.put("/{mid}")
def update_maintenance(mid: str, data: dict, user=Depends(require_permission("maintenance", "edit")), db: Session = Depends(get_db)):
    m = db.query(Maintenance).filter(Maintenance.id == mid).first()
    if not m: raise HTTPException(404, "Not found")
    for f in ("title","description","strategy","active","start_time","end_time","timezone",
              "weekdays","days_of_month","interval_days","cron_expr","status"):
        if f in data: setattr(m, f, data[f])
    if "start_date" in data: m.start_date = _parse_dt(data["start_date"])
    if "end_date"   in data: m.end_date   = _parse_dt(data["end_date"])
    if "monitor_ids" in data:
        db.query(MaintenanceMonitor).filter(MaintenanceMonitor.maintenance_id == mid).delete()
        for svc_id in (data["monitor_ids"] or []):
            db.add(MaintenanceMonitor(maintenance_id=mid, service_id=svc_id))
    db.commit()
    db.refresh(m)
    return _fmt(m)

@router.delete("/{mid}")
def delete_maintenance(mid: str, user=Depends(require_permission("maintenance", "edit")), db: Session = Depends(get_db)):
    m = db.query(Maintenance).filter(Maintenance.id == mid).first()
    if m: db.delete(m); db.commit()
    return {"ok": True}

@router.post("/{mid}/pause")
def toggle_maintenance(mid: str, user=Depends(require_permission("maintenance", "edit")), db: Session = Depends(get_db)):
    m = db.query(Maintenance).filter(Maintenance.id == mid).first()
    if not m: raise HTTPException(404, "Not found")
    m.active = not m.active
    db.commit()
    return _fmt(m)

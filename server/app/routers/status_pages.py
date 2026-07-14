from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from core.db import get_db
from core.permissions import require_permission
from models.models import StatusPage, StatusPageGroup, StatusPageMonitor, ServiceCheck, ServiceCheckHistory
from datetime import datetime, timedelta
import json

router = APIRouter(prefix="/api/status-pages", tags=["status-pages"])

def _uptime(history, hours=24):
    since = datetime.utcnow() - timedelta(hours=hours)
    rows  = [h for h in history if h.timestamp >= since and h.status not in ("pending","maintenance")]
    if not rows: return None
    return round(sum(1 for h in rows if h.status == "up") / len(rows) * 100, 1)

def _fmt(sp: StatusPage) -> dict:
    return {
        "id": sp.id, "slug": sp.slug, "title": sp.title,
        "description": sp.description, "icon": sp.icon,
        "theme": sp.theme, "published": sp.published,
        "show_tags": sp.show_tags, "footer_text": sp.footer_text,
        "groups": [
            {
                "id": g.id, "name": g.name, "order": g.order,
                "monitors": [{"service_id": m.service_id, "order": m.order} for m in g.monitors]
            }
            for g in sp.groups
        ],
        "created_at": sp.created_at.isoformat() if sp.created_at else None,
    }

@router.get("")
def list_pages(user=Depends(require_permission("status_pages", "view")), db: Session = Depends(get_db)):
    return [_fmt(p) for p in db.query(StatusPage).order_by(StatusPage.created_at).all()]

@router.post("")
def create_page(data: dict, user=Depends(require_permission("status_pages", "edit")), db: Session = Depends(get_db)):
    sp = StatusPage(
        slug=data["slug"], title=data.get("title","Status"),
        description=data.get("description"), icon=data.get("icon"),
        theme=data.get("theme","dark"), published=data.get("published",True),
        show_tags=data.get("show_tags",False), footer_text=data.get("footer_text"),
    )
    db.add(sp)
    db.commit()
    db.refresh(sp)
    for g_data in (data.get("groups") or []):
        g = StatusPageGroup(status_page_id=sp.id, name=g_data.get("name","Monitors"), order=g_data.get("order",0))
        db.add(g)
        db.commit()
        db.refresh(g)
        for i, m in enumerate(g_data.get("monitors") or []):
            db.add(StatusPageMonitor(group_id=g.id, service_id=m["service_id"], order=i))
    db.commit()
    db.refresh(sp)
    return _fmt(sp)

@router.put("/{pid}")
def update_page(pid: str, data: dict, user=Depends(require_permission("status_pages", "edit")), db: Session = Depends(get_db)):
    sp = db.query(StatusPage).filter(StatusPage.id == pid).first()
    if not sp: raise HTTPException(404, "Not found")
    for f in ("slug","title","description","icon","theme","published","show_tags","footer_text"):
        if f in data: setattr(sp, f, data[f])
    if "groups" in data:
        for g in sp.groups:
            db.delete(g)
        db.commit()
        for g_data in (data["groups"] or []):
            g = StatusPageGroup(status_page_id=sp.id, name=g_data.get("name","Monitors"), order=g_data.get("order",0))
            db.add(g)
            db.commit()
            db.refresh(g)
            for i, m in enumerate(g_data.get("monitors") or []):
                db.add(StatusPageMonitor(group_id=g.id, service_id=m["service_id"], order=i))
    db.commit()
    db.refresh(sp)
    return _fmt(sp)

@router.delete("/{pid}")
def delete_page(pid: str, user=Depends(require_permission("status_pages", "edit")), db: Session = Depends(get_db)):
    sp = db.query(StatusPage).filter(StatusPage.id == pid).first()
    if sp: db.delete(sp); db.commit()
    return {"ok": True}

# ── Public endpoint ────────────────────────────────────────────────────────────
@router.get("/public/{slug}")
def public_page_data(slug: str, db: Session = Depends(get_db)):
    sp = db.query(StatusPage).filter(StatusPage.slug == slug, StatusPage.published == True).first()
    if not sp: raise HTTPException(404, "Status page not found")
    result = {
        "title": sp.title, "description": sp.description,
        "icon": sp.icon, "theme": sp.theme, "footer_text": sp.footer_text,
        "groups": [],
    }
    for g in sp.groups:
        monitors = []
        for pm in g.monitors:
            svc = db.query(ServiceCheck).filter(ServiceCheck.id == pm.service_id).first()
            if not svc: continue
            since = datetime.utcnow() - timedelta(days=30)
            hist  = db.query(ServiceCheckHistory)\
                      .filter(ServiceCheckHistory.service_id == svc.id,
                              ServiceCheckHistory.timestamp >= since)\
                      .order_by(ServiceCheckHistory.timestamp).all()
            hb = [{"s": h.status, "t": h.timestamp.isoformat()+"Z", "l": h.latency_ms}
                  for h in hist[-90:]]
            monitors.append({
                "id": svc.id, "name": svc.name, "type": svc.type,
                "status": svc.last_status, "uptime_24h": _uptime(hist, 24),
                "heartbeat": hb,
            })
        result["groups"].append({"name": g.name, "monitors": monitors})
    return result

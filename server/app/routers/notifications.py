from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from core.db import get_db
from core.permissions import require_permission
from models.models import NotificationChannel
import json, urllib.request

router = APIRouter(prefix="/api/notifications", tags=["notifications"])

def _fmt(ch: NotificationChannel) -> dict:
    cfg = json.loads(ch.config_json or "{}")
    # Mask secrets
    for k in ("password","token","api_key","app_token","access_token","webhook_url",
              "client_secret","integration_key","user_key"):
        if k in cfg and cfg[k]:
            cfg[k] = "***"
    return {
        "id": ch.id, "name": ch.name, "type": ch.type,
        "is_default": ch.is_default, "active": ch.active,
        "config": cfg,
        "created_at": ch.created_at.isoformat() if ch.created_at else None,
    }

@router.get("")
def list_channels(user=Depends(require_permission("notifications", "view")), db: Session = Depends(get_db)):
    return [_fmt(c) for c in db.query(NotificationChannel).order_by(NotificationChannel.created_at).all()]

@router.post("")
def create_channel(data: dict, user=Depends(require_permission("notifications", "edit")), db: Session = Depends(get_db)):
    ch = NotificationChannel(
        name=data.get("name","New Notification"),
        type=data.get("type","webhook"),
        config_json=json.dumps(data.get("config",{})),
        is_default=bool(data.get("is_default", False)),
        active=True,
    )
    db.add(ch)
    db.commit()
    db.refresh(ch)
    return _fmt(ch)

@router.put("/{nid}")
def update_channel(nid: str, data: dict, user=Depends(require_permission("notifications", "edit")), db: Session = Depends(get_db)):
    ch = db.query(NotificationChannel).filter(NotificationChannel.id == nid).first()
    if not ch:
        raise HTTPException(404, "Not found")
    if "name" in data:       ch.name       = data["name"]
    if "type" in data:       ch.type       = data["type"]
    if "is_default" in data: ch.is_default = data["is_default"]
    if "active" in data:     ch.active     = data["active"]
    if "config" in data:
        # Merge config preserving masked secrets
        existing = json.loads(ch.config_json or "{}")
        new_cfg  = data["config"]
        for k, v in new_cfg.items():
            if v != "***":
                existing[k] = v
        ch.config_json = json.dumps(existing)
    db.commit()
    return _fmt(ch)

@router.delete("/{nid}")
def delete_channel(nid: str, user=Depends(require_permission("notifications", "edit")), db: Session = Depends(get_db)):
    ch = db.query(NotificationChannel).filter(NotificationChannel.id == nid).first()
    if ch:
        db.delete(ch)
        db.commit()
    return {"ok": True}

@router.post("/{nid}/test")
def test_channel(nid: str, user=Depends(require_permission("notifications", "edit")), db: Session = Depends(get_db)):
    ch = db.query(NotificationChannel).filter(NotificationChannel.id == nid).first()
    if not ch:
        raise HTTPException(404, "Not found")
    from routers.services import _dispatch_notification
    try:
        _dispatch_notification(ch, f"🔔 Test notification from SmartMonitor3\nChannel: {ch.name}")
        return {"ok": True, "msg": "Notification sent"}
    except Exception as e:
        raise HTTPException(500, str(e))

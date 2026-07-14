from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from core.db import get_db
from core.permissions import require_permission
from models.models import Proxy

router = APIRouter(prefix="/api/proxies", tags=["proxies"])

def _fmt(p: Proxy) -> dict:
    return {
        "id": p.id, "protocol": p.protocol, "host": p.host, "port": p.port,
        "auth": p.auth, "username": p.username,
        "password": "***" if p.password else None,
        "active": p.active, "is_default": p.is_default,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }

@router.get("")
def list_proxies(user=Depends(require_permission("proxies", "view")), db: Session = Depends(get_db)):
    return [_fmt(p) for p in db.query(Proxy).order_by(Proxy.created_at).all()]

@router.post("")
def create_proxy(data: dict, user=Depends(require_permission("proxies", "edit")), db: Session = Depends(get_db)):
    p = Proxy(
        protocol=data.get("protocol","http"),
        host=data["host"], port=int(data["port"]),
        auth=bool(data.get("auth", False)),
        username=data.get("username"), password=data.get("password"),
        active=True, is_default=data.get("is_default", False),
    )
    if p.is_default:
        db.query(Proxy).update({"is_default": False})
    db.add(p)
    db.commit()
    db.refresh(p)
    return _fmt(p)

@router.put("/{pid}")
def update_proxy(pid: str, data: dict, user=Depends(require_permission("proxies", "edit")), db: Session = Depends(get_db)):
    p = db.query(Proxy).filter(Proxy.id == pid).first()
    if not p: raise HTTPException(404, "Not found")
    for f in ("protocol","host","port","auth","username","active","is_default"):
        if f in data: setattr(p, f, data[f])
    if "password" in data and data["password"] != "***":
        p.password = data["password"]
    if data.get("is_default"):
        db.query(Proxy).filter(Proxy.id != pid).update({"is_default": False})
    db.commit()
    return _fmt(p)

@router.delete("/{pid}")
def delete_proxy(pid: str, user=Depends(require_permission("proxies", "edit")), db: Session = Depends(get_db)):
    p = db.query(Proxy).filter(Proxy.id == pid).first()
    if p: db.delete(p); db.commit()
    return {"ok": True}

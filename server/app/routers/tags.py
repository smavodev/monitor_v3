from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from core.db import get_db
from core.permissions import require_permission
from models.models import Tag, MonitorTag

router = APIRouter(prefix="/api/tags", tags=["tags"])

def _fmt(t: Tag) -> dict:
    return {"id": t.id, "name": t.name, "color": t.color, "description": t.description,
            "monitor_count": len(t.monitors)}

@router.get("")
def list_tags(user=Depends(require_permission("tags", "view")), db: Session = Depends(get_db)):
    return [_fmt(t) for t in db.query(Tag).order_by(Tag.name).all()]

@router.post("")
def create_tag(data: dict, user=Depends(require_permission("tags", "edit")), db: Session = Depends(get_db)):
    t = Tag(name=data["name"], color=data.get("color","#3b82f6"), description=data.get("description"))
    db.add(t)
    db.commit()
    db.refresh(t)
    return _fmt(t)

@router.put("/{tid}")
def update_tag(tid: str, data: dict, user=Depends(require_permission("tags", "edit")), db: Session = Depends(get_db)):
    t = db.query(Tag).filter(Tag.id == tid).first()
    if not t:
        raise HTTPException(404, "Not found")
    if "name"        in data: t.name        = data["name"]
    if "color"       in data: t.color       = data["color"]
    if "description" in data: t.description = data["description"]
    db.commit()
    return _fmt(t)

@router.delete("/{tid}")
def delete_tag(tid: str, user=Depends(require_permission("tags", "edit")), db: Session = Depends(get_db)):
    t = db.query(Tag).filter(Tag.id == tid).first()
    if t:
        db.delete(t)
        db.commit()
    return {"ok": True}

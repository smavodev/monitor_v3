from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from core.db import get_db
from core.permissions import require_permission
from models.models import Sede

router = APIRouter(prefix="/api/sedes", tags=["sedes"])

class SedeCreate(BaseModel):
    name: str
    location: str = ""

class SedeUpdate(BaseModel):
    name: str | None = None
    location: str | None = None

def _fmt(s: Sede) -> dict:
    return {"id": s.id, "name": s.name, "location": s.location, "agents": len(s.agents)}

@router.get("")
def list_sedes(user=Depends(require_permission("areas", "view")), db: Session = Depends(get_db)):
    return [_fmt(s) for s in db.query(Sede).all()]

@router.post("")
def create_sede(data: SedeCreate, user=Depends(require_permission("areas", "edit")), db: Session = Depends(get_db)):
    sede = Sede(name=data.name, location=data.location)
    db.add(sede)
    db.commit()
    db.refresh(sede)
    return _fmt(sede)

@router.put("/{sede_id}")
def update_sede(sede_id: str, data: SedeUpdate, user=Depends(require_permission("areas", "edit")), db: Session = Depends(get_db)):
    sede = db.query(Sede).filter(Sede.id == sede_id).first()
    if not sede:
        raise HTTPException(404, "Área no encontrada")
    if data.name is not None:
        sede.name = data.name
    if data.location is not None:
        sede.location = data.location
    db.commit()
    db.refresh(sede)
    return _fmt(sede)

@router.delete("/{sede_id}")
def delete_sede(sede_id: str, user=Depends(require_permission("areas", "edit")), db: Session = Depends(get_db)):
    sede = db.query(Sede).filter(Sede.id == sede_id).first()
    if not sede:
        raise HTTPException(404, "Área no encontrada")
    db.delete(sede)
    db.commit()
    return {"ok": True}

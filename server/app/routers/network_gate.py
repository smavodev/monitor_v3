from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List

from core.db import get_db
from core.permissions import require_permission
from models.models import NetworkGateConfig

router = APIRouter(prefix="/api/network-gate", tags=["network-gate"])

CONFIG_ID = "default"

def seed_default(db: Session):
    if db.query(NetworkGateConfig).filter(NetworkGateConfig.id == CONFIG_ID).first():
        return
    db.add(NetworkGateConfig(id=CONFIG_ID, enabled=False, networks=[]))
    db.commit()

def _get_config(db: Session) -> NetworkGateConfig:
    cfg = db.query(NetworkGateConfig).filter(NetworkGateConfig.id == CONFIG_ID).first()
    if not cfg:
        cfg = NetworkGateConfig(id=CONFIG_ID, enabled=False, networks=[])
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg

def is_network_allowed(ssid: Optional[str], db: Session) -> bool:
    """True si las reglas de bloqueo deben aplicarse dado el SSID actual del equipo.
    Si el toggle está desactivado, siempre True (comportamiento normal del sistema).
    Si está activado, solo True cuando el SSID coincide con una de las redes definidas."""
    cfg = _get_config(db)
    if not cfg.enabled:
        return True
    if not ssid:
        return False
    allowed = {n.strip().lower() for n in (cfg.networks or [])}
    return ssid.strip().lower() in allowed

class NetworkGateUpdate(BaseModel):
    enabled: bool
    networks: List[str] = []

@router.get("")
def get_network_gate(user=Depends(require_permission("parental_blocked", "view")), db: Session = Depends(get_db)):
    cfg = _get_config(db)
    return {"enabled": cfg.enabled, "networks": cfg.networks or []}

@router.put("")
def update_network_gate(data: NetworkGateUpdate, user=Depends(require_permission("parental_blocked", "edit")), db: Session = Depends(get_db)):
    cfg = _get_config(db)
    cfg.enabled = data.enabled
    cfg.networks = [n.strip() for n in data.networks if n and n.strip()]
    db.commit()
    return {"enabled": cfg.enabled, "networks": cfg.networks or []}

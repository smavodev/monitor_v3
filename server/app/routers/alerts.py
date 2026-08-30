from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc
from core.db import get_db
from core.permissions import require_permission
from models.models import AlertConfig, Agent, Metric
from routers.agents import check_metric_alerts

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

# Los umbrales de alerta (CPU/RAM/Disco/Temperatura) son UNA sola
# configuracion global para todos los equipos - no por agente (esa opcion
# existia en el modelo pero nunca tuvo una UI funcional conectada, y
# complicaba innecesariamente algo que se quiere igual para todo el parque).
def _get_or_create_global(db: Session):
    cfg = db.query(AlertConfig).filter(AlertConfig.agent_id == None).first()
    if not cfg:
        cfg = AlertConfig(agent_id=None)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg

def _fmt(cfg):
    return {
        "cpu_threshold": cfg.cpu_threshold,
        "ram_threshold": cfg.ram_threshold,
        "disk_threshold":cfg.disk_threshold,
        "temp_threshold":cfg.temp_threshold,
    }

@router.get("/config/global")
def get_global(user=Depends(require_permission("alerts", "view")), db: Session=Depends(get_db)):
    return _fmt(_get_or_create_global(db))

@router.put("/config/global")
def set_global(data: dict, user=Depends(require_permission("alerts", "edit")), db: Session=Depends(get_db)):
    cfg = _get_or_create_global(db)
    for field in ("cpu_threshold","ram_threshold","disk_threshold","temp_threshold"):
        if field in data:
            setattr(cfg, field, float(data[field]))
    db.commit()

    # Reevalua de inmediato el ultimo valor conocido de CADA equipo contra el
    # umbral nuevo, en vez de esperar a que cada uno mande su proximo reporte
    # (podrian pasar varios minutos) - asi subir/bajar un umbral se refleja
    # al toque en el panel de alertas, no solo en el siguiente ciclo.
    for a in db.query(Agent).all():
        last = db.query(Metric).filter(Metric.agent_id == a.id).order_by(desc(Metric.timestamp)).first()
        if last:
            check_metric_alerts(a, last.cpu_percent, last.ram_percent, last.disk_percent, last.cpu_temp, cfg, db, last.top_processes)
    db.commit()
    return _fmt(cfg)

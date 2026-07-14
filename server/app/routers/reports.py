from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from core.db import get_db
from core.permissions import require_permission
from models.models import Agent, Metric
from sqlalchemy import desc
from datetime import datetime
import csv, io

router = APIRouter(prefix="/api/reports", tags=["reports"])

@router.get("/agents.csv")
def export_agents(user=Depends(require_permission("inventory", "view")), db: Session=Depends(get_db)):
    agents = db.query(Agent).all()
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["Hostname","Estado","OS","Fabricante","Modelo","Serie","CPU","RAM GB",
                "CPU %","RAM %","Disco %","Temp °C","Sede","Primera vez","Ultimo reporte"])
    for a in agents:
        last = db.query(Metric).filter(Metric.agent_id == a.id)\
                 .order_by(desc(Metric.timestamp)).first()
        w.writerow([
            a.hostname, a.status, f"{a.os or ''} {a.os_version or ''}".strip(),
            a.manufacturer or "", a.model or "", a.serial_number or "",
            a.cpu_model or "", a.ram_total_gb or "",
            last.cpu_percent if last else "",
            last.ram_percent if last else "",
            last.disk_percent if last else "",
            last.cpu_temp if last else "",
            a.sede.name if a.sede else "",
            a.first_seen.strftime("%d/%m/%Y %H:%M") if a.first_seen else "",
            a.last_seen.strftime("%d/%m/%Y %H:%M") if a.last_seen else "",
        ])
    output.seek(0)
    filename = f"smartmonitor_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    return StreamingResponse(iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"})

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import asyncio, json, urllib.request, urllib.parse
from core.db import get_db, get_user_from_token_param
from core.permissions import require_permission
from core.notify import send_email_silent
from models.models import Agent, Metric, Disk, Event, AlertConfig, BlockedSite, AgentChangeLog, AssignmentLog, User
from routers.block_schedules import resolve_schedule_for_agent, is_within_schedule
from routers.blocked_sites import resolve_domains_for_agent, resolve_all_configured_domains
from routers.network_gate import is_network_allowed

router = APIRouter(prefix="/api/agents", tags=["agents"])

def _send_telegram(text: str):
    try:
        cfg = json.load(open("/data/config.json"))
        token = cfg.get("telegram_token","")
        chat  = cfg.get("telegram_chat_id","")
        if not (token and chat and cfg.get("telegram_enabled", False)):
            return
        url  = f"https://api.telegram.org/bot{token}/sendMessage"
        body = json.dumps({"chat_id": chat, "text": text, "parse_mode": "HTML"}).encode()
        req  = urllib.request.Request(url, data=body, headers={"Content-Type":"application/json"})
        urllib.request.urlopen(req, timeout=5)
    except:
        pass

def _notify(tipo: str, telegram_html: str, equipo: str, detalle: str):
    _send_telegram(telegram_html)
    send_email_silent(f"SmartMonitor — {tipo}: {equipo}", f"{equipo} — {detalle}",
                       context={"equipo": equipo, "detalle": detalle, "tipo": tipo})

def _get_thresholds(agent_id: str, db: Session):
    cfg = db.query(AlertConfig).filter(AlertConfig.agent_id == agent_id).first()
    if not cfg:
        cfg = db.query(AlertConfig).filter(AlertConfig.agent_id == None).first()
    return cfg or AlertConfig()

def _get_offline_threshold() -> int:
    """Umbral dinámico: 2.5× el intervalo configurado, mínimo 30s."""
    try:
        cfg = json.load(open("/data/config.json"))
        interval = int(cfg.get("push_interval", 60))
    except:
        interval = 60
    return max(30, int(interval * 2.5))

def _log_agent_change(db: Session, agent: Agent, field: str, old_value, new_value, changed_by: str = None):
    """Registra un cambio de un campo de inventario en el historial."""
    ov = "" if old_value is None else str(old_value)
    nv = "" if new_value is None else str(new_value)
    if ov == nv:
        return
    db.add(AgentChangeLog(
        agent_id=agent.id, field=field,
        old_value=old_value, new_value=new_value, changed_by=changed_by,
    ))

def _parse_date(v):
    if not v:
        return None
    try:
        return datetime.strptime(str(v)[:10], "%Y-%m-%d").date()
    except Exception:
        return None

# ── Schemas de entrada del agente ──────────────────────────────────────────
class DiskInfo(BaseModel):
    device: str
    mountpoint: str
    total_gb: float
    used_gb: float
    percent: float

class MetricPayload(BaseModel):
    hostname: str
    os: str = "linux"
    os_version: str = ""
    # Hardware info (solo se envía en el primer push o cuando cambia)
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    cpu_model: Optional[str] = None
    cpu_cores: Optional[int] = None
    ram_slots_total:  Optional[int]  = None
    ram_slots_used:   Optional[int]  = None
    ram_slots_detail:   list          = []
    ram_total_gb:       Optional[float] = None
    installed_software: list          = []
    device_type: Optional[str] = None  # Laptop|Desktop|Tablet|Other (auto-detectado)
    # Métricas
    cpu_percent: float
    ram_percent: float
    ram_used_gb: float
    disk_percent: float
    net_rx_mb: float = 0
    net_tx_mb: float = 0
    cpu_temp: Optional[float] = None
    latency_ms: Optional[float] = None
    top_processes: list = []
    disks: list[DiskInfo] = []

# ── Recibir métricas ───────────────────────────────────────────────────────
@router.post("/metrics")
def receive_metrics(payload: MetricPayload, request: Request, db: Session = Depends(get_db)):
    now = datetime.utcnow()

    # Buscar o crear agente: el serial_number es la identidad persistente.
    found_by_serial = False
    agent = db.query(Agent).filter(Agent.hostname == payload.hostname).first()
    if not agent and payload.serial_number:
        agent = db.query(Agent).filter(Agent.serial_number == payload.serial_number).first()
        if agent:
            agent.hostname = payload.hostname
            found_by_serial = True
    if not agent and not payload.serial_number and payload.manufacturer and payload.model:
        agent = db.query(Agent).filter(
            Agent.manufacturer == payload.manufacturer,
            Agent.model == payload.model
        ).first()
        if agent:
            agent.hostname = payload.hostname
            found_by_serial = True
    was_offline = agent and agent.status == "offline"

    if not agent:
        agent = Agent(hostname=payload.hostname, display_name=payload.hostname)
        db.add(agent)
        db.flush()
    elif found_by_serial:
        agent.display_name = payload.hostname

    # Actualizar info de hardware si viene en el payload
    if payload.manufacturer: agent.manufacturer = payload.manufacturer
    if payload.model:        agent.model = payload.model
    if payload.serial_number: agent.serial_number = payload.serial_number
    if payload.cpu_model:    agent.cpu_model = payload.cpu_model
    if payload.cpu_cores:    agent.cpu_cores = payload.cpu_cores
    if payload.ram_slots_total:  agent.ram_slots_total  = payload.ram_slots_total
    if payload.ram_slots_used:   agent.ram_slots_used   = payload.ram_slots_used
    if payload.ram_slots_detail:   agent.ram_slots_detail   = payload.ram_slots_detail
    if payload.ram_total_gb:       agent.ram_total_gb       = payload.ram_total_gb
    if payload.installed_software:
        agent.installed_software  = payload.installed_software
        agent.software_updated_at = now
    if payload.os:           agent.os = payload.os
    if payload.os_version:   agent.os_version = payload.os_version

    # Tipo de dispositivo:
    # - backend: jamás toca agent.device_type si device_type_manual=True
    # - frontend: si el usuario lo tocó, se marca explícitamente
    if payload.device_type:
        if agent.device_type_manual:
            pass  # humano lo fijó ⇒ respetar
        else:
            if agent.device_type != payload.device_type:
                _log_agent_change(db, agent, "device_type", agent.device_type, payload.device_type)
            agent.device_type = payload.device_type

    agent.ip = request.client.host if request.client else None
    agent.last_seen = now
    agent.status = "online"

    # Evento: volvió online → resolver todos sus eventos offline anteriores
    if was_offline:
        db.query(Event).filter(
            Event.agent_id == agent.id,
            Event.type == "offline",
            Event.resolved == False
        ).update({"resolved": True})
        db.add(Event(agent_id=agent.id, type="online", detail="Equipo reconectado"))

    # Guardar métrica
    metric = Metric(
        agent_id=agent.id,
        cpu_percent=payload.cpu_percent,
        ram_percent=payload.ram_percent,
        ram_used_gb=payload.ram_used_gb,
        disk_percent=payload.disk_percent,
        net_rx_mb=payload.net_rx_mb,
        net_tx_mb=payload.net_tx_mb,
        cpu_temp=payload.cpu_temp,
        latency_ms=payload.latency_ms,
        top_processes=payload.top_processes,
    )
    db.add(metric)

    # Actualizar discos
    if payload.disks:
        db.query(Disk).filter(Disk.agent_id == agent.id).delete()
        for d in payload.disks:
            db.add(Disk(
                agent_id=agent.id,
                device=d.device,
                mountpoint=d.mountpoint,
                total_gb=d.total_gb,
                used_gb=d.used_gb,
                percent=d.percent,
            ))

    # Umbrales configurables por agente o globales
    thr = _get_thresholds(agent.id, db)

    cpu_thr  = thr.cpu_threshold  if thr.cpu_threshold  is not None else 85.0
    ram_thr  = thr.ram_threshold  if thr.ram_threshold  is not None else 90.0
    disk_thr = thr.disk_threshold if thr.disk_threshold is not None else 90.0
    temp_thr = thr.temp_threshold if thr.temp_threshold is not None else 85.0

    # Auto-resolver alertas cuando los valores vuelven a la normalidad
    if payload.cpu_percent <= cpu_thr:
        db.query(Event).filter(Event.agent_id == agent.id, Event.type == "cpu_high",  Event.resolved == False).update({"resolved": True})
    if payload.ram_percent <= ram_thr:
        db.query(Event).filter(Event.agent_id == agent.id, Event.type == "ram_high",  Event.resolved == False).update({"resolved": True})
    if payload.disk_percent <= disk_thr:
        db.query(Event).filter(Event.agent_id == agent.id, Event.type == "disk_high", Event.resolved == False).update({"resolved": True})
    if not payload.cpu_temp or payload.cpu_temp <= temp_thr:
        db.query(Event).filter(Event.agent_id == agent.id, Event.type == "temp_high", Event.resolved == False).update({"resolved": True})

    # Generar nuevas alertas (solo si no hay una activa del mismo tipo)
    def no_active(etype):
        return not db.query(Event).filter(Event.agent_id == agent.id, Event.type == etype, Event.resolved == False).first()

    name = agent.display_name or agent.hostname
    if payload.cpu_percent > cpu_thr and no_active("cpu_high"):
        detail = f"CPU al {payload.cpu_percent:.1f}%"
        db.add(Event(agent_id=agent.id, type="cpu_high", detail=detail))
        _notify(f"🔥 CPU alta — {name}", f"🔥 <b>{name}</b> — {detail}", name, detail)
    if payload.ram_percent > ram_thr and no_active("ram_high"):
        detail = f"RAM al {payload.ram_percent:.1f}%"
        db.add(Event(agent_id=agent.id, type="ram_high", detail=detail))
        _notify(f"💾 RAM alta — {name}", f"💾 <b>{name}</b> — {detail}", name, detail)
    if payload.disk_percent > disk_thr and no_active("disk_high"):
        detail = f"Disco al {payload.disk_percent:.1f}%"
        db.add(Event(agent_id=agent.id, type="disk_high", detail=detail))
        _notify(f"💿 Disco alto — {name}", f"💿 <b>{name}</b> — {detail}", name, detail)
    if payload.cpu_temp and payload.cpu_temp > temp_thr and no_active("temp_high"):
        detail = f"Temperatura {payload.cpu_temp:.1f}°C"
        db.add(Event(agent_id=agent.id, type="temp_high", detail=detail))
        _notify(f"🌡 Temperatura alta — {name}", f"🌡 <b>{name}</b> — {detail}", name, detail)

    # Limpiar métricas antiguas (conservar 24h)
    cutoff = now - timedelta(hours=24)
    db.query(Metric).filter(Metric.agent_id == agent.id, Metric.timestamp < cutoff).delete()

    db.commit()
    return {"ok": True}

# ── Marcar equipos offline ─────────────────────────────────────────────────
def check_offline(db: Session):
    threshold = _get_offline_threshold()
    cutoff = datetime.utcnow() - timedelta(seconds=threshold)
    agents = db.query(Agent).filter(Agent.status == "online", Agent.last_seen < cutoff).all()
    for a in agents:
        a.status = "offline"
        mins = round(threshold / 60, 1)
        detail = f"Sin reporte por más de {mins} min"
        db.add(Event(agent_id=a.id, type="offline", detail=detail))
        name = a.display_name or a.hostname
        _notify(f"⬛ Equipo sin conexión — {name}", f"⬛ <b>{name}</b> — Sin conexión", name, detail)
    if agents:
        db.commit()

# ── Listar agentes ─────────────────────────────────────────────────────────
@router.get("")
def list_agents(user = Depends(require_permission("dashboard", "view")), db: Session = Depends(get_db)):
    check_offline(db)
    agents = db.query(Agent).all()
    result = []
    for a in agents:
        last_metric = db.query(Metric).filter(Metric.agent_id == a.id).order_by(desc(Metric.timestamp)).first()
        ago = int((datetime.utcnow() - a.last_seen).total_seconds()) if a.last_seen else 9999
        result.append({
            "id": a.id,
            "hostname": a.hostname,
            "display_name": a.display_name or a.hostname,
            "status": a.status,
            "last_seen_ago": ago,
            "os": a.os,
            "os_version": a.os_version,
            "manufacturer": a.manufacturer,
            "model": a.model,
            "serial_number": a.serial_number,
            "cpu_model": a.cpu_model,
            "cpu_cores": a.cpu_cores,
            "ram_total_gb": a.ram_total_gb,
            "ram_slots_total": a.ram_slots_total,
            "ram_slots_used": a.ram_slots_used,
            "sede": a.sede.name if a.sede else None,
            "sede_id": a.sede_id,
            "notes": a.notes,
            "device_type": a.device_type,
            "device_type_manual": bool(a.device_type_manual),
            "assigned_user": a.assigned_user,
            "assigned_user_name": (db.query(User).filter(User.id == a.assigned_user).first().name
                                    if a.assigned_user else None),
            "assigned_at": a.assigned_at.isoformat() if a.assigned_at else None,
            "returned_at": a.returned_at.isoformat() if a.returned_at else None,
            "assignment_notes": a.assignment_notes,
            "return_notes": a.return_notes,
            "cpu_percent": last_metric.cpu_percent if last_metric else 0,
            "ram_percent": last_metric.ram_percent if last_metric else 0,
            "ram_used_gb": last_metric.ram_used_gb if last_metric else 0,
            "disk_percent": last_metric.disk_percent if last_metric else 0,
            "net_rx_mb": last_metric.net_rx_mb if last_metric else 0,
            "net_tx_mb": last_metric.net_tx_mb if last_metric else 0,
            "cpu_temp": last_metric.cpu_temp if last_metric else None,
            "latency_ms": last_metric.latency_ms if last_metric else None,
            "top_processes": last_metric.top_processes if last_metric else [],
        })
    result.sort(key=lambda x: (x["status"] != "online", -(x["cpu_percent"] or 0)))
    return result

# ── SSE: stream en vivo ───────────────────────────────────────────────────
@router.get("/stream")
async def stream_agents(
    interval: int = 3,
    user = Depends(get_user_from_token_param),
    db: Session = Depends(get_db)
):
    interval = max(1, min(interval, 60))

    def build_snapshot():
        check_offline(db)
        db.expire_all()
        agents = db.query(Agent).all()
        result = []
        for a in agents:
            last = db.query(Metric).filter(Metric.agent_id == a.id).order_by(desc(Metric.timestamp)).first()
            ago  = int((datetime.utcnow() - a.last_seen).total_seconds()) if a.last_seen else 9999
            result.append({
                "id": a.id, "hostname": a.hostname,
                "display_name": a.display_name or a.hostname,
                "status": a.status, "last_seen_ago": ago,
                "os": a.os, "os_version": a.os_version,
                "manufacturer": a.manufacturer, "model": a.model,
                "serial_number": a.serial_number,
                "cpu_model": a.cpu_model, "cpu_cores": a.cpu_cores,
                "ram_total_gb":   a.ram_total_gb,
                "ram_slots_total": a.ram_slots_total,
                "ram_slots_used":  a.ram_slots_used,
                "cpu_percent":  last.cpu_percent  if last else 0,
                "ram_percent":  last.ram_percent  if last else 0,
                "ram_used_gb":  last.ram_used_gb  if last else 0,
                "disk_percent": last.disk_percent if last else 0,
                "net_rx_mb":    last.net_rx_mb    if last else 0,
                "net_tx_mb":    last.net_tx_mb    if last else 0,
                "cpu_temp":     last.cpu_temp     if last else None,
                "latency_ms":   last.latency_ms   if last else None,
                "top_processes":last.top_processes if last else [],
                "sede": a.sede.name if a.sede else None,
                "sede_id": a.sede_id,
            })
        result.sort(key=lambda x: (x["status"] != "online", -(x["cpu_percent"] or 0)))

        alerts = db.query(Event).filter(
            Event.resolved == False,
            Event.type.in_(["offline","cpu_high","ram_high","disk_high","temp_high"])
        ).order_by(desc(Event.timestamp)).limit(20).all()

        agents_map = {a.id: a for a in db.query(Agent).all()}
        alert_list = [{"id": e.agent_id,
                       "hostname": agents_map[e.agent_id].hostname if e.agent_id in agents_map else "?",
                       "type": e.type, "detail": e.detail} for e in alerts]

        return json.dumps({
            "agents": result,
            "summary": {
                "total":   len(result),
                "online":  sum(1 for a in result if a["status"] == "online"),
                "offline": sum(1 for a in result if a["status"] == "offline"),
                "alerts":  alert_list,
            },
            "ts": datetime.utcnow().isoformat()
        })

    async def generator():
        yield f"data: {build_snapshot()}\n\n"
        while True:
            await asyncio.sleep(interval)
            try:
                yield f"data: {build_snapshot()}\n\n"
            except Exception:
                break

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )

# ── Eventos globales ──────────────────────────────────────────────────────
@router.get("/events/global")
def get_global_events(
    agent_id:   str = Query(None),
    sede_id:    str = Query(None),
    event_type: str = Query(None),
    from_date:  str = Query(None),
    to_date:    str = Query(None),
    limit:      int = Query(500),
    user = Depends(require_permission("events", "view")),
    db: Session = Depends(get_db)
):
    q = db.query(Event)
    if agent_id:
        q = q.filter(Event.agent_id == agent_id)
    if event_type:
        q = q.filter(Event.type == event_type)
    if from_date:
        try:
            q = q.filter(Event.timestamp >= datetime.fromisoformat(from_date))
        except ValueError:
            pass
    if to_date:
        try:
            dt_to = datetime.fromisoformat(to_date) + timedelta(days=1)
            q = q.filter(Event.timestamp < dt_to)
        except ValueError:
            pass
    events = q.order_by(desc(Event.timestamp)).limit(max(1, min(limit, 2000))).all()
    agent_ids = {e.agent_id for e in events}
    agents_map = {a.id: a for a in db.query(Agent).filter(Agent.id.in_(agent_ids)).all()}
    result = []
    for e in events:
        a = agents_map.get(e.agent_id)
        if not a:
            continue
        if sede_id and str(a.sede_id) != sede_id:
            continue
        result.append({
            "id": e.id, "hostname": a.hostname,
            "display_name": a.display_name or a.hostname,
            "agent_id": e.agent_id,
            "sede": a.sede.name if a.sede else None,
            "type": e.type, "detail": e.detail,
            "timestamp": e.timestamp.isoformat(), "resolved": e.resolved
        })
    return result

# ── Lista de bloqueo (consultada periódicamente por el agente) ─────────────
@router.get("/blocklist")
def get_blocklist(hostname: str, ssid: Optional[str] = Query(None), db: Session = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.hostname == hostname).first()

    active_sites = db.query(BlockedSite).filter(BlockedSite.active == True).all()
    all_domains = resolve_all_configured_domains(agent, active_sites)
    domains = resolve_domains_for_agent(agent, active_sites)

    schedule = resolve_schedule_for_agent(agent, db)
    should_block = is_within_schedule(schedule) and is_network_allowed(ssid, db)

    if not should_block:
        domains = []

    return {"should_block": should_block, "domains": sorted(domains), "all_domains": sorted(all_domains)}

# ── Detalle de un agente ───────────────────────────────────────────────────
@router.get("/{agent_id}")
def get_agent(agent_id: str, user = Depends(require_permission("inventory", "view")), db: Session = Depends(get_db)):
    a = db.query(Agent).filter(Agent.id == agent_id).first()
    if not a:
        raise HTTPException(404, "Agente no encontrado")
    disks = db.query(Disk).filter(Disk.agent_id == a.id).all()
    return {
        "id": a.id, "hostname": a.hostname, "display_name": a.display_name,
        "status": a.status, "os": a.os, "os_version": a.os_version,
        "manufacturer": a.manufacturer, "model": a.model,
        "serial_number": a.serial_number, "cpu_model": a.cpu_model,
        "cpu_cores": a.cpu_cores, "ram_total_gb": a.ram_total_gb,
        "ram_slots_total": a.ram_slots_total, "ram_slots_used": a.ram_slots_used,
        "ram_slots_detail": a.ram_slots_detail or [],
        "sede_id": a.sede_id, "notes": a.notes,
        "device_type": a.device_type, "device_type_manual": bool(a.device_type_manual),
        "assigned_user": a.assigned_user,
        "assigned_user_name": (db.query(User).filter(User.id == a.assigned_user).first().name
                                if a.assigned_user else None),
        "assigned_at": a.assigned_at.isoformat() if a.assigned_at else None,
        "returned_at": a.returned_at.isoformat() if a.returned_at else None,
        "assignment_notes": a.assignment_notes,
        "return_notes": a.return_notes,
        "first_seen": a.first_seen.isoformat() if a.first_seen else None,
        "last_seen": a.last_seen.isoformat() if a.last_seen else None,
        "disks": [{"device": d.device, "mountpoint": d.mountpoint,
                   "total_gb": d.total_gb, "used_gb": d.used_gb, "percent": d.percent} for d in disks],
    }

# ── Actualizar agente (notas, sede, nombre) ────────────────────────────────
@router.put("/{agent_id}")
def update_agent(agent_id: str, data: dict, user = Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    a = db.query(Agent).filter(Agent.id == agent_id).first()
    if not a:
        raise HTTPException(404, "Agente no encontrado")
    if "display_name" in data:
        a.display_name = data["display_name"]
        a.display_name_manual = True
    if "notes" in data:        a.notes = data["notes"]
    if "sede_id" in data:      a.sede_id = data["sede_id"] or None
    if "device_type" in data and data.get("device_type"):
        new_dt = str(data["device_type"])
        if a.device_type != new_dt:
            _log_agent_change(db, a, "device_type", a.device_type, new_dt,
                              changed_by=(user.name or user.email if user else None))
        a.device_type = new_dt
        a.device_type_manual = True
    if "assigned_user" in data:
        a.assigned_user = data["assigned_user"] or None
    if "assigned_at" in data:
        a.assigned_at = _parse_date(data.get("assigned_at"))
    if "returned_at" in data:
        a.returned_at = _parse_date(data.get("returned_at"))
    if "assignment_notes" in data:
        a.assignment_notes = data["assignment_notes"] or None
    if "return_notes" in data:
        a.return_notes = data["return_notes"] or None
    db.commit()
    return {"ok": True}

# ── Eliminar agente ─────────────────────────────────────────────────────────
@router.delete("/{agent_id}")
def delete_agent(agent_id: str, user = Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    """Borra el registro del equipo (y su historial: métricas, discos,
    eventos, bloqueos/horarios propios, etc. — todo cae en cascada).
    IMPORTANTE: esto NO desinstala el agente remoto. Si el proceso sigue
    corriendo en esa máquina, al siguiente push de métricas el servidor
    vuelve a crear el registro (se busca/crea por hostname). Pensado para
    limpiar equipos ya dados de baja, duplicados o de prueba."""
    a = db.query(Agent).filter(Agent.id == agent_id).first()
    if not a:
        raise HTTPException(404, "Agente no encontrado")
    # AlertConfig no tiene ON DELETE CASCADE a nivel de base de datos.
    db.query(AlertConfig).filter(AlertConfig.agent_id == agent_id).delete()
    db.delete(a)
    db.commit()
    return {"ok": True}

# ── Historial de cambios de inventario ─────────────────────────────────────
@router.get("/{agent_id}/changes")
def get_agent_changes(agent_id: str, user = Depends(require_permission("inventory", "view")), db: Session = Depends(get_db)):
    a = db.query(Agent).filter(Agent.id == agent_id).first()
    if not a:
        raise HTTPException(404, "Agente no encontrado")
    rows = db.query(AgentChangeLog).filter(AgentChangeLog.agent_id == agent_id)\
              .order_by(desc(AgentChangeLog.change_date), desc(AgentChangeLog.changed_at)).all()
    return [{
        "id": r.id, "field": r.field,
        "old_value": r.old_value, "new_value": r.new_value,
        "note": r.note,
        "change_date": r.change_date.isoformat() if r.change_date else None,
        "changed_by": r.changed_by,
        "changed_at": r.changed_at.isoformat() if r.changed_at else None,
    } for r in rows]

@router.post("/{agent_id}/changes")
def add_agent_change(agent_id: str, data: dict, user = Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    """Registra manualmente un cambio/mantenimiento de hardware (RAM, batería,
    fuente, etc.) con la fecha en que ocurrió y un detalle libre."""
    a = db.query(Agent).filter(Agent.id == agent_id).first()
    if not a:
        raise HTTPException(404, "Agente no encontrado")
    field = str(data.get("field") or "").strip()
    change_date = data.get("change_date")
    note = str(data.get("note") or "").strip()
    if not field or not change_date or not note:
        raise HTTPException(400, "Todos los campos son obligatorios: componente, fecha de cambio y motivo.")
    try:
        datetime.strptime(change_date, "%Y-%m-%d").date()
    except Exception:
        raise HTTPException(400, "La fecha de cambio no es válida (AAAA-MM-DD).")
    cd = datetime.strptime(change_date, "%Y-%m-%d").date()
    db.add(AgentChangeLog(
        agent_id=agent_id, field=field,
        old_value=data.get("old_value") or None,
        new_value=data.get("new_value") or None,
        note=str(data.get("note") or "") or None,
        change_date=cd,
        changed_by=(user.name or user.email if user else None),
    ))
    db.commit()
    return {"ok": True}

# ── Historial de asignaciones (log de entregas/devoluciones) ────────────────
@router.get("/{agent_id}/assignments")
def get_assignments(agent_id: str, user = Depends(require_permission("inventory", "view")), db: Session = Depends(get_db)):
    a = db.query(Agent).filter(Agent.id == agent_id).first()
    if not a:
        raise HTTPException(404, "Agente no encontrado")
    rows = db.query(AssignmentLog).filter(AssignmentLog.agent_id == agent_id)\
              .order_by(desc(AssignmentLog.created_at), desc(AssignmentLog.assigned_at)).all()
    return [{
        "id": r.id,
        "assigned_to": r.assigned_to,
        "assigned_to_name": r.assigned_to_name,
        "assigned_at": r.assigned_at.isoformat() if r.assigned_at else None,
        "delivery_notes": r.delivery_notes,
        "returned_at": r.returned_at.isoformat() if r.returned_at else None,
        "return_notes": r.return_notes,
        "changed_by": r.changed_by,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    } for r in rows]

@router.post("/{agent_id}/assignments")
def add_assignment(agent_id: str, data: dict, user = Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    """Registra una asignación/devolución de equipo: a quién se asignó, fechas
    y observaciones de entrega y devolución. Refleja lo último en el agente."""
    a = db.query(Agent).filter(Agent.id == agent_id).first()
    if not a:
        raise HTTPException(404, "Agente no encontrado")
    assigned_to = data.get("assigned_to") or None
    name = data.get("assigned_to_name")
    if not name and assigned_to:
        u = db.query(User).filter(User.id == assigned_to).first()
        name = u.name if u else None
    rec = AssignmentLog(
        agent_id=agent_id,
        assigned_to=assigned_to,
        assigned_to_name=name,
        assigned_at=_parse_date(data.get("assigned_at")),
        delivery_notes=data.get("delivery_notes") or None,
        returned_at=_parse_date(data.get("returned_at")),
        return_notes=data.get("return_notes") or None,
        changed_by=(user.name or user.email if user else None),
    )
    db.add(rec)
    # La "asignación actual" del agente refleja el último registro del log
    a.assigned_user   = assigned_to
    a.assigned_at     = rec.assigned_at
    a.assignment_notes = rec.delivery_notes
    a.returned_at     = rec.returned_at
    a.return_notes    = rec.return_notes
    db.commit()
    return {"ok": True}

@router.delete("/{agent_id}/assignments/{record_id}")
def delete_assignment(agent_id: str, record_id: int, user = Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    rec = db.query(AssignmentLog).filter(AssignmentLog.id == record_id, AssignmentLog.agent_id == agent_id).first()
    if not rec:
        raise HTTPException(404, "Registro no encontrado")
    db.delete(rec)
    db.commit()
    return {"ok": True}

# ── Software instalado ────────────────────────────────────────────────────
@router.get("/{agent_id}/software")
def get_software(agent_id: str, user = Depends(require_permission("inventory", "view")), db: Session = Depends(get_db)):
    a = db.query(Agent).filter(Agent.id == agent_id).first()
    if not a:
        raise HTTPException(404, "Agente no encontrado")
    return {
        "software": a.installed_software or [],
        "count": len(a.installed_software or []),
        "updated_at": a.software_updated_at.isoformat() if a.software_updated_at else None,
    }

# ── Historial de métricas ─────────────────────────────────────────────────
@router.get("/{agent_id}/history")
def get_history(agent_id: str, range: str = Query("24h"),
                user = Depends(require_permission("inventory", "view")), db: Session = Depends(get_db)):
    hours = {"1h":1,"6h":6,"12h":12,"24h":24}.get(range, 24)
    since = datetime.utcnow() - timedelta(hours=hours)
    metrics = db.query(Metric).filter(
        Metric.agent_id == agent_id,
        Metric.timestamp >= since
    ).order_by(Metric.timestamp).all()
    return [{"t": m.timestamp.isoformat()+"Z", "cpu": m.cpu_percent, "ram": m.ram_percent,
             "disk": m.disk_percent, "temp": m.cpu_temp, "latency": m.latency_ms} for m in metrics]

# ── Uptime ────────────────────────────────────────────────────────────────
@router.get("/{agent_id}/uptime")
def get_uptime(agent_id: str, days: int = Query(7),
               user = Depends(require_permission("inventory", "view")), db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(days=days)
    events = db.query(Event).filter(
        Event.agent_id == agent_id,
        Event.timestamp >= since,
        Event.type.in_(["online","offline"])
    ).order_by(Event.timestamp).all()

    total_secs = days * 86400
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: return {"uptime_pct": 0, "days": days}

    # Construir línea de tiempo
    offline_secs = 0
    last_offline = None

    for e in events:
        if e.type == "offline":
            last_offline = e.timestamp
        elif e.type == "online" and last_offline:
            offline_secs += (e.timestamp - last_offline).total_seconds()
            last_offline = None

    if last_offline and agent.status == "offline":
        offline_secs += (datetime.utcnow() - last_offline).total_seconds()

    uptime_pct = max(0, round((1 - offline_secs / total_secs) * 100, 2))
    return {"uptime_pct": uptime_pct, "days": days, "offline_secs": int(offline_secs)}

# ── Eventos del agente ────────────────────────────────────────────────────
@router.get("/{agent_id}/events")
def get_events(agent_id: str, user = Depends(require_permission("inventory", "view")), db: Session = Depends(get_db)):
    events = db.query(Event).filter(Event.agent_id == agent_id)\
        .order_by(desc(Event.timestamp)).limit(500).all()
    return [{"id": e.id, "type": e.type, "detail": e.detail,
             "timestamp": e.timestamp.isoformat(), "resolved": e.resolved} for e in events]

# ── Summary global ────────────────────────────────────────────────────────
@router.get("/summary/global")
def get_summary(user = Depends(require_permission("dashboard", "view")), db: Session = Depends(get_db)):
    check_offline(db)
    agents = db.query(Agent).all()
    online  = sum(1 for a in agents if a.status == "online")
    offline = sum(1 for a in agents if a.status == "offline")
    alerts  = db.query(Event).filter(
                  Event.resolved == False,
                  Event.type.in_(["offline", "cpu_high", "ram_high", "disk_high", "temp_high"])
              ).order_by(desc(Event.timestamp)).limit(20).all()
    return {
        "total": len(agents), "online": online, "offline": offline,
        "alerts": [{"id": e.agent_id,
                    "hostname": db.query(Agent).get(e.agent_id).hostname,
                    "type": e.type, "detail": e.detail,
                    "timestamp": e.timestamp.isoformat()} for e in alerts]
    }

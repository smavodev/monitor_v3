from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import asyncio, json, urllib.request, urllib.parse, threading, time as _time
from core.db import get_db, get_user_from_token_param, Session as DBSession
from core.permissions import require_permission
from core.notify import send_email_silent
from models.models import Agent, Metric, Disk, PhysicalDisk, Event, AlertConfig, BlockedSite, AgentChangeLog, AssignmentLog, User, BlockSchedule, NetworkGateConfig, Sede, Asset
from routers.block_schedules import is_within_schedule, _local_now
from routers.blocked_sites import resolve_domains_for_agent, resolve_all_configured_domains
from routers.headscale import rename_headscale_node

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

def _send_whatsapp(text: str):
    """CallMeBot: servicio comunitario que reenvia el mensaje a cada numero
    de la lista (cada uno con su propia API key, activada por su lado en
    Configuracion) - sin necesidad de correr nada propio ni escanear QR."""
    try:
        cfg = json.load(open("/data/config.json"))
        if not cfg.get("whatsapp_enabled", False):
            return
        for r in cfg.get("whatsapp_recipients", []):
            phone  = r.get("phone", "")
            apikey = r.get("apikey", "")
            if not (phone and apikey):
                continue
            try:
                params = urllib.parse.urlencode({"phone": phone, "apikey": apikey, "text": text})
                urllib.request.urlopen(f"https://api.callmebot.com/whatsapp.php?{params}", timeout=8)
            except:
                pass
    except:
        pass

def _notify(tipo: str, telegram_html: str, equipo: str, detalle: str, agent_id: str = None):
    _send_telegram(telegram_html)
    _send_whatsapp(f"{tipo} — {equipo}: {detalle}")
    send_email_silent(f"SmartMonitor — {tipo}: {equipo}", f"{equipo} — {detalle}",
                       context={"equipo": equipo, "detalle": detalle, "tipo": tipo, "agent_id": agent_id})

def _agent_version(a: Agent):
    """Version del SmartMonitor Agent instalado en el equipo - no hay un
    campo propio para esto, se lee del inventario de software que el propio
    agente ya reporta (se auto-lista, ver installed_software en
    smartmonitor_agent.py) en vez de duplicar el dato."""
    for sw in (a.installed_software or []):
        if sw.get("name") == "SmartMonitor Agent":
            return sw.get("version")
    return None

def _get_thresholds(db: Session):
    # Umbral unico y global para todos los equipos (ver routers/alerts.py) -
    # ya no hay umbrales por agente.
    return db.query(AlertConfig).filter(AlertConfig.agent_id == None).first() or AlertConfig()

def _fmt_duration_mins(mins: float) -> str:
    """Minutos legibles para el detalle de un evento - en horas apenas supera
    los 60 minutos (ej. "~8049.2 min" pasa a ser "~134.2 horas"), para
    cualquier reporte que muestre una duracion asi (desconexion, reconexion)."""
    if mins < 60:
        return f"~{mins} min"
    return f"~{round(mins / 60, 1)} horas"

def _top_process(top_processes: list, key: str):
    """Proceso con mayor consumo (cpu o mem) de la ultima lista reportada,
    para dar un motivo mas concreto en las alertas de CPU/RAM (no solo
    'supero el umbral' sino que ademas indicar que lo esta causando)."""
    if not top_processes:
        return None
    try:
        return max(top_processes, key=lambda p: p.get(key) or 0)
    except Exception:
        return None

def check_metric_alerts(agent: Agent, cpu_pct: float, ram_pct: float, disk_pct: float,
                         temp: Optional[float], thr: AlertConfig, db: Session,
                         top_processes: list = None):
    """Evalua CPU/RAM/Disco/Temperatura contra los umbrales dados y registra
    un Event por CADA llamada en la que el valor este en o sobre el umbral
    (no solo la primera vez) - da trazabilidad completa en el historial de
    Eventos. La notificacion (Telegram/email) solo se manda cuando no habia
    ya una alerta activa del mismo tipo, para no repetir el aviso en cada
    reporte mientras el equipo siga sobre el umbral.

    Se llama tanto desde receive_metrics() (con el valor recien reportado)
    como desde alerts.set_global() (con el ultimo valor conocido de cada
    equipo, para que cambiar el umbral global tome efecto de inmediato en
    vez de esperar al proximo reporte de cada agente).

    Solo aplica si el equipo esta online: uno offline no tiene datos frescos
    (los "ultimos valores conocidos" pueden ser de horas atras), asi que no
    tiene sentido disparar/reevaluar CPU/RAM/Disco/Temperatura para el - la
    unica alerta que le corresponde a un equipo offline es la de desconexion
    (que maneja check_offline() por separado, no esta funcion)."""
    if agent.status != "online":
        return
    cpu_thr  = thr.cpu_threshold  if thr.cpu_threshold  is not None else 85.0
    ram_thr  = thr.ram_threshold  if thr.ram_threshold  is not None else 90.0
    disk_thr = thr.disk_threshold if thr.disk_threshold is not None else 90.0
    temp_thr = thr.temp_threshold if thr.temp_threshold is not None else 85.0

    # Auto-resolver alertas cuando los valores vuelven a la normalidad. El
    # corte es estrictamente "<" (no "<=") para que sea el complemento exacto
    # de ">=" de mas abajo - al valor justo del umbral, la alerta esta activa
    # (dispara al llegar), no resuelta.
    if cpu_pct < cpu_thr:
        db.query(Event).filter(Event.agent_id == agent.id, Event.type == "cpu_high",  Event.resolved == False).update({"resolved": True})
    if ram_pct < ram_thr:
        db.query(Event).filter(Event.agent_id == agent.id, Event.type == "ram_high",  Event.resolved == False).update({"resolved": True})
    if disk_pct < disk_thr:
        db.query(Event).filter(Event.agent_id == agent.id, Event.type == "disk_high", Event.resolved == False).update({"resolved": True})
    if not temp or temp < temp_thr:
        db.query(Event).filter(Event.agent_id == agent.id, Event.type == "temp_high", Event.resolved == False).update({"resolved": True})

    def no_active(etype):
        return not db.query(Event).filter(Event.agent_id == agent.id, Event.type == etype, Event.resolved == False).first()

    name = agent.display_name or agent.hostname
    if cpu_pct >= cpu_thr:
        detail = f"CPU al {cpu_pct:.1f}%"
        reason = "CPU elevada"
        top = _top_process(top_processes, "cpu")
        if top and top.get("name"):
            detail += f" — proceso con mayor consumo: {top['name']} ({top.get('cpu', 0):.0f}% CPU)"
        is_new = no_active("cpu_high")
        db.add(Event(agent_id=agent.id, type="cpu_high", detail=detail, reason=reason))
        if is_new:
            _notify("🔥 Alerta", f"🔥 <b>{name}</b> — {detail}", name, detail, agent.id)
    if ram_pct >= ram_thr:
        detail = f"RAM al {ram_pct:.1f}%"
        reason = "RAM elevada"
        top = _top_process(top_processes, "mem")
        if top and top.get("name"):
            detail += f" — proceso con mayor consumo: {top['name']} ({top.get('mem', 0):.0f}% RAM)"
        is_new = no_active("ram_high")
        db.add(Event(agent_id=agent.id, type="ram_high", detail=detail, reason=reason))
        if is_new:
            _notify("💾 Alerta", f"💾 <b>{name}</b> — {detail}", name, detail, agent.id)
    if disk_pct >= disk_thr:
        detail = f"Disco al {disk_pct:.1f}%"
        reason = "Disco elevado"
        is_new = no_active("disk_high")
        db.add(Event(agent_id=agent.id, type="disk_high", detail=detail, reason=reason))
        if is_new:
            _notify("💿 Alerta", f"💿 <b>{name}</b> — {detail}", name, detail, agent.id)
    if temp and temp >= temp_thr:
        detail = f"Temperatura {temp:.1f}°C"
        reason = "Temperatura elevada"
        is_new = no_active("temp_high")
        db.add(Event(agent_id=agent.id, type="temp_high", detail=detail, reason=reason))
        if is_new:
            _notify("🌡 Alerta", f"🌡 <b>{name}</b> — {detail}", name, detail, agent.id)

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

def _validate_assignment_dates(db: Session, agent_id: str, assigned_at, returned_at, exclude_id=None):
    """Evita solapar asignaciones: la fecha de asignación de un registro no
    puede caer antes de que se haya devuelto el equipo en el registro
    anterior, ni su devolución puede pisar el inicio de la siguiente
    asignación ya registrada."""
    if assigned_at and returned_at and returned_at < assigned_at:
        raise HTTPException(400, "La fecha de devolución no puede ser anterior a la fecha de asignación.")
    if not assigned_at:
        return
    q = db.query(AssignmentLog).filter(AssignmentLog.agent_id == agent_id)
    if exclude_id is not None:
        q = q.filter(AssignmentLog.id != exclude_id)
    others = [o for o in q.all() if o.assigned_at]

    prev = max((o for o in others if o.assigned_at <= assigned_at), key=lambda o: o.assigned_at, default=None)
    if prev and prev.returned_at and prev.returned_at > assigned_at:
        raise HTTPException(400, f"La fecha de asignación no puede ser anterior a la devolución del registro anterior ({prev.returned_at.isoformat()}).")

    nxt = min((o for o in others if o.assigned_at >= assigned_at), key=lambda o: o.assigned_at, default=None)
    if nxt and returned_at and nxt.assigned_at < returned_at:
        raise HTTPException(400, f"La fecha de devolución no puede superponerse con la siguiente asignación ({nxt.assigned_at.isoformat()}).")

def _sync_agent_from_latest_assignment(a: "Agent", latest):
    """Refleja en el agente el registro de asignación más reciente. Si ese
    registro ya fue devuelto, nadie lo tiene actualmente — se limpia
    assigned_user (columna "Usuario") aunque el historial completo del
    registro (fechas, notas) se conserva para consulta."""
    if not latest:
        a.assigned_user = None
        a.assigned_at = None
        a.assignment_notes = None
        a.returned_at = None
        a.return_notes = None
        return
    a.assigned_user    = latest.assigned_to if not latest.returned_at else None
    a.assigned_at       = latest.assigned_at
    a.assignment_notes = latest.delivery_notes
    a.returned_at      = latest.returned_at
    a.return_notes     = latest.return_notes

# ── Schemas de entrada del agente ──────────────────────────────────────────
class DiskInfo(BaseModel):
    device: str
    mountpoint: str
    total_gb: float
    used_gb: float
    percent: float
    disk_index: Optional[int] = None  # a que disco fisico pertenece (ver PhysicalDiskInfo)

class PhysicalDiskInfo(BaseModel):
    disk_index: int
    total_gb: float   # tamano REAL de hardware, no suma de particiones
    used_gb: float
    percent: float
    partitions: int
    media_type: Optional[str] = None  # "NVMe SSD"/"SSD"/"HDD"/None si no se pudo determinar
    model: Optional[str] = None  # ej. "Samsung SSD 980 500GB"
    interface: Optional[str] = None  # ej. "PCIe Gen3 x4"/"SATA"/"USB"/None si no se pudo determinar

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
    ram_max_capacity_gb: Optional[int] = None
    ram_total_gb:       Optional[float] = None
    installed_software: list          = []
    device_type: Optional[str] = None  # Laptop|Desktop|Tablet|Other (auto-detectado)
    screen_size_in: Optional[float] = None  # Solo en laptop o PC "All in One" - ver Agent.screen_size_in
    tailnet_ip: Optional[str] = None  # IP unica del tunel WireGuard/Headscale, si esta conectado
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
    process_count: Optional[int] = None
    disk_read_mb_s: Optional[float] = None
    disk_write_mb_s: Optional[float] = None
    net_down_mbps: Optional[float] = None
    net_up_mbps: Optional[float] = None
    disks: list[DiskInfo] = []
    physical_disks: list[PhysicalDiskInfo] = []

# ── Recibir métricas ───────────────────────────────────────────────────────
@router.post("/metrics")
def receive_metrics(payload: MetricPayload, request: Request, db: Session = Depends(get_db)):
    now = datetime.utcnow()

    # Buscar o crear agente: el serial_number es la identidad persistente (es
    # lo único con UNIQUE real en la tabla). El hostname NO se usa como
    # primera búsqueda: dos equipos físicos distintos pueden compartir el
    # mismo nombre de Windows (clonación, error humano al nombrarlos), y
    # buscar primero por hostname mezclaba sus datos en una sola fila.
    found_by_serial = False
    agent = None
    if payload.serial_number:
        agent = db.query(Agent).filter(Agent.serial_number == payload.serial_number).first()
        if agent and agent.hostname != payload.hostname:
            agent.hostname = payload.hostname
            found_by_serial = True
            # Si el equipo fisico se renombro (no un display_name manual - ese
            # es otro campo, ya sincronizado aparte en update_agent()) y esta
            # conectado al tunel, se refleja tambien en Headscale.
            if not agent.display_name_manual and payload.tailnet_ip:
                rename_headscale_node(payload.tailnet_ip, payload.hostname)

    if not agent:
        candidate = db.query(Agent).filter(Agent.hostname == payload.hostname).first()
        # Si el candidato por hostname ya tiene una serie DISTINTA a la
        # reportada ahora, es un equipo físico distinto que solo coincide en
        # nombre: no se mezcla con ese registro, se trata como nuevo.
        if candidate and payload.serial_number and candidate.serial_number \
                and candidate.serial_number != payload.serial_number:
            candidate = None
        agent = candidate

    if not agent and not payload.serial_number and payload.manufacturer and payload.model:
        agent = db.query(Agent).filter(
            Agent.manufacturer == payload.manufacturer,
            Agent.model == payload.model,
            Agent.serial_number.is_(None),
        ).first()
        if agent:
            agent.hostname = payload.hostname
            found_by_serial = True
    was_offline = agent and agent.status == "offline"
    is_new_agent = agent is None

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
    if payload.ram_max_capacity_gb: agent.ram_max_capacity_gb = payload.ram_max_capacity_gb
    if payload.ram_total_gb:       agent.ram_total_gb       = payload.ram_total_gb
    if payload.screen_size_in:     agent.screen_size_in     = payload.screen_size_in
    # A diferencia de los demas campos opcionales de arriba (que solo se
    # actualizan si vienen con dato, porque el hardware no "deja de tener"
    # fabricante/modelo), tailnet_ip SIEMPRE se sobrescribe con lo que
    # reporte el agente - incluido null/vacio, que es exactamente lo que
    # manda cuando el tunel se desconecto. Si solo se actualizara cuando
    # viene con valor, la IP vieja quedaba pegada para siempre en la base y
    # el panel mostraba "Conectado" aunque el equipo ya no lo estuviera.
    agent.tailnet_ip = payload.tailnet_ip
    if payload.installed_software:
        agent.installed_software  = payload.installed_software
        agent.software_updated_at = now
    old_os, old_os_version = agent.os, agent.os_version
    if payload.os:           agent.os = payload.os
    if payload.os_version:   agent.os_version = payload.os_version
    # Cambio de sistema operativo (ej. el equipo se reinstaló con otro OS) -
    # solo se registra si el equipo YA existía con un OS previo conocido, para
    # no generar una entrada de "cambio" en el primer reporte de un agente
    # recien creado (ahi no hay un OS anterior real con el cual comparar).
    if not is_new_agent and old_os and old_os_version:
        old_full = f"{old_os} {old_os_version}".strip()
        new_full = f"{agent.os or old_os} {agent.os_version or old_os_version}".strip()
        if old_full != new_full:
            _log_agent_change(db, agent, "SistemaOperativo", old_full, new_full, changed_by="Sistema")
            db.add(Event(
                agent_id=agent.id, type="os_change",
                detail=f"Sistema operativo cambió de {old_full} a {new_full}",
                reason="Cambio de sistema operativo",
            ))

    # Tipo de dispositivo:
    # - backend: jamás toca agent.device_type si device_type_manual=True
    # - frontend: si el usuario lo tocó, se marca explícitamente
    # No se registra en el historial de cambios: ese historial es para
    # componentes físicos (RAM, batería, fuente, disco), no para la
    # clasificación Laptop/Desktop/Tablet.
    if payload.device_type:
        if agent.device_type_manual:
            pass  # humano lo fijó ⇒ respetar
        else:
            agent.device_type = payload.device_type

    agent.ip = request.client.host if request.client else None
    agent.last_seen = now
    agent.status = "online"

    # Evento: volvió online → resolver todos sus eventos offline anteriores
    if was_offline:
        prev_offline = db.query(Event).filter(
            Event.agent_id == agent.id,
            Event.type == "offline",
            Event.resolved == False
        ).order_by(desc(Event.timestamp)).first()
        db.query(Event).filter(
            Event.agent_id == agent.id,
            Event.type == "offline",
            Event.resolved == False
        ).update({"resolved": True})
        detail = "Equipo reconectado"
        if prev_offline and prev_offline.timestamp:
            mins = round((now - prev_offline.timestamp).total_seconds() / 60, 1)
            detail += f" (estuvo desconectado {_fmt_duration_mins(mins)})"
        db.add(Event(agent_id=agent.id, type="online", detail=detail, reason="Reconectado"))

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
        process_count=payload.process_count,
        disk_read_mb_s=payload.disk_read_mb_s,
        disk_write_mb_s=payload.disk_write_mb_s,
        net_down_mbps=payload.net_down_mbps,
        net_up_mbps=payload.net_up_mbps,
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
                disk_index=d.disk_index,
            ))
    if payload.physical_disks:
        db.query(PhysicalDisk).filter(PhysicalDisk.agent_id == agent.id).delete()
        for pd in payload.physical_disks:
            db.add(PhysicalDisk(
                agent_id=agent.id,
                disk_index=pd.disk_index,
                total_gb=pd.total_gb,
                used_gb=pd.used_gb,
                percent=pd.percent,
                partitions=pd.partitions,
                media_type=pd.media_type,
                model=pd.model,
                interface=pd.interface,
            ))

    # Umbrales globales (Configuracion -> Alertas), iguales para todos los equipos
    thr = _get_thresholds(db)
    check_metric_alerts(agent, payload.cpu_percent, payload.ram_percent, payload.disk_percent, payload.cpu_temp, thr, db, payload.top_processes)

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
        detail = f"Sin reporte por más de {_fmt_duration_mins(mins)} (umbral de desconexión configurado)"
        db.add(Event(agent_id=a.id, type="offline", detail=detail, reason="Desconectado"))
        name = a.display_name or a.hostname
        _notify("⬛ Alerta", f"⬛ <b>{name}</b> — Sin conexión", name, detail, a.id)
    if agents:
        db.commit()

# ── Listar agentes ─────────────────────────────────────────────────────────
@router.get("")
def list_agents(user = Depends(require_permission("dashboard", "view")), db: Session = Depends(get_db)):
    check_offline(db)
    agents = db.query(Agent).all()
    # Capacidad total de disco por equipo (suma de sus discos fisicos) - una
    # sola consulta agrupada para todos los agentes, en vez de una por
    # agente, para no repetir el problema N+1 ya conocido en este endpoint.
    disk_totals = dict(
        db.query(PhysicalDisk.agent_id, func.sum(PhysicalDisk.total_gb)).group_by(PhysicalDisk.agent_id).all()
    )
    result = []
    for a in agents:
        last_metric = db.query(Metric).filter(Metric.agent_id == a.id).order_by(desc(Metric.timestamp)).first()
        ago = int((datetime.utcnow() - a.last_seen).total_seconds()) if a.last_seen else 9999
        assigned_user_obj = db.query(User).filter(User.id == a.assigned_user).first() if a.assigned_user else None
        result.append({
            "id": a.id,
            "hostname": a.hostname,
            "display_name": a.display_name or a.hostname,
            "tailnet_ip": a.tailnet_ip,
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
            "ram_max_capacity_gb": a.ram_max_capacity_gb,
            "disk_total_gb": disk_totals.get(a.id),
            "sede": a.sede.name if a.sede else None,
            "sede_id": a.sede_id,
            "notes": a.notes,
            "device_type": a.device_type,
            "device_type_manual": bool(a.device_type_manual),
            "screen_size_in": a.screen_size_in,
            "assigned_user": a.assigned_user,
            "assigned_user_name": assigned_user_obj.name if assigned_user_obj else None,
            "assigned_user_email": assigned_user_obj.email if assigned_user_obj else None,
            "assigned_at": a.assigned_at.isoformat() if a.assigned_at else None,
            "returned_at": a.returned_at.isoformat() if a.returned_at else None,
            "assignment_notes": a.assignment_notes,
            "return_notes": a.return_notes,
            "review_status": a.review_status,
            # "Z" explicito: paused_until es naive-UTC - sin eso el navegador
            # del admin lo interpreta como su hora local, no UTC (mismo bug
            # corregido en agent_uninstall_codes.py).
            "paused_until": (a.paused_until.isoformat() + "Z") if a.paused_until else None,
            "purchase_date": a.purchase_date.isoformat() if a.purchase_date else None,
            "invoice_number": a.invoice_number,
            "cpu_percent": last_metric.cpu_percent if last_metric else 0,
            "ram_percent": last_metric.ram_percent if last_metric else 0,
            "ram_used_gb": last_metric.ram_used_gb if last_metric else 0,
            "disk_percent": last_metric.disk_percent if last_metric else 0,
            "net_rx_mb": last_metric.net_rx_mb if last_metric else 0,
            "net_tx_mb": last_metric.net_tx_mb if last_metric else 0,
            "cpu_temp": last_metric.cpu_temp if last_metric else None,
            "latency_ms": last_metric.latency_ms if last_metric else None,
            "top_processes": last_metric.top_processes if last_metric else [],
            "process_count": last_metric.process_count if last_metric else None,
            "disk_read_mb_s": last_metric.disk_read_mb_s if last_metric else None,
            "disk_write_mb_s": last_metric.disk_write_mb_s if last_metric else None,
            "net_down_mbps": last_metric.net_down_mbps if last_metric else None,
            "net_up_mbps": last_metric.net_up_mbps if last_metric else None,
            "agent_version": _agent_version(a),
        })
    result.sort(key=lambda x: (x["status"] != "online", -(x["cpu_percent"] or 0)))
    return result

# ── SSE: stream en vivo ───────────────────────────────────────────────────
@router.get("/stream")
async def stream_agents(
    interval: int = 3,
    user = Depends(get_user_from_token_param),
):
    interval = max(1, min(interval, 60))

    # OJO: esta conexión SSE vive mientras el navegador tenga el dashboard
    # abierto (horas). Antes se usaba un único `db` de Depends(get_db) para
    # todo ese tiempo — cada pestaña/reconexión dejaba una conexión del pool
    # ocupada indefinidamente, y tras suficientes horas de uso normal el pool
    # (tamaño 5 + 10 de overflow) se agotaba con un TimeoutError, tumbando
    # el resto de la API con 500. Cada snapshot abre y cierra su propia
    # sesión, así solo ocupa una conexión el instante que tarda en construirse.
    def build_snapshot():
        db = DBSession()
        try:
            check_offline(db)
            agents = db.query(Agent).all()
            disk_totals = dict(
                db.query(PhysicalDisk.agent_id, func.sum(PhysicalDisk.total_gb)).group_by(PhysicalDisk.agent_id).all()
            )
            result = []
            for a in agents:
                last = db.query(Metric).filter(Metric.agent_id == a.id).order_by(desc(Metric.timestamp)).first()
                ago  = int((datetime.utcnow() - a.last_seen).total_seconds()) if a.last_seen else 9999
                assigned_user_obj = db.query(User).filter(User.id == a.assigned_user).first() if a.assigned_user else None
                result.append({
                    "id": a.id, "hostname": a.hostname,
                    "display_name": a.display_name or a.hostname,
                    "tailnet_ip": a.tailnet_ip,
                    "status": a.status, "last_seen_ago": ago,
                    "os": a.os, "os_version": a.os_version,
                    "manufacturer": a.manufacturer, "model": a.model,
                    "serial_number": a.serial_number,
                    "cpu_model": a.cpu_model, "cpu_cores": a.cpu_cores,
                    "ram_total_gb":   a.ram_total_gb,
                    "ram_slots_total": a.ram_slots_total,
                    "ram_slots_used":  a.ram_slots_used,
                    "ram_max_capacity_gb": a.ram_max_capacity_gb,
                    "disk_total_gb": disk_totals.get(a.id),
                    "cpu_percent":  last.cpu_percent  if last else 0,
                    "ram_percent":  last.ram_percent  if last else 0,
                    "ram_used_gb":  last.ram_used_gb  if last else 0,
                    "disk_percent": last.disk_percent if last else 0,
                    "net_rx_mb":    last.net_rx_mb    if last else 0,
                    "net_tx_mb":    last.net_tx_mb    if last else 0,
                    "cpu_temp":     last.cpu_temp     if last else None,
                    "latency_ms":   last.latency_ms   if last else None,
                    "top_processes":last.top_processes if last else [],
                    "process_count":     last.process_count     if last else None,
                    "disk_read_mb_s":    last.disk_read_mb_s    if last else None,
                    "disk_write_mb_s":   last.disk_write_mb_s   if last else None,
                    "net_down_mbps":     last.net_down_mbps     if last else None,
                    "net_up_mbps":       last.net_up_mbps       if last else None,
                    "agent_version": _agent_version(a),
                    "sede": a.sede.name if a.sede else None,
                    "sede_id": a.sede_id,
                    # Estos campos también los usa la vista de Inventario (edición,
                    # tipo de dispositivo, asignaciones): si faltan aquí, cada
                    # refresco del stream (cada pocos segundos) los borra de
                    # allAgents en el frontend aunque sigan bien guardados en la
                    # base de datos — parecía que "no guardaba" el tipo de equipo.
                    "notes": a.notes,
                    "device_type": a.device_type,
                    "device_type_manual": bool(a.device_type_manual),
                    "screen_size_in": a.screen_size_in,
                    "assigned_user": a.assigned_user,
                    "assigned_user_name": assigned_user_obj.name if assigned_user_obj else None,
                    "assigned_user_email": assigned_user_obj.email if assigned_user_obj else None,
                    "assigned_at": a.assigned_at.isoformat() if a.assigned_at else None,
                    "returned_at": a.returned_at.isoformat() if a.returned_at else None,
                    "assignment_notes": a.assignment_notes,
                    "return_notes": a.return_notes,
                    "review_status": a.review_status,
                    # "Z" explicito: paused_until es naive-UTC - sin eso el navegador
            # del admin lo interpreta como su hora local, no UTC (mismo bug
            # corregido en agent_uninstall_codes.py).
            "paused_until": (a.paused_until.isoformat() + "Z") if a.paused_until else None,
                    "purchase_date": a.purchase_date.isoformat() if a.purchase_date else None,
                    "invoice_number": a.invoice_number,
                })
            result.sort(key=lambda x: (x["status"] != "online", -(x["cpu_percent"] or 0)))

            # Mismo criterio que /summary/global: solo la mas reciente por
            # (agente, tipo), ya que puede haber varias filas sin resolver
            # del mismo incidente (una por cada reporte que siga sobre el
            # umbral, para el historial completo en Eventos).
            raw_alerts = db.query(Event).filter(
                Event.resolved == False,
                Event.type.in_(["offline","cpu_high","ram_high","disk_high","temp_high"])
            ).order_by(desc(Event.timestamp)).all()
            seen_alert_keys, alerts = set(), []
            for e in raw_alerts:
                key = (e.agent_id, e.type)
                if key in seen_alert_keys: continue
                seen_alert_keys.add(key)
                alerts.append(e)
                if len(alerts) >= 20: break

            agents_map = {a.id: a for a in db.query(Agent).all()}
            def _alert_name(aid):
                ag = agents_map.get(aid)
                return (ag.display_name or ag.hostname) if ag else "?"
            alert_list = [{"id": e.agent_id,
                           "hostname": _alert_name(e.agent_id),
                           "type": e.type, "detail": e.detail,
                           "timestamp": e.timestamp.isoformat()} for e in alerts]

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
        finally:
            db.close()

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
    agent_ids = {e.agent_id for e in events if e.agent_id}
    agents_map = {a.id: a for a in db.query(Agent).filter(Agent.id.in_(agent_ids)).all()}
    # sede_ids_needed: eventos sin agente (excepciones a nivel de area o
    # globales) referencian la sede directo en Event.sede_id, no via un
    # agente - antes estos eventos se descartaban del todo (silenciosamente)
    # porque el filtro exigia un agente encontrado.
    sede_ids_needed = {e.sede_id for e in events if e.sede_id}
    sedes_map = {s.id: s for s in db.query(Sede).filter(Sede.id.in_(sede_ids_needed)).all()}
    # asset_ids_needed: eventos del inventario general (activos no
    # monitoreados) - mismo trato que sede_id, referencia directa sin agente.
    asset_ids_needed = {e.asset_id for e in events if e.asset_id}
    assets_map = {a.id: a for a in db.query(Asset).filter(Asset.id.in_(asset_ids_needed)).all()}
    result = []
    for e in events:
        a = agents_map.get(e.agent_id) if e.agent_id else None
        if e.agent_id and not a:
            continue  # agente borrado desde entonces - se omite, igual que antes
        s = sedes_map.get(e.sede_id) if e.sede_id else None
        asset = assets_map.get(e.asset_id) if e.asset_id else None
        if e.asset_id and not asset:
            continue  # activo borrado desde entonces
        if sede_id:
            agent_sede = str(a.sede_id) if a and a.sede_id else None
            event_sede = str(e.sede_id) if e.sede_id else None
            if agent_sede != sede_id and event_sede != sede_id:
                continue
        if a:
            hostname, display_name, sede_name = a.hostname, (a.display_name or a.hostname), (a.sede.name if a.sede else None)
        elif asset:
            hostname = display_name = asset.name
            sede_name = asset.sede.name if asset.sede else None
        elif s:
            hostname = display_name = f"Área: {s.name}"
            sede_name = s.name
        else:
            hostname = display_name = "Todos los equipos (global)"
            sede_name = None
        result.append({
            "id": e.id, "hostname": hostname,
            "display_name": display_name,
            "agent_id": e.agent_id,
            "asset_id": e.asset_id,
            "sede": sede_name,
            "type": e.type, "detail": e.detail, "reason": e.reason,
            "timestamp": e.timestamp.isoformat(), "resolved": e.resolved
        })
    return result

# ── Lista de bloqueo (consultada cada 10s por CADA agente) ──────────────────
# Sin caché, esto eran 4-5 consultas a la DB por llamada (sitios bloqueados +
# horario + red permitida): a 200 equipos sondeando cada 10s son ~80-100
# consultas/segundo sostenidas contra Postgres en una máquina de 2GB de RAM.
# Se cachea en memoria lo que es IGUAL para todos los agentes (sitios,
# horarios, red permitida) y se refresca cada BL_CACHE_REFRESH_SEC — el único
# query que sigue siendo por-request es encontrar AL agente puntual (rápido,
# por índice de serial_number/hostname).
_bl_cache_lock = threading.Lock()
_bl_cache = {"ts": 0.0, "active_sites": [], "schedules": [], "gate_enabled": False, "gate_networks": set()}
BL_CACHE_REFRESH_SEC = 5

def _get_bl_cache():
    """Abre su propia Session corta SOLO cuando el cache de verdad necesita
    refrescarse (cada BL_CACHE_REFRESH_SEC) — así puede llamarse también
    desde el hot-path del resolver DNS/DoH (dns_blocker.py), donde abrir una
    Session por request para satisfacer una firma reventaría de vuelta el
    problema de 80-100 queries/seg contra Postgres que este cache evita."""
    with _bl_cache_lock:
        if _time.time() - _bl_cache["ts"] > BL_CACHE_REFRESH_SEC:
            db = DBSession()
            try:
                gate = db.query(NetworkGateConfig).filter(NetworkGateConfig.id == "default").first()
                _bl_cache.update({
                    "ts": _time.time(),
                    "active_sites": db.query(BlockedSite).filter(BlockedSite.active == True).all(),
                    "schedules": db.query(BlockSchedule).all(),
                    "gate_enabled": bool(gate.enabled) if gate else False,
                    "gate_networks": {n.strip().lower() for n in (gate.networks or [])} if gate else set(),
                })
            except Exception as e:
                print(f"[blocklist-cache] error refrescando (se sigue usando el anterior): {e}")
            finally:
                db.close()
        return _bl_cache

# ── Último SSID reportado por cada agente (para el gate de red en el camino
# DoH, que no tiene forma de ver el SSID por su cuenta — solo el agente puede
# observarlo). Se alimenta desde get_blocklist(), que YA recibe el SSID en
# cada sondeo del agente.
_last_ssid_lock = threading.Lock()
_last_ssid: dict = {}  # agent_id -> ultimo ssid reportado

def record_ssid(agent_id: Optional[str], ssid: Optional[str]) -> None:
    if agent_id and ssid:
        with _last_ssid_lock:
            _last_ssid[agent_id] = ssid

def get_last_ssid(agent_id: Optional[str]) -> Optional[str]:
    with _last_ssid_lock:
        return _last_ssid.get(agent_id) if agent_id else None

def _resolve_schedule_cached(agent, schedules):
    """Misma prioridad y semantica que resolve_schedule_for_agent, pero
    resuelta en memoria contra la lista ya cacheada en vez de consultar la DB."""
    if agent:
        agent_s = next((s for s in schedules if s.agent_id == agent.id), None)
        if agent_s and (agent_s.expires_at is None or agent_s.expires_at > _local_now(agent_s.timezone)):
            return agent_s
        if agent.sede_id:
            sede_s = next((s for s in schedules if s.sede_id == agent.sede_id), None)
            if sede_s:
                return sede_s
    return next((s for s in schedules if s.agent_id is None and s.sede_id is None), None)

def _is_network_allowed_cached(ssid: Optional[str], cache: dict) -> bool:
    if not cache["gate_enabled"]:
        return True
    if not ssid:
        return False
    return ssid.strip().lower() in cache["gate_networks"]

def resolve_should_block(agent, ssid: Optional[str]) -> bool:
    """Único punto de verdad para 'debe bloquear ahora mismo' (horario +
    red permitida + no-pausado). Usado tanto por get_blocklist() como por
    el camino DoH en dns_blocker.py (resolve_dns_query) — no duplicar esta
    lógica en ningún otro lado."""
    cache = _get_bl_cache()
    schedule = _resolve_schedule_cached(agent, cache["schedules"])
    is_paused = bool(agent and agent.paused_until and agent.paused_until > datetime.utcnow())
    return is_within_schedule(schedule) and _is_network_allowed_cached(ssid, cache) and not is_paused

@router.get("/blocklist")
def get_blocklist(hostname: str, ssid: Optional[str] = Query(None), serial: Optional[str] = Query(None), db: Session = Depends(get_db)):
    # El hostname puede repetirse entre equipos distintos (ver receive_metrics),
    # así que si el agente manda su serial (versión nueva del script) se usa
    # eso para identificarlo sin ambigüedad. Si no lo manda (agente viejo
    # todavía no actualizado), se cae de vuelta al hostname como antes.
    agent = None
    if serial:
        agent = db.query(Agent).filter(Agent.serial_number == serial).first()
    if not agent:
        agent = db.query(Agent).filter(Agent.hostname == hostname).first()

    record_ssid(agent.id if agent else None, ssid)

    cache = _get_bl_cache()
    active_sites = cache["active_sites"]
    all_domains = resolve_all_configured_domains(agent, active_sites)
    domains = resolve_domains_for_agent(agent, active_sites)

    should_block = resolve_should_block(agent, ssid)

    if not should_block:
        domains = []

    return {"should_block": should_block, "domains": sorted(domains), "all_domains": sorted(all_domains)}

# ── Detalle de un agente ───────────────────────────────────────────────────
@router.get("/{agent_id}")
def get_agent(agent_id: str, user = Depends(require_permission("inventory", "view")), db: Session = Depends(get_db)):
    a = db.query(Agent).filter(Agent.id == agent_id).first()
    if not a:
        raise HTTPException(404, "Agente no encontrado")
    # order_by(Disk.id) importa: el panel usa disks[0] como respaldo cuando no
    # encuentra un mountpoint '/' (Windows nunca lo tiene) - sin este orden,
    # el orden de retorno de Postgres no esta garantizado y ese respaldo
    # podia terminar mostrando cualquier disco (ej. una unidad de red
    # mapeada) en vez del disco de sistema que el agente ya manda primero.
    disks = db.query(Disk).filter(Disk.agent_id == a.id).order_by(Disk.id).all()
    physical_disks = db.query(PhysicalDisk).filter(PhysicalDisk.agent_id == a.id).order_by(PhysicalDisk.disk_index).all()
    return {
        "id": a.id, "hostname": a.hostname, "display_name": a.display_name,
        "status": a.status, "os": a.os, "os_version": a.os_version,
        "manufacturer": a.manufacturer, "model": a.model,
        "serial_number": a.serial_number, "cpu_model": a.cpu_model,
        "cpu_cores": a.cpu_cores, "ram_total_gb": a.ram_total_gb,
        "ram_slots_total": a.ram_slots_total, "ram_slots_used": a.ram_slots_used,
        "ram_max_capacity_gb": a.ram_max_capacity_gb,
        "ram_slots_detail": a.ram_slots_detail or [],
        "sede_id": a.sede_id, "notes": a.notes,
        "device_type": a.device_type, "device_type_manual": bool(a.device_type_manual),
        "screen_size_in": a.screen_size_in,
        "assigned_user": a.assigned_user,
        "assigned_user_name": (db.query(User).filter(User.id == a.assigned_user).first().name
                                if a.assigned_user else None),
        "assigned_at": a.assigned_at.isoformat() if a.assigned_at else None,
        "returned_at": a.returned_at.isoformat() if a.returned_at else None,
        "assignment_notes": a.assignment_notes,
        "return_notes": a.return_notes,
        "review_status": a.review_status,
        "paused_until": (a.paused_until.isoformat() + "Z") if a.paused_until else None,
            "purchase_date": a.purchase_date.isoformat() if a.purchase_date else None,
            "invoice_number": a.invoice_number,
        "first_seen": a.first_seen.isoformat() if a.first_seen else None,
        "last_seen": a.last_seen.isoformat() if a.last_seen else None,
        "disks": [{"device": d.device, "mountpoint": d.mountpoint,
                   "total_gb": d.total_gb, "used_gb": d.used_gb, "percent": d.percent,
                   "disk_index": d.disk_index} for d in disks],
        "physical_disks": [{"disk_index": pd.disk_index, "total_gb": pd.total_gb,
                             "used_gb": pd.used_gb, "percent": pd.percent,
                             "partitions": pd.partitions, "media_type": pd.media_type,
                             "model": pd.model, "interface": pd.interface} for pd in physical_disks],
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
        if a.tailnet_ip:
            rename_headscale_node(a.tailnet_ip, a.display_name)
    if "notes" in data:        a.notes = data["notes"]
    if "sede_id" in data:      a.sede_id = data["sede_id"] or None
    if "device_type" in data and data.get("device_type"):
        # No se registra en el historial de cambios: ese historial es para
        # componentes físicos (RAM, batería, fuente, disco), no para la
        # clasificación Laptop/Desktop/Tablet.
        a.device_type = str(data["device_type"])
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
    if "purchase_date" in data:
        a.purchase_date = _parse_date(data.get("purchase_date"))
    if "invoice_number" in data:
        a.invoice_number = (data.get("invoice_number") or "").strip() or None
    db.commit()
    return {"ok": True}

# ── Estado del equipo en Inventario (Disponible/Asignado se derivan solos;  ─
#    En observación/Baja son manuales) ───────────────────────────────────────
@router.put("/{agent_id}/review-status")
def set_review_status(agent_id: str, data: dict, user = Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    a = db.query(Agent).filter(Agent.id == agent_id).first()
    if not a:
        raise HTTPException(404, "Agente no encontrado")
    status = data.get("status") or None
    if status not in (None, "en_observacion", "baja"):
        raise HTTPException(400, "Estado no válido.")
    note = str(data.get("note") or "").strip()
    if not note:
        raise HTTPException(400, "Indica el motivo.")
    today = datetime.utcnow().date()
    by = (user.name or user.email if user else None)

    # Todo cambio manual de estado exige motivo y queda registrado en el
    # historial de cambios, igual que una reparación.
    if status in ("en_observacion", "baja"):
        db.add(AgentChangeLog(
            agent_id=agent_id,
            field=("Baja" if status == "baja" else "EnObservacion"),
            note=note, change_date=today, changed_by=by,
        ))

    if status == "baja":
        # Dar de baja un equipo con una asignación abierta la cierra sola —
        # un equipo dado de baja no puede seguir figurando como "asignado".
        latest = db.query(AssignmentLog).filter(AssignmentLog.agent_id == agent_id)\
                    .order_by(desc(AssignmentLog.assigned_at), desc(AssignmentLog.created_at)).first()
        if latest and (latest.assigned_to or latest.assigned_to_name) and not latest.returned_at:
            latest.returned_at = today
            latest.return_notes = (latest.return_notes + " — Dado de baja") if latest.return_notes else "Dado de baja"
            latest.changed_by = by
            _sync_agent_from_latest_assignment(a, latest)
    elif a.review_status in ("en_observacion", "baja") and status is None:
        # Reactivación: vuelve a Normal desde un estado especial — se documenta
        # también, para no perder el rastro de que hubo una vuelta atrás.
        db.add(AgentChangeLog(
            agent_id=agent_id, field="Reactivacion",
            note=note, change_date=today, changed_by=by,
        ))
    a.review_status = status
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
    # Registrar un cambio/mantenimiento pone el equipo "en observación"
    # automáticamente — salvo que ya esté dado de baja, que no se debe pisar.
    if a.review_status != "baja":
        a.review_status = "en_observacion"
    db.commit()
    return {"ok": True}

@router.put("/{agent_id}/changes/{record_id}")
def update_agent_change(agent_id: str, record_id: int, data: dict, user = Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    """Corrige un registro ya cargado del historial de cambios (p.ej. una
    fecha mal escrita) sin perder la trazabilidad de quién lo registró."""
    rec = db.query(AgentChangeLog).filter(AgentChangeLog.id == record_id, AgentChangeLog.agent_id == agent_id).first()
    if not rec:
        raise HTTPException(404, "Registro no encontrado")
    field = str(data.get("field") or "").strip()
    change_date = data.get("change_date")
    note = str(data.get("note") or "").strip()
    if not field or not change_date or not note:
        raise HTTPException(400, "Todos los campos son obligatorios: componente, fecha de cambio y motivo.")
    try:
        cd = datetime.strptime(change_date, "%Y-%m-%d").date()
    except Exception:
        raise HTTPException(400, "La fecha de cambio no es válida (AAAA-MM-DD).")
    rec.field = field
    rec.change_date = cd
    rec.note = note
    rec.changed_by = (user.name or user.email if user else None)
    db.commit()
    return {"ok": True}

# ── Historial de equipos de una persona (misma tabla, vista al revés) ───────
@router.get("/by-user/{user_id}/assignments")
def get_assignments_by_user(user_id: str, user = Depends(require_permission("inventory", "view")), db: Session = Depends(get_db)):
    rows = db.query(AssignmentLog).filter(AssignmentLog.assigned_to == user_id)\
              .order_by(desc(AssignmentLog.assigned_at), desc(AssignmentLog.created_at)).all()
    agent_ids = {r.agent_id for r in rows}
    agents = {a.id: a for a in db.query(Agent).filter(Agent.id.in_(agent_ids)).all()} if agent_ids else {}
    return [{
        "id": r.id,
        "agent_id": r.agent_id,
        "hostname": agents[r.agent_id].hostname if r.agent_id in agents else None,
        "display_name": (agents[r.agent_id].display_name or agents[r.agent_id].hostname) if r.agent_id in agents else "(equipo eliminado)",
        "assigned_to_name": r.assigned_to_name,
        "assigned_at": r.assigned_at.isoformat() if r.assigned_at else None,
        "delivery_notes": r.delivery_notes,
        "returned_at": r.returned_at.isoformat() if r.returned_at else None,
        "return_notes": r.return_notes,
        "changed_by": r.changed_by,
    } for r in rows]

# ── Historial de asignaciones (log de entregas/devoluciones) ────────────────
@router.get("/{agent_id}/assignments")
def get_assignments(agent_id: str, user = Depends(require_permission("inventory", "view")), db: Session = Depends(get_db)):
    a = db.query(Agent).filter(Agent.id == agent_id).first()
    if not a:
        raise HTTPException(404, "Agente no encontrado")
    rows = db.query(AssignmentLog).filter(AssignmentLog.agent_id == agent_id)\
              .order_by(desc(AssignmentLog.assigned_at), desc(AssignmentLog.created_at)).all()
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
    assigned_at = _parse_date(data.get("assigned_at"))
    returned_at = _parse_date(data.get("returned_at"))
    _validate_assignment_dates(db, agent_id, assigned_at, returned_at)
    rec = AssignmentLog(
        agent_id=agent_id,
        assigned_to=assigned_to,
        assigned_to_name=name,
        assigned_at=assigned_at,
        delivery_notes=data.get("delivery_notes") or None,
        returned_at=returned_at,
        return_notes=data.get("return_notes") or None,
        changed_by=(user.name or user.email if user else None),
    )
    db.add(rec)
    db.flush()
    # La "asignación actual" del agente refleja el registro más reciente por
    # fecha de asignación — no necesariamente el que se acaba de crear, si se
    # está cargando un registro histórico con fecha anterior a otro ya existente.
    latest = db.query(AssignmentLog).filter(AssignmentLog.agent_id == agent_id)\
                .order_by(desc(AssignmentLog.assigned_at), desc(AssignmentLog.created_at)).first()
    _sync_agent_from_latest_assignment(a, latest)
    db.commit()
    return {"ok": True}

@router.put("/{agent_id}/assignments/{record_id}")
def update_assignment(agent_id: str, record_id: int, data: dict, user = Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    """Actualiza un registro de asignación existente — se usa principalmente
    para 'Devolver' un equipo: agrega fecha/observaciones de devolución a la
    asignación ya abierta en vez de crear un registro nuevo y desconectado."""
    a = db.query(Agent).filter(Agent.id == agent_id).first()
    if not a:
        raise HTTPException(404, "Agente no encontrado")
    rec = db.query(AssignmentLog).filter(AssignmentLog.id == record_id, AssignmentLog.agent_id == agent_id).first()
    if not rec:
        raise HTTPException(404, "Registro no encontrado")

    new_assigned_at = _parse_date(data.get("assigned_at")) if "assigned_at" in data else rec.assigned_at
    new_returned_at = _parse_date(data.get("returned_at")) if "returned_at" in data else rec.returned_at
    _validate_assignment_dates(db, agent_id, new_assigned_at, new_returned_at, exclude_id=rec.id)

    if "assigned_to" in data or "assigned_to_name" in data:
        assigned_to = data.get("assigned_to") or None
        name = data.get("assigned_to_name")
        if not name and assigned_to:
            u = db.query(User).filter(User.id == assigned_to).first()
            name = u.name if u else None
        rec.assigned_to = assigned_to
        rec.assigned_to_name = name
    rec.assigned_at = new_assigned_at
    rec.returned_at = new_returned_at
    if "delivery_notes" in data: rec.delivery_notes = data.get("delivery_notes") or None
    if "return_notes" in data:   rec.return_notes = data.get("return_notes") or None
    rec.changed_by = (user.name or user.email if user else None)

    # El resumen del agente siempre se recalcula desde el registro más
    # reciente por fecha de asignación — de paso, autocorrige el resumen si
    # había quedado desincronizado por datos viejos.
    latest = db.query(AssignmentLog).filter(AssignmentLog.agent_id == agent_id)\
                .order_by(desc(AssignmentLog.assigned_at), desc(AssignmentLog.created_at)).first()
    _sync_agent_from_latest_assignment(a, latest)
    db.commit()
    return {"ok": True}

@router.delete("/{agent_id}/assignments/{record_id}")
def delete_assignment(agent_id: str, record_id: int, user = Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    rec = db.query(AssignmentLog).filter(AssignmentLog.id == record_id, AssignmentLog.agent_id == agent_id).first()
    if not rec:
        raise HTTPException(404, "Registro no encontrado")
    was_latest = db.query(AssignmentLog).filter(AssignmentLog.agent_id == agent_id)\
                    .order_by(desc(AssignmentLog.assigned_at), desc(AssignmentLog.created_at)).first().id == rec.id
    db.delete(rec)
    db.flush()
    if was_latest:
        # El resumen "asignado a" del equipo reflejaba este registro — hay que
        # recalcularlo con el que quede más reciente (o limpiarlo si no queda
        # ninguno), si no se queda con datos de un registro que ya no existe.
        a = db.query(Agent).filter(Agent.id == agent_id).first()
        new_latest = db.query(AssignmentLog).filter(AssignmentLog.agent_id == agent_id)\
                        .order_by(desc(AssignmentLog.assigned_at), desc(AssignmentLog.created_at)).first()
        if a:
            _sync_agent_from_latest_assignment(a, new_latest)
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
    return [{"id": e.id, "type": e.type, "detail": e.detail, "reason": e.reason,
             "timestamp": e.timestamp.isoformat(), "resolved": e.resolved} for e in events]

# ── Summary global ────────────────────────────────────────────────────────
@router.get("/summary/global")
def get_summary(user = Depends(require_permission("dashboard", "view")), db: Session = Depends(get_db)):
    check_offline(db)
    agents = db.query(Agent).all()
    online  = sum(1 for a in agents if a.status == "online")
    offline = sum(1 for a in agents if a.status == "offline")
    # check_metric_alerts() registra un Event por CADA reporte que siga sobre
    # el umbral (para el historial completo en Eventos), asi que puede haber
    # varias filas sin resolver del mismo tipo para el mismo equipo - aca se
    # deja solo la mas reciente por (agente, tipo), para que "Alertas
    # activas" muestre cada incidente una sola vez en vez de repetido.
    raw = db.query(Event).filter(
                  Event.resolved == False,
                  Event.type.in_(["offline", "cpu_high", "ram_high", "disk_high", "temp_high"])
              ).order_by(desc(Event.timestamp)).all()
    seen, alerts = set(), []
    for e in raw:
        key = (e.agent_id, e.type)
        if key in seen: continue
        seen.add(key)
        alerts.append(e)
        if len(alerts) >= 20: break
    # Nombre para mostrar en la alerta: el mismo criterio que el resto del
    # panel (display_name si existe, si no el hostname) - reutiliza la lista
    # de agentes ya cargada arriba en vez de una consulta por fila.
    agents_map = {a.id: a for a in agents}
    def _alert_name(aid):
        ag = agents_map.get(aid)
        return (ag.display_name or ag.hostname) if ag else "?"
    return {
        "total": len(agents), "online": online, "offline": offline,
        "alerts": [{"id": e.agent_id,
                    "hostname": _alert_name(e.agent_id),
                    "type": e.type, "detail": e.detail,
                    "timestamp": e.timestamp.isoformat()} for e in alerts]
    }

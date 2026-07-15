from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Date, Text, ForeignKey, JSON, UniqueConstraint
)
from sqlalchemy.orm import relationship, DeclarativeBase
from sqlalchemy.sql import func
import uuid

class Base(DeclarativeBase):
    pass

def gen_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"
    id                   = Column(String, primary_key=True, default=gen_uuid)
    name                 = Column(String, nullable=False)
    email                = Column(String, unique=True, nullable=False, index=True)
    password             = Column(String, nullable=False)
    role                 = Column(String, default="technician")  # deprecado: se mantiene solo por compatibilidad de datos viejos, ya no se usa para permisos (ver role_id)
    role_id              = Column(String, ForeignKey("roles.id"), nullable=True, index=True)
    active               = Column(Boolean, default=True)
    has_access           = Column(Boolean, default=True)  # False = existe solo para asignarle equipos (estilo "acceso a consola" de AWS IAM), no puede iniciar sesión
    must_change_password = Column(Boolean, default=False)
    token_version        = Column(Integer, default=0)  # incrementar invalida todos los tokens ya emitidos (revocar sesiones)
    password_changed_at  = Column(DateTime, server_default=func.now())  # para calcular expiración de contraseña
    created_at           = Column(DateTime, server_default=func.now())
    role_obj             = relationship("Role")

# ── Roles y permisos (por sección, granularidad none/view/edit/manage) ─────
class Role(Base):
    __tablename__ = "roles"
    id         = Column(String, primary_key=True, default=gen_uuid)
    name       = Column(String, unique=True, nullable=False)
    is_admin_role = Column(Boolean, default=False)  # el rol "Admin" sembrado: no se puede eliminar (los demás roles sí)
    created_at = Column(DateTime, server_default=func.now())

class RolePermission(Base):
    __tablename__ = "role_permissions"
    __table_args__ = (UniqueConstraint("role_id", "section", name="uq_role_section"),)
    id      = Column(String, primary_key=True, default=gen_uuid)
    role_id = Column(String, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True)
    section = Column(String, nullable=False)
    level   = Column(String, nullable=False, default="none")  # none | view | edit | manage

# ── Política de contraseñas (config global, estilo IAM) ────────────────────
class PasswordPolicy(Base):
    __tablename__ = "password_policy"
    id                   = Column(String, primary_key=True, default=lambda: "default")
    min_length           = Column(Integer, default=8)
    require_uppercase    = Column(Boolean, default=True)
    require_lowercase    = Column(Boolean, default=True)
    require_number       = Column(Boolean, default=True)
    require_special      = Column(Boolean, default=True)
    expiration_enabled   = Column(Boolean, default=False)
    expire_days          = Column(Integer, default=90)
    prevent_reuse        = Column(Boolean, default=True)
    reuse_remember_count = Column(Integer, default=3)
    created_at           = Column(DateTime, server_default=func.now())

# ── Historial de contraseñas (para hacer cumplir "prevent_reuse") ──────────
class PasswordHistory(Base):
    __tablename__ = "password_history"
    id         = Column(String, primary_key=True, default=gen_uuid)
    user_id    = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    password   = Column(String, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

class Sede(Base):
    __tablename__ = "sedes"
    id          = Column(String, primary_key=True, default=gen_uuid)
    name        = Column(String, nullable=False)
    location    = Column(String)
    created_at  = Column(DateTime, server_default=func.now())
    agents      = relationship("Agent", back_populates="sede")

class Agent(Base):
    __tablename__ = "agents"
    id              = Column(String, primary_key=True, default=gen_uuid)
    # No unique: dos equipos físicos distintos pueden terminar con el mismo
    # hostname de Windows (clonación, error humano al nombrarlos). La
    # identidad real y única del equipo es serial_number (ver más abajo).
    hostname        = Column(String, nullable=False, index=True)
    ip              = Column(String, nullable=True, index=True)
    # IP unica dentro del tailnet de Headscale (WireGuard), si el agente esta
    # conectado por tunel. A diferencia de `ip` (la IP publica, que varios
    # equipos de una misma oficina comparten), esta identifica al equipo sin
    # ambiguedad — dns_blocker.py la prefiere sobre `ip` cuando existe.
    tailnet_ip      = Column(String, nullable=True, index=True)
    display_name    = Column(String)
    display_name_manual = Column(Boolean, default=False)
    sede_id         = Column(String, ForeignKey("sedes.id"), nullable=True)
    assigned_user   = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    notes           = Column(Text)
    first_seen      = Column(DateTime, server_default=func.now())
    last_seen       = Column(DateTime)
    status          = Column(String, default="offline")
    os              = Column(String)
    os_version      = Column(String)
    manufacturer    = Column(String)
    model           = Column(String)
    serial_number   = Column(String, unique=True, nullable=True)
    cpu_model       = Column(String)
    cpu_cores       = Column(Integer)
    ram_slots_total      = Column(Integer)
    ram_slots_used       = Column(Integer)
    ram_slots_detail     = Column(JSON, nullable=True)
    ram_total_gb         = Column(Float)
    installed_software   = Column(JSON, nullable=True)
    software_updated_at  = Column(DateTime, nullable=True)
    device_type        = Column(String, nullable=True)   # Laptop|Desktop|Tablet|Other (auto o manual)
    device_type_manual = Column(Boolean, default=False)  # True si un humano lo fijó
    assigned_at      = Column(Date, nullable=True)       # fecha de asignación
    returned_at      = Column(Date, nullable=True)       # fecha de devolución
    assignment_notes = Column(Text, nullable=True)       # observaciones al asignar
    return_notes     = Column(Text, nullable=True)       # observaciones al devolver
    # None = estado normal (Asignado/Disponible se derivan solos de assigned_user/
    # returned_at); "en_observacion" | "baja" son estados manuales que pisan esa
    # derivación para mostrar en Inventario. "en_observacion" también se activa
    # solo al registrar un cambio en el historial de mantenimiento.
    review_status    = Column(String, nullable=True)
    purchase_date    = Column(Date, nullable=True)        # fecha de compra
    invoice_number   = Column(String, nullable=True)      # número de factura
    sede            = relationship("Sede", back_populates="agents")
    metrics         = relationship("Metric", back_populates="agent", cascade="all, delete-orphan")
    disks           = relationship("Disk", back_populates="agent", cascade="all, delete-orphan")
    events          = relationship("Event", back_populates="agent", cascade="all, delete-orphan")

class AgentChangeLog(Base):
    __tablename__ = "agent_change_log"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    agent_id    = Column(String, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    field       = Column(String, nullable=False)   # device_type | RAM | Batería | Fuente | Disco | Otro
    old_value   = Column(Text, nullable=True)
    new_value   = Column(Text, nullable=True)
    note        = Column(Text, nullable=True)      # detalle libre (ej. "cambio por falla")
    change_date = Column(Date, nullable=True)      # fecha en que ocurrió el cambio
    changed_by  = Column(String, nullable=True)
    changed_at  = Column(DateTime, server_default=func.now())
    agent       = relationship("Agent")

class AssignmentLog(Base):
    __tablename__ = "assignment_log"
    id              = Column(Integer, primary_key=True, autoincrement=True)
    agent_id        = Column(String, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    assigned_to     = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assigned_to_name = Column(String, nullable=True)   # desnormalizado para mostrar aunque se borre el usuario
    assigned_at     = Column(Date, nullable=True)       # fecha de asignación/entrega
    delivery_notes  = Column(Text, nullable=True)       # observaciones de entrega
    returned_at     = Column(Date, nullable=True)       # fecha de devolución
    return_notes    = Column(Text, nullable=True)       # observaciones de devolución
    changed_by      = Column(String, nullable=True)
    created_at      = Column(DateTime, server_default=func.now())
    agent           = relationship("Agent")

class Metric(Base):
    __tablename__ = "metrics"
    id              = Column(Integer, primary_key=True, autoincrement=True)
    agent_id        = Column(String, ForeignKey("agents.id"), nullable=False, index=True)
    timestamp       = Column(DateTime, server_default=func.now(), index=True)
    cpu_percent     = Column(Float)
    ram_percent     = Column(Float)
    ram_used_gb     = Column(Float)
    disk_percent    = Column(Float)
    net_rx_mb       = Column(Float)
    net_tx_mb       = Column(Float)
    cpu_temp        = Column(Float, nullable=True)
    latency_ms      = Column(Float, nullable=True)
    top_processes   = Column(JSON)
    agent           = relationship("Agent", back_populates="metrics")

class Disk(Base):
    __tablename__ = "disks"
    id              = Column(Integer, primary_key=True, autoincrement=True)
    agent_id        = Column(String, ForeignKey("agents.id"), nullable=False)
    device          = Column(String)
    mountpoint      = Column(String)
    total_gb        = Column(Float)
    used_gb         = Column(Float)
    percent         = Column(Float)
    updated_at      = Column(DateTime, server_default=func.now(), onupdate=func.now())
    agent           = relationship("Agent", back_populates="disks")

class Event(Base):
    __tablename__ = "events"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    agent_id    = Column(String, ForeignKey("agents.id"), nullable=False, index=True)
    timestamp   = Column(DateTime, server_default=func.now(), index=True)
    type        = Column(String)
    detail      = Column(String)
    resolved    = Column(Boolean, default=False)
    agent       = relationship("Agent", back_populates="events")

class AlertConfig(Base):
    __tablename__ = "alert_configs"
    id              = Column(String, primary_key=True, default=gen_uuid)
    agent_id        = Column(String, ForeignKey("agents.id"), nullable=True)
    cpu_threshold   = Column(Float, default=85.0)
    ram_threshold   = Column(Float, default=85.0)
    disk_threshold  = Column(Float, default=90.0)
    temp_threshold  = Column(Float, default=80.0)
    active          = Column(Boolean, default=True)

# ── Blocked Sites (bloqueo de páginas) ─────────────────────────────────────────
class BlockCategory(Base):
    __tablename__ = "block_categories"
    id          = Column(String, primary_key=True, default=gen_uuid)
    label       = Column(String, nullable=False)
    domains     = Column(JSON, nullable=False, default=list)
    group_key   = Column(String, nullable=False, default="parental")  # "parental" | "productividad"
    created_at  = Column(DateTime, server_default=func.now())

# ── Horario de bloqueo (solo aplica en horario de oficina) ─────────────────────
class BlockSchedule(Base):
    __tablename__ = "block_schedules"
    id         = Column(String, primary_key=True, default=gen_uuid)
    agent_id   = Column(String, ForeignKey("agents.id", ondelete="CASCADE"), nullable=True, index=True)
    sede_id    = Column(String, ForeignKey("sedes.id", ondelete="CASCADE"), nullable=True, index=True)
    # agent_id y sede_id ambos NULL = horario global por defecto (debe existir siempre exactamente una fila así)
    enabled    = Column(Boolean, default=True)   # False = bloqueo desactivado siempre en este alcance
    timezone   = Column(String, default="America/Lima")
    days       = Column(JSON, nullable=False, default=dict)  # {"mon":["06:00","19:00"], ..., "sat":["06:00","13:00"]} - dia ausente = no bloquea ese dia
    expires_at = Column(DateTime, nullable=True)  # solo para excepciones de equipo: pasada esta fecha se ignora sola
    created_at = Column(DateTime, server_default=func.now())
    agent      = relationship("Agent")
    sede       = relationship("Sede")

class BlockedSite(Base):
    __tablename__ = "blocked_sites"
    id           = Column(String, primary_key=True, default=gen_uuid)
    domain       = Column(String, nullable=False, index=True)
    agent_id     = Column(String, ForeignKey("agents.id", ondelete="CASCADE"), nullable=True, index=True)  # null = global (si sede_id tampoco está seteado)
    sede_id      = Column(String, ForeignKey("sedes.id", ondelete="CASCADE"), nullable=True, index=True)  # alcance por área
    is_exception = Column(Boolean, default=False)  # True = excluye el dominio para agent_id/sede_id de un bloqueo global/heredado
    category     = Column(String, nullable=True, index=True)  # ej. "streaming" si vino de un bloqueo por categoría; null = sitio personalizado
    section      = Column(String, nullable=True)  # "parental" si se creó desde la página Control Parental; null = página general
    reason       = Column(String, nullable=True)
    active       = Column(Boolean, default=True)
    expires_at   = Column(DateTime, nullable=True)  # solo relevante para excepciones: pasada esta fecha se ignora sola
    created_at   = Column(DateTime, server_default=func.now())
    agent        = relationship("Agent")
    sede         = relationship("Sede")

# ── Restricción por red WiFi (aplica el bloqueo solo en ciertas redes) ─────
class NetworkGateConfig(Base):
    __tablename__ = "network_gate_config"
    id         = Column(String, primary_key=True, default=lambda: "default")
    enabled    = Column(Boolean, default=False)
    networks   = Column(JSON, nullable=False, default=list)  # lista de SSID permitidos
    created_at = Column(DateTime, server_default=func.now())

# ── Intentos de acceso a sitios bloqueados (resumen agregado por día) ──────
class BlockAttempt(Base):
    __tablename__ = "block_attempts"
    __table_args__ = (UniqueConstraint("agent_id", "domain", "date", "blocked", name="uq_block_attempt_agent_domain_date_blocked"),)
    id         = Column(String, primary_key=True, default=gen_uuid)
    agent_id   = Column(String, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    domain     = Column(String, nullable=False, index=True)
    date       = Column(Date, nullable=False, index=True)
    blocked    = Column(Boolean, nullable=False, default=True)  # False = dominio de la config que se dejó pasar (excepción/horario/red)
    count      = Column(Integer, nullable=False, default=0)
    last_seen  = Column(DateTime, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    agent      = relationship("Agent")

class BlockAttemptConfig(Base):
    __tablename__ = "block_attempt_config"
    id             = Column(String, primary_key=True, default=lambda: "default")
    retention_days = Column(Integer, nullable=True)  # None = nunca borrar automáticamente
    created_at     = Column(DateTime, server_default=func.now())

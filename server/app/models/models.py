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
    is_default_admin     = Column(Boolean, default=False)  # el admin sembrado de fabrica: no se puede eliminar desde el panel (solo desactivar/cambiar contraseña), red de seguridad para nunca quedar bloqueados afuera
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

# ── Historial de accesos (login exitoso o intento fallido) ────────────────
class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    email      = Column(String, index=True)
    # nullable: un intento fallido puede ser con un email que ni siquiera
    # existe como usuario - ahi no hay user_id que referenciar.
    user_id    = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    success    = Column(Boolean, default=False, index=True)
    reason     = Column(String, nullable=True)  # motivo del fallo; null si success=True
    ip_address = Column(String, nullable=True)
    timestamp  = Column(DateTime, server_default=func.now(), index=True)

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
    ram_max_capacity_gb  = Column(Integer, nullable=True)  # limite de RAM de la placa (Win32_PhysicalMemoryArray.MaxCapacity / dmidecode "Maximum Capacity")
    ram_total_gb         = Column(Float)
    installed_software   = Column(JSON, nullable=True)
    software_updated_at  = Column(DateTime, nullable=True)
    device_type        = Column(String, nullable=True)   # Laptop|Desktop|Tablet|Other (auto o manual)
    device_type_manual = Column(Boolean, default=False)  # True si un humano lo fijó
    # Tamaño de pantalla en pulgadas (diagonal, via EDID del panel/monitor) -
    # solo tiene sentido si la pantalla es parte fisica del equipo: laptop
    # (pantalla integrada siempre) o PC "All in One" (chasis tipo 13). Un
    # desktop normal con monitor aparte queda en None a proposito - ese
    # monitor no es del equipo, podria cambiarse sin que signifique nada.
    screen_size_in     = Column(Float, nullable=True)
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
    # Pausa temporal del bloqueo de sitios (NO del monitoreo/metricas) para
    # este equipo, puesta a mano desde el panel - ver get_blocklist(). Se usa
    # tambien para la pausa que el propio usuario del equipo dispara con un
    # codigo (ver AgentPauseCode) - misma columna, dos formas de setearla.
    paused_until     = Column(DateTime, nullable=True)
    # Si la pausa activa fue pedida como "hasta reiniciar" (no una duracion
    # fija) - el agente la limpia solo al arrancar (ver cmd_clear_reboot_pause
    # / startup de smartmonitor_agent.py), independiente de paused_until.
    pause_until_reboot = Column(Boolean, default=False)
    sede            = relationship("Sede", back_populates="agents")
    metrics         = relationship("Metric", back_populates="agent", cascade="all, delete-orphan")
    disks           = relationship("Disk", back_populates="agent", cascade="all, delete-orphan")
    physical_disks  = relationship("PhysicalDisk", back_populates="agent", cascade="all, delete-orphan")
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

class PasswordResetToken(Base):
    """Token de un solo uso para "Olvidé mi contraseña" - se manda por email
    (link, no un código a tipear a mano como los de arriba), por eso es un
    string largo y aleatorio en vez de 8 caracteres."""
    __tablename__ = "password_reset_tokens"
    id          = Column(String, primary_key=True, default=gen_uuid)
    user_id     = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token       = Column(String, nullable=False, unique=True, index=True)
    expires_at  = Column(DateTime, nullable=False)
    used_at     = Column(DateTime, nullable=True)
    created_at  = Column(DateTime, server_default=func.now())
    user        = relationship("User")

class AgentUninstallCode(Base):
    __tablename__ = "agent_uninstall_codes"
    id          = Column(String, primary_key=True, default=gen_uuid)
    agent_id    = Column(String, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    code        = Column(String, nullable=False, index=True)
    expires_at  = Column(DateTime, nullable=False)
    used_at     = Column(DateTime, nullable=True)
    attempts    = Column(Integer, default=0)
    invalidated = Column(Boolean, default=False)
    created_by  = Column(String, nullable=True)
    created_at  = Column(DateTime, server_default=func.now())
    agent       = relationship("Agent")

class AgentPauseCode(Base):
    """Codigo de un solo uso para que el propio usuario del equipo pause el
    bloqueo por un rato (tipo Kaspersky) sin pasar por el panel - lo pide un
    administrador (o se lo comparte el propio panel) y lo canjea el tray del
    agente. Mismo patron que AgentUninstallCode, tabla separada porque el
    proposito y el ciclo de vida son distintos (vigencia mucho mas corta acá,
    y esto SI puede pedirse repetidas veces por dia)."""
    __tablename__ = "agent_pause_codes"
    id          = Column(String, primary_key=True, default=gen_uuid)
    agent_id    = Column(String, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    code        = Column(String, nullable=False, index=True)
    expires_at  = Column(DateTime, nullable=False)
    used_at     = Column(DateTime, nullable=True)
    attempts    = Column(Integer, default=0)
    invalidated = Column(Boolean, default=False)
    created_by  = Column(String, nullable=True)
    created_at  = Column(DateTime, server_default=func.now())
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
    process_count   = Column(Integer, nullable=True)
    disk_read_mb_s  = Column(Float, nullable=True)
    disk_write_mb_s = Column(Float, nullable=True)
    net_down_mbps   = Column(Float, nullable=True)
    net_up_mbps     = Column(Float, nullable=True)
    agent           = relationship("Agent", back_populates="metrics")

class Disk(Base):
    """Una PARTICION/unidad logica (ej. C:, D:, o / en Linux). Varias
    particiones pueden pertenecer al mismo disco fisico (ver disk_index,
    que las agrupa - PhysicalDisk.disk_index es la fuente de verdad del
    tamano REAL de ese disco, esta tabla es solo el detalle por particion)."""
    __tablename__ = "disks"
    id              = Column(Integer, primary_key=True, autoincrement=True)
    agent_id        = Column(String, ForeignKey("agents.id"), nullable=False)
    device          = Column(String)
    mountpoint      = Column(String)
    total_gb        = Column(Float)
    used_gb         = Column(Float)
    percent         = Column(Float)
    disk_index      = Column(Integer, nullable=True)  # a que disco fisico pertenece (ver PhysicalDisk)
    updated_at      = Column(DateTime, server_default=func.now(), onupdate=func.now())
    agent           = relationship("Agent", back_populates="disks")

class PhysicalDisk(Base):
    """Un disco fisico real (ej. el SSD/NVMe/HDD como hardware, no una
    particion). total_gb viene de una consulta de hardware (Get-Disk en
    Windows, /sys/block/*/size en Linux) - la capacidad real del disco, no
    la suma de sus particiones (que puede no cubrir el 100%: espacio sin
    particionar, particiones no montadas, etc.). used_gb es la suma del uso
    de sus particiones (no hay forma de medir "uso" a nivel de disco crudo
    sin pasar por el sistema de archivos)."""
    __tablename__ = "physical_disks"
    id              = Column(Integer, primary_key=True, autoincrement=True)
    agent_id        = Column(String, ForeignKey("agents.id"), nullable=False)
    disk_index      = Column(Integer)
    total_gb        = Column(Float)
    used_gb         = Column(Float)
    percent         = Column(Float)
    partitions      = Column(Integer)  # cuantas particiones tiene
    media_type      = Column(String, nullable=True)  # "NVMe SSD"/"SSD"/"HDD"/None si no se pudo determinar
    model           = Column(String, nullable=True)  # ej. "Samsung SSD 980 500GB" (Win32_DiskDrive.Model / lsblk MODEL)
    interface       = Column(String, nullable=True)  # ej. "PCIe Gen3 x4"/"SATA"/"USB"/None si no se pudo determinar
    updated_at      = Column(DateTime, server_default=func.now(), onupdate=func.now())
    agent           = relationship("Agent", back_populates="physical_disks")

class Event(Base):
    __tablename__ = "events"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    # Nullable: la mayoria de eventos son de UN equipo puntual, pero una
    # excepcion de bloqueo puede aplicarse a nivel de area (sede_id) o global
    # (ninguno de los dos) - ahi no hay un agente especifico que referenciar.
    agent_id    = Column(String, ForeignKey("agents.id"), nullable=True, index=True)
    sede_id     = Column(String, ForeignKey("sedes.id"), nullable=True, index=True)
    # Idem para eventos del inventario general (activos): un activo no es
    # un Agent, asi que necesita su propia columna en vez de reusar agent_id.
    asset_id    = Column(String, ForeignKey("assets.id"), nullable=True, index=True)
    timestamp   = Column(DateTime, server_default=func.now(), index=True)
    type        = Column(String)
    detail      = Column(String)
    reason      = Column(String, nullable=True)
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

# ── Inventario general (activos NO monitoreados: monitores, cables, celulares,
# líneas telefónicas, etc.) - distinto de Agent, que es solo para equipos con
# el agente de SmartMonitor instalado reportando métricas en vivo. ─────────
class AssetType(Base):
    """Categoria configurable (Monitor, Cable VGA, Celular, Línea telefónica...).
    'kind' decide el comportamiento: 'serialized' = una fila por unidad
    (como Agent), 'stock' = una fila por modelo con conteo de cantidad."""
    __tablename__ = "asset_types"
    id           = Column(String, primary_key=True, default=gen_uuid)
    name         = Column(String, unique=True, nullable=False)
    icon         = Column(String, default="other")
    kind         = Column(String, default="serialized")  # "serialized" | "stock"
    # extra_fields: [{"key":"imei","label":"IMEI","type":"text"}] o
    # [{"key":"operador","label":"Operador","type":"select","options":["Claro","Movistar"]}]
    # - "type" ausente se trata como "text" (compatibilidad con categorias viejas).
    extra_fields = Column(JSON, default=list)
    # Si esta seteado, un activo de este tipo solo puede "Vincular con" activos
    # de ESE otro tipo (ej. Celular -> Linea telefonica) - la relacion se trata
    # como bidireccional al filtrar (ver _linkable_type_ids en el router), no
    # hace falta setearlo en ambos tipos.
    linkable_type_id = Column(String, ForeignKey("asset_types.id"), nullable=True)
    created_at   = Column(DateTime, server_default=func.now())

class Asset(Base):
    __tablename__ = "assets"
    id             = Column(String, primary_key=True, default=gen_uuid)
    type_id        = Column(String, ForeignKey("asset_types.id"), nullable=False, index=True)
    name           = Column(String, nullable=False)  # "Laptop Dell Latitude 5420" o, en stock, el modelo: "Cable VGA 1.5m"
    code           = Column(String, nullable=True, index=True)  # codigo interno / serie - solo tiene sentido en 'serialized'
    status         = Column(String, default="nuevo")  # nuevo | almacen | asignado | dañado | baja
    sede_id        = Column(String, ForeignKey("sedes.id"), nullable=True, index=True)
    # Asignacion vigente (denormalizado, igual que Agent con assigned_user) -
    # solo aplica a 'serialized'; el detalle historico vive en AssetAssignmentLog.
    assigned_user  = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    assigned_at    = Column(Date, nullable=True)
    purchase_date  = Column(Date, nullable=True)
    invoice_number = Column(String, nullable=True)
    notes          = Column(Text, nullable=True)
    extra_data     = Column(JSON, default=dict)  # valores de los extra_fields del tipo (ej. {"imei": "..."})
    linked_asset_id = Column(String, ForeignKey("assets.id"), nullable=True)  # ej. celular <-> linea telefonica
    # Solo 'stock': cantidad total comprada y cuanta esta actualmente asignada
    # (disponible = stock_total - stock_assigned, se calcula, no se guarda).
    stock_total    = Column(Integer, nullable=True)
    stock_assigned = Column(Integer, default=0)
    created_at     = Column(DateTime, server_default=func.now())
    updated_at     = Column(DateTime, server_default=func.now(), onupdate=func.now())
    asset_type     = relationship("AssetType")
    sede           = relationship("Sede")
    linked_asset   = relationship("Asset", remote_side=[id])

class AssetAssignmentLog(Base):
    """Historial de asignaciones/devoluciones de un activo - mismo patron que
    AssignmentLog (Agent), con 'quantity' de mas para los activos de stock
    (asignar/devolver N unidades a la vez, no solo 1)."""
    __tablename__ = "asset_assignment_log"
    id               = Column(Integer, primary_key=True, autoincrement=True)
    asset_id         = Column(String, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    assigned_to      = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assigned_to_name = Column(String, nullable=True)
    quantity         = Column(Integer, default=1)
    returned_quantity = Column(Integer, default=0)  # permite devoluciones parciales en items de stock (ej. asigno 5, devuelve 2, quedan 3)
    assigned_at      = Column(Date, nullable=True)
    delivery_notes   = Column(Text, nullable=True)
    returned_at      = Column(Date, nullable=True)
    return_notes     = Column(Text, nullable=True)
    changed_by       = Column(String, nullable=True)
    created_at       = Column(DateTime, server_default=func.now())
    asset            = relationship("Asset")

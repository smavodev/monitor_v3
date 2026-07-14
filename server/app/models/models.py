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
    hostname        = Column(String, unique=True, nullable=False, index=True)
    ip              = Column(String, nullable=True, index=True)
    display_name    = Column(String)
    display_name_manual = Column(Boolean, default=False)
    sede_id         = Column(String, ForeignKey("sedes.id"), nullable=True)
    assigned_user   = Column(String, ForeignKey("users.id"), nullable=True)
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

# ── Tag system ─────────────────────────────────────────────────────────────────
class Tag(Base):
    __tablename__ = "tags"
    id          = Column(String, primary_key=True, default=gen_uuid)
    name        = Column(String, nullable=False, unique=True)
    color       = Column(String, default="#3b82f6")
    description = Column(String, nullable=True)
    created_at  = Column(DateTime, server_default=func.now())
    monitors    = relationship("MonitorTag", back_populates="tag", cascade="all, delete-orphan")

class MonitorTag(Base):
    __tablename__ = "monitor_tags"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    service_id  = Column(String, ForeignKey("service_checks.id", ondelete="CASCADE"), nullable=False, index=True)
    tag_id      = Column(String, ForeignKey("tags.id", ondelete="CASCADE"), nullable=False, index=True)
    service     = relationship("ServiceCheck", back_populates="tags")
    tag         = relationship("Tag", back_populates="monitors")
    __table_args__ = (UniqueConstraint("service_id", "tag_id"),)

# ── Notification Channels ──────────────────────────────────────────────────────
class NotificationChannel(Base):
    __tablename__ = "notification_channels"
    id          = Column(String, primary_key=True, default=gen_uuid)
    name        = Column(String, nullable=False)
    type        = Column(String, nullable=False)  # telegram|email|slack|discord|webhook|teams|pagerduty|pushover|gotify|ntfy|matrix|signal|line|opsgenie|zulip|rocketchat|mattermost|apprise
    config_json = Column(Text, nullable=False, default="{}")
    is_default  = Column(Boolean, default=False)
    active      = Column(Boolean, default=True)
    created_at  = Column(DateTime, server_default=func.now())
    monitor_links = relationship("MonitorNotification", back_populates="channel", cascade="all, delete-orphan")

class MonitorNotification(Base):
    __tablename__ = "monitor_notifications"
    id              = Column(Integer, primary_key=True, autoincrement=True)
    service_id      = Column(String, ForeignKey("service_checks.id", ondelete="CASCADE"), nullable=False, index=True)
    notification_id = Column(String, ForeignKey("notification_channels.id", ondelete="CASCADE"), nullable=False)
    channel         = relationship("NotificationChannel", back_populates="monitor_links")
    __table_args__ = (UniqueConstraint("service_id", "notification_id"),)

# ── Proxy ──────────────────────────────────────────────────────────────────────
class Proxy(Base):
    __tablename__ = "proxies"
    id          = Column(String, primary_key=True, default=gen_uuid)
    protocol    = Column(String, default="http")  # http|https|socks5|socks4
    host        = Column(String, nullable=False)
    port        = Column(Integer, nullable=False)
    auth        = Column(Boolean, default=False)
    username    = Column(String, nullable=True)
    password    = Column(Text, nullable=True)
    active      = Column(Boolean, default=True)
    is_default  = Column(Boolean, default=False)
    created_at  = Column(DateTime, server_default=func.now())

# ── Maintenance ────────────────────────────────────────────────────────────────
class Maintenance(Base):
    __tablename__ = "maintenances"
    id              = Column(String, primary_key=True, default=gen_uuid)
    title           = Column(String, nullable=False)
    description     = Column(String, nullable=True)
    status          = Column(String, default="scheduled")  # scheduled|active|ended
    strategy        = Column(String, default="manual")     # manual|single|recurring-interval|recurring-weekday|recurring-day-of-month|cron
    active          = Column(Boolean, default=True)
    start_date      = Column(DateTime, nullable=True)
    end_date        = Column(DateTime, nullable=True)
    start_time      = Column(String, nullable=True)   # HH:MM
    end_time        = Column(String, nullable=True)
    timezone        = Column(String, default="UTC")
    weekdays        = Column(String, nullable=True)   # JSON array e.g. [1,3,5]
    days_of_month   = Column(String, nullable=True)   # JSON array e.g. [1,15]
    interval_days   = Column(Integer, nullable=True)
    cron_expr       = Column(String, nullable=True)
    created_at      = Column(DateTime, server_default=func.now())
    monitors        = relationship("MaintenanceMonitor", back_populates="maintenance", cascade="all, delete-orphan")

class MaintenanceMonitor(Base):
    __tablename__ = "maintenance_monitors"
    id              = Column(Integer, primary_key=True, autoincrement=True)
    maintenance_id  = Column(String, ForeignKey("maintenances.id", ondelete="CASCADE"), nullable=False, index=True)
    service_id      = Column(String, ForeignKey("service_checks.id", ondelete="CASCADE"), nullable=False)
    maintenance     = relationship("Maintenance", back_populates="monitors")

# ── Status Page ────────────────────────────────────────────────────────────────
class StatusPage(Base):
    __tablename__ = "status_pages"
    id              = Column(String, primary_key=True, default=gen_uuid)
    slug            = Column(String, unique=True, nullable=False)
    title           = Column(String, nullable=False)
    description     = Column(Text, nullable=True)
    icon            = Column(String, nullable=True)
    theme           = Column(String, default="dark")
    published       = Column(Boolean, default=True)
    show_tags       = Column(Boolean, default=False)
    custom_css      = Column(Text, nullable=True)
    footer_text     = Column(String, nullable=True)
    created_at      = Column(DateTime, server_default=func.now())
    groups          = relationship("StatusPageGroup", back_populates="status_page", cascade="all, delete-orphan", order_by="StatusPageGroup.order")

class StatusPageGroup(Base):
    __tablename__ = "status_page_groups"
    id              = Column(String, primary_key=True, default=gen_uuid)
    status_page_id  = Column(String, ForeignKey("status_pages.id", ondelete="CASCADE"), nullable=False, index=True)
    name            = Column(String, nullable=False)
    order           = Column(Integer, default=0)
    status_page     = relationship("StatusPage", back_populates="groups")
    monitors        = relationship("StatusPageMonitor", back_populates="group", cascade="all, delete-orphan", order_by="StatusPageMonitor.order")

class StatusPageMonitor(Base):
    __tablename__ = "status_page_monitors"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    group_id    = Column(String, ForeignKey("status_page_groups.id", ondelete="CASCADE"), nullable=False, index=True)
    service_id  = Column(String, ForeignKey("service_checks.id", ondelete="CASCADE"), nullable=False)
    order       = Column(Integer, default=0)
    group       = relationship("StatusPageGroup", back_populates="monitors")

# ── Service Check (Monitor) ────────────────────────────────────────────────────
class ServiceCheck(Base):
    __tablename__ = "service_checks"
    id                   = Column(String, primary_key=True, default=gen_uuid)
    name                 = Column(String, nullable=False)
    # Types: http|keyword|json-query|tcp|ping|dns|push|websocket-upgrade|smtp|
    #        mysql|postgres|redis|mongodb|grpc-keyword|docker|group|manual|
    #        mqtt|kafka-producer|rabbitmq|steam|gamedig|snmp|radius|tailscale-ping
    type                 = Column(String, default="http")
    target               = Column(String, nullable=True)   # URL or main target
    hostname             = Column(String, nullable=True)   # Separate hostname for TCP/DNS/SMTP etc.
    port                 = Column(Integer, nullable=True)
    interval_sec         = Column(Integer, default=60)
    timeout_sec          = Column(Integer, default=10)
    max_retries          = Column(Integer, default=0)
    consecutive_failures = Column(Integer, default=0)
    resend_interval      = Column(Integer, default=0)
    description          = Column(Text, nullable=True)
    active               = Column(Boolean, default=True)
    parent_id            = Column(String, ForeignKey("service_checks.id"), nullable=True)
    group_order          = Column(Integer, default=0)

    # HTTP / Keyword / JSON Query
    keyword              = Column(String, nullable=True)
    invert_keyword       = Column(Boolean, default=False)
    accepted_statuscodes = Column(String, default="200-299")
    method               = Column(String, default="GET")
    headers_json         = Column(Text, nullable=True)
    body                 = Column(Text, nullable=True)
    body_encoding        = Column(String, default="json")   # json|form|xml
    max_redirects        = Column(Integer, default=10)
    ignore_tls           = Column(Boolean, default=True)
    upside_down          = Column(Boolean, default=False)
    cache_bust           = Column(Boolean, default=False)
    ip_family            = Column(String, nullable=True)    # null|ipv4|ipv6
    save_response        = Column(Boolean, default=False)
    save_error_response  = Column(Boolean, default=True)
    last_response        = Column(Text, nullable=True)

    # Authentication
    auth_method          = Column(String, nullable=True)   # null|basic|bearer|oauth2-cc|ntlm|mtls
    basic_auth_user      = Column(String, nullable=True)
    basic_auth_pass      = Column(Text, nullable=True)
    bearer_token         = Column(Text, nullable=True)
    oauth_token_url      = Column(String, nullable=True)
    oauth_client_id      = Column(String, nullable=True)
    oauth_client_secret  = Column(Text, nullable=True)
    oauth_scopes         = Column(String, nullable=True)
    oauth_audience       = Column(String, nullable=True)
    oauth_auth_method    = Column(String, default="client_secret_basic")
    auth_domain          = Column(String, nullable=True)   # NTLM
    auth_workstation     = Column(String, nullable=True)   # NTLM
    tls_cert             = Column(Text, nullable=True)     # mTLS
    tls_key              = Column(Text, nullable=True)     # mTLS
    tls_ca               = Column(Text, nullable=True)     # mTLS

    # Certificate / Domain expiry
    expiry_notification        = Column(Boolean, default=False)
    domain_expiry_notification = Column(Boolean, default=False)
    cert_expiry                = Column(DateTime, nullable=True)   # stored when TLS check runs

    # JSON Query
    json_path            = Column(String, nullable=True)
    json_path_operator   = Column(String, nullable=True)   # ==|!=|>|>=|<|<=|contains
    expected_value       = Column(String, nullable=True)

    # DNS
    dns_resolve_type     = Column(String, default="A")
    dns_resolve_server   = Column(String, nullable=True)

    # Push (passive)
    push_token           = Column(String, nullable=True, unique=True)
    last_push            = Column(DateTime, nullable=True)

    # WebSocket
    ws_subprotocol       = Column(String, nullable=True)

    # Ping
    ping_count           = Column(Integer, default=1)
    ping_numeric         = Column(Boolean, default=False)

    # SMTP
    smtp_security        = Column(String, nullable=True)   # secure|nostarttls|starttls

    # Database
    db_connection_string = Column(Text, nullable=True)
    db_query             = Column(Text, nullable=True)

    # gRPC
    grpc_url             = Column(String, nullable=True)
    grpc_service_name    = Column(String, nullable=True)
    grpc_method          = Column(String, nullable=True)
    grpc_enable_tls      = Column(Boolean, default=False)
    grpc_body            = Column(Text, nullable=True)
    grpc_protobuf        = Column(Text, nullable=True)

    # Docker
    docker_container     = Column(String, nullable=True)
    docker_host          = Column(String, default="unix:///var/run/docker.sock")

    # MQTT
    mqtt_username        = Column(String, nullable=True)
    mqtt_password        = Column(Text, nullable=True)
    mqtt_topic           = Column(String, nullable=True)
    mqtt_check_type      = Column(String, default="keyword")  # keyword|json-query
    mqtt_success_msg     = Column(String, nullable=True)

    # Kafka
    kafka_brokers        = Column(Text, nullable=True)    # JSON array
    kafka_topic          = Column(String, nullable=True)
    kafka_message        = Column(Text, nullable=True)
    kafka_ssl            = Column(Boolean, default=False)
    kafka_sasl_mechanism = Column(String, default="None")
    kafka_sasl_username  = Column(String, nullable=True)
    kafka_sasl_password  = Column(Text, nullable=True)

    # Proxy
    proxy_id             = Column(String, ForeignKey("proxies.id"), nullable=True)

    # Status
    last_check           = Column(DateTime, nullable=True)
    last_status          = Column(String, default="unknown")  # up|down|pending|maintenance|unknown
    last_latency_ms      = Column(Float, nullable=True)
    created_at           = Column(DateTime, server_default=func.now())

    # Relationships
    history       = relationship("ServiceCheckHistory", back_populates="service",
                                 cascade="all, delete-orphan", passive_deletes=True)
    tags          = relationship("MonitorTag", back_populates="service",
                                 cascade="all, delete-orphan")
    notifications = relationship("MonitorNotification", back_populates=None,
                                 cascade="all, delete-orphan",
                                 foreign_keys="MonitorNotification.service_id")
    children      = relationship("ServiceCheck", backref=__import__("sqlalchemy.orm", fromlist=["backref"]).backref("parent", remote_side="ServiceCheck.id"))

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

class ServiceCheckHistory(Base):
    __tablename__ = "service_check_history"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    service_id = Column(String, ForeignKey("service_checks.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    timestamp  = Column(DateTime, server_default=func.now(), index=True)
    status     = Column(String)
    latency_ms = Column(Float, nullable=True)
    msg        = Column(String, nullable=True)
    service    = relationship("ServiceCheck", back_populates="history")

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi import Response
from pathlib import Path
import os, threading, time as _time

from core.db import engine, get_db, hash_password, Session as DBSession
from models.models import Base, User
from routers import auth, agents, sedes, config, alerts, discovery, reports
from routers import blocked_sites, block_schedules, block_reports, network_gate, block_attempts
from routers import roles, headscale, assets, agent_uninstall_codes
from dns_blocker import start_dns_blocker
from sqlalchemy.orm import Session

app = FastAPI(title="SmartMonitor v3", docs_url=None, redoc_url=None)

# ── Init DB ────────────────────────────────────────────────────────────────
# SMARTMONITOR_ROLE=web-only: usado por el proceso uvicorn secundario (panel
# admin por HTTPS en :8443 cuando hay certificado real, ver entrypoint.sh) —
# ese proceso solo debe SERVIR la app; las migraciones, el seed de datos, el
# resolver DNS (puertos 53/80/443) y el scheduler ya los corre el proceso
# principal (:8000). Correrlos por duplicado chocaría bind de puertos y
# podría duplicar inserts de seed en una condición de carrera.
_WEB_ONLY = os.getenv("SMARTMONITOR_ROLE") == "web-only"


@app.on_event("startup")
def startup():
    if _WEB_ONLY:
        return
    Base.metadata.create_all(bind=engine)
    from sqlalchemy import text
    migrations = [
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS ip VARCHAR",
        "ALTER TABLE blocked_sites ADD COLUMN IF NOT EXISTS category VARCHAR",
        "ALTER TABLE blocked_sites ADD COLUMN IF NOT EXISTS section VARCHAR",
        "ALTER TABLE block_categories ADD COLUMN IF NOT EXISTS group_key VARCHAR DEFAULT 'parental'",
        "ALTER TABLE block_schedules ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP",
        "ALTER TABLE blocked_sites ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP",
        "ALTER TABLE blocked_sites ADD COLUMN IF NOT EXISTS sede_id VARCHAR",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP DEFAULT NOW()",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS role_id VARCHAR",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS has_access BOOLEAN DEFAULT TRUE",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS device_type VARCHAR",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS device_type_manual BOOLEAN DEFAULT FALSE",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS display_name_manual BOOLEAN DEFAULT FALSE",
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_agents_serial_number ON agents (serial_number)",
        # El hostname de Windows puede repetirse entre equipos distintos
        # (clonación, error humano); la identidad única real es
        # serial_number (índice de arriba). Se quita el UNIQUE de hostname
        # para poder registrar ambos equipos como filas separadas.
        "DROP INDEX IF EXISTS ix_agents_hostname",
        "CREATE INDEX IF NOT EXISTS ix_agents_hostname ON agents (hostname)",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS tailnet_ip VARCHAR",
        "CREATE INDEX IF NOT EXISTS ix_agents_tailnet_ip ON agents (tailnet_ip)",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS assigned_at DATE",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS returned_at DATE",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS assignment_notes TEXT",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS return_notes TEXT",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS review_status VARCHAR",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS purchase_date DATE",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS invoice_number VARCHAR",
        # Antes no tenía ON DELETE SET NULL: borrar un usuario que seguía
        # asignado a algún equipo tumbaba con 500 (ForeignKeyViolation) en vez
        # de simplemente desasignarlo.
        "ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_assigned_user_fkey",
        "ALTER TABLE agents ADD CONSTRAINT agents_assigned_user_fkey FOREIGN KEY (assigned_user) REFERENCES users(id) ON DELETE SET NULL",
        # Red de seguridad: create_all ya debería crear esta tabla, pero si no
        # existiera (código viejo) la creamos para no abortar la migración.
        """CREATE TABLE IF NOT EXISTS agent_change_log (
            id SERIAL PRIMARY KEY,
            agent_id VARCHAR REFERENCES agents(id) ON DELETE CASCADE,
            field VARCHAR NOT NULL,
            old_value TEXT,
            new_value TEXT,
            note TEXT,
            change_date DATE,
            changed_by VARCHAR,
            changed_at TIMESTAMP DEFAULT NOW()
        )""",
        "ALTER TABLE agent_change_log ADD COLUMN IF NOT EXISTS note TEXT",
        "ALTER TABLE agent_change_log ADD COLUMN IF NOT EXISTS change_date DATE",
        # Historial de asignaciones (log de entregas/devoluciones)
        """CREATE TABLE IF NOT EXISTS assignment_log (
            id SERIAL PRIMARY KEY,
            agent_id VARCHAR REFERENCES agents(id) ON DELETE CASCADE,
            assigned_to VARCHAR REFERENCES users(id) ON DELETE SET NULL,
            assigned_to_name VARCHAR,
            assigned_at DATE,
            delivery_notes TEXT,
            returned_at DATE,
            return_notes TEXT,
            changed_by VARCHAR,
            created_at TIMESTAMP DEFAULT NOW()
        )""",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS screen_size_in FLOAT",
        "ALTER TABLE disks ADD COLUMN IF NOT EXISTS disk_index INTEGER",
        """CREATE TABLE IF NOT EXISTS physical_disks (
            id SERIAL PRIMARY KEY,
            agent_id VARCHAR NOT NULL REFERENCES agents(id),
            disk_index INTEGER,
            total_gb FLOAT,
            used_gb FLOAT,
            percent FLOAT,
            partitions INTEGER,
            updated_at TIMESTAMP DEFAULT NOW()
        )""",
        # events.agent_id ya no es obligatorio (excepciones a nivel de area o
        # globales no tienen un agente puntual) + nueva columna sede_id.
        "ALTER TABLE events ALTER COLUMN agent_id DROP NOT NULL",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS sede_id VARCHAR",
        "CREATE INDEX IF NOT EXISTS ix_events_sede_id ON events (sede_id)",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS reason VARCHAR",
        """CREATE TABLE IF NOT EXISTS login_attempts (
            id SERIAL PRIMARY KEY,
            email VARCHAR,
            user_id VARCHAR REFERENCES users(id) ON DELETE SET NULL,
            success BOOLEAN DEFAULT FALSE,
            reason VARCHAR,
            ip_address VARCHAR,
            timestamp TIMESTAMP DEFAULT NOW()
        )""",
        "CREATE INDEX IF NOT EXISTS ix_login_attempts_email ON login_attempts (email)",
        "CREATE INDEX IF NOT EXISTS ix_login_attempts_user_id ON login_attempts (user_id)",
        "CREATE INDEX IF NOT EXISTS ix_login_attempts_success ON login_attempts (success)",
        "CREATE INDEX IF NOT EXISTS ix_login_attempts_timestamp ON login_attempts (timestamp)",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_default_admin BOOLEAN DEFAULT FALSE",
        # Inventario general (activos no monitoreados). create_all ya deberia
        # crear estas 3 tablas nuevas, pero se dejan explicitas como red de
        # seguridad (mismo criterio que agent_change_log) - deben ir ANTES de
        # la columna events.asset_id, que las referencia.
        """CREATE TABLE IF NOT EXISTS asset_types (
            id VARCHAR PRIMARY KEY,
            name VARCHAR UNIQUE NOT NULL,
            icon VARCHAR,
            kind VARCHAR,
            extra_fields JSON,
            created_at TIMESTAMP DEFAULT NOW()
        )""",
        "ALTER TABLE asset_types ADD COLUMN IF NOT EXISTS linkable_type_id VARCHAR REFERENCES asset_types(id)",
        """CREATE TABLE IF NOT EXISTS assets (
            id VARCHAR PRIMARY KEY,
            type_id VARCHAR NOT NULL REFERENCES asset_types(id),
            name VARCHAR NOT NULL,
            code VARCHAR,
            status VARCHAR,
            sede_id VARCHAR REFERENCES sedes(id),
            assigned_user VARCHAR REFERENCES users(id) ON DELETE SET NULL,
            assigned_at DATE,
            purchase_date DATE,
            invoice_number VARCHAR,
            notes TEXT,
            extra_data JSON,
            linked_asset_id VARCHAR REFERENCES assets(id),
            stock_total INTEGER,
            stock_assigned INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        )""",
        "CREATE INDEX IF NOT EXISTS ix_assets_type_id ON assets (type_id)",
        "CREATE INDEX IF NOT EXISTS ix_assets_sede_id ON assets (sede_id)",
        "CREATE INDEX IF NOT EXISTS ix_assets_assigned_user ON assets (assigned_user)",
        "CREATE INDEX IF NOT EXISTS ix_assets_code ON assets (code)",
        """CREATE TABLE IF NOT EXISTS asset_assignment_log (
            id SERIAL PRIMARY KEY,
            asset_id VARCHAR NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            assigned_to VARCHAR REFERENCES users(id) ON DELETE SET NULL,
            assigned_to_name VARCHAR,
            quantity INTEGER DEFAULT 1,
            returned_quantity INTEGER DEFAULT 0,
            assigned_at DATE,
            delivery_notes TEXT,
            returned_at DATE,
            return_notes TEXT,
            changed_by VARCHAR,
            created_at TIMESTAMP DEFAULT NOW()
        )""",
        "CREATE INDEX IF NOT EXISTS ix_asset_assignment_log_asset_id ON asset_assignment_log (asset_id)",
        "ALTER TABLE events ADD COLUMN IF NOT EXISTS asset_id VARCHAR",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS paused_until TIMESTAMP",
        "CREATE INDEX IF NOT EXISTS ix_events_asset_id ON events (asset_id)",
        """CREATE TABLE IF NOT EXISTS agent_uninstall_codes (
            id VARCHAR PRIMARY KEY,
            agent_id VARCHAR NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
            code VARCHAR NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP,
            attempts INTEGER DEFAULT 0,
            invalidated BOOLEAN DEFAULT FALSE,
            created_by VARCHAR,
            created_at TIMESTAMP DEFAULT NOW()
        )""",
        "CREATE INDEX IF NOT EXISTS ix_agent_uninstall_codes_agent_id ON agent_uninstall_codes (agent_id)",
        "CREATE INDEX IF NOT EXISTS ix_agent_uninstall_codes_code ON agent_uninstall_codes (code)",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS pause_until_reboot BOOLEAN DEFAULT FALSE",
        """CREATE TABLE IF NOT EXISTS agent_pause_codes (
            id VARCHAR PRIMARY KEY,
            agent_id VARCHAR NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
            code VARCHAR NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP,
            attempts INTEGER DEFAULT 0,
            invalidated BOOLEAN DEFAULT FALSE,
            created_by VARCHAR,
            created_at TIMESTAMP DEFAULT NOW()
        )""",
        "CREATE INDEX IF NOT EXISTS ix_agent_pause_codes_agent_id ON agent_pause_codes (agent_id)",
        "CREATE INDEX IF NOT EXISTS ix_agent_pause_codes_code ON agent_pause_codes (code)",
        """CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id VARCHAR PRIMARY KEY,
            user_id VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token VARCHAR NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT NOW()
        )""",
        "CREATE INDEX IF NOT EXISTS ix_password_reset_tokens_user_id ON password_reset_tokens (user_id)",
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_password_reset_tokens_token ON password_reset_tokens (token)",
        "ALTER TABLE metrics ADD COLUMN IF NOT EXISTS process_count INTEGER",
        "ALTER TABLE metrics ADD COLUMN IF NOT EXISTS disk_read_mb_s FLOAT",
        "ALTER TABLE metrics ADD COLUMN IF NOT EXISTS disk_write_mb_s FLOAT",
        "ALTER TABLE metrics ADD COLUMN IF NOT EXISTS net_down_mbps FLOAT",
        "ALTER TABLE metrics ADD COLUMN IF NOT EXISTS net_up_mbps FLOAT",
        "ALTER TABLE physical_disks ADD COLUMN IF NOT EXISTS media_type VARCHAR",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS ram_max_capacity_gb INTEGER",
        "ALTER TABLE physical_disks ADD COLUMN IF NOT EXISTS model VARCHAR",
        "ALTER TABLE physical_disks ADD COLUMN IF NOT EXISTS interface VARCHAR",
    ]
    conn = engine.connect()
    try:
        for stmt in migrations:
            try:
                conn.execute(text(stmt))
            except Exception as e:
                print(f"[migración] advertencia en: {stmt[:60]}... -> {e}")
        conn.commit()
    finally:
        conn.close()
    db: Session = next(get_db())
    try:
        role_ids = roles.seed_default_roles(db)

        # Red de seguridad para nunca quedar bloqueados fuera del panel - pero
        # SOLO si de verdad no queda NINGUN admin activo. Antes esto revivia
        # el "Administrador" de fabrica en cada reinicio del contenedor con
        # solo que faltara ESE email puntual, aunque el usuario ya tuviera
        # sus propios admins configurados - beneficio, cada deploy le hacia
        # "reaparecer" un usuario que habia eliminado a proposito.
        admin_email = os.getenv("ADMIN_EMAIL", "admin@smartmonitor.local")
        admin_pass  = os.getenv("ADMIN_PASSWORD", "Admin2024!")
        has_active_admin = db.query(User).filter(
            User.role_id == role_ids["admin"],
            User.active == True,
            User.has_access.isnot(False),
        ).first()
        existing_default_admin = db.query(User).filter(User.email == admin_email).first()
        if not has_active_admin and not existing_default_admin:
            db.add(User(
                name="Administrador",
                email=admin_email,
                password=hash_password(admin_pass),
                role="admin",
                role_id=role_ids["admin"],
                is_default_admin=True,
            ))
            db.commit()
            print(f"[SmartMonitor] Admin creado: {admin_email}")
        elif existing_default_admin and not existing_default_admin.is_default_admin:
            # Backfill: la fila ya existia de antes de que existiera esta
            # columna - se marca ahora para que quede protegida contra
            # eliminacion desde el panel (solo desactivar/cambiar contraseña).
            existing_default_admin.is_default_admin = True
            db.commit()

        # Migrar usuarios viejos que todavía no tienen role_id (creados antes
        # del sistema de roles): se mapean por su antiguo campo role de texto.
        for u in db.query(User).filter(User.role_id.is_(None)).all():
            u.role_id = role_ids["admin"] if u.role == "admin" else role_ids["technician"]
        db.commit()

        blocked_sites.seed_default_categories(db)
        block_schedules.seed_default_schedule(db)
        network_gate.seed_default(db)
        block_attempts.seed_default_config(db)
        auth.seed_default_password_policy(db)
        assets.seed_default_asset_types(db)
        assets.migrate_device_types_into_asset_types(db)
    finally:
        db.close()

    # Resolver DNS central con filtrado (Fase 1) + pagina de bloqueo (Fase 2)
    try:
        start_dns_blocker()
    except Exception as e:
        print(f"[DNSBlocker] No se inicio el bloqueo DNS central: {e}")

    threading.Thread(target=_background_scheduler, daemon=True).start()

# ── Chequeo periódico de equipos offline + purga de intentos vencidos ───────
_last_attempt_purge = 0.0

def _background_scheduler():
    global _last_attempt_purge
    _time.sleep(15)  # esperar inicio completo
    while True:
        try:
            db = DBSession()
            if _time.time() - _last_attempt_purge >= 3600:
                try:
                    block_attempts.purge_expired(db)
                except Exception as e:
                    print(f"[BlockAttemptPurge] {e}")
                _last_attempt_purge = _time.time()
            try:
                agents.check_offline(db)
            except Exception as e:
                print(f"[CheckOffline] {e}")
            # Excepciones de bloqueo vencidas (expires_at) - antes solo se
            # purgaban/registraban en Eventos cuando alguien abria la
            # pantalla de "Sitios bloqueados" (GET /api/blocked-sites), asi
            # que si nadie la abria el dia que vencia, el evento quedaba
            # "atrasado" hasta la proxima visita en vez de generarse el
            # mismo dia. Enganchado aca corre cada ~15s sin depender de que
            # alguien mire el panel.
            try:
                blocked_sites._purge_expired_sites(db)
            except Exception as e:
                print(f"[BlockedSitesExpiry] {e}")
            db.close()
        except Exception as e:
            print(f"[BackgroundScheduler] {e}")
        _time.sleep(15)

# ── Routers ────────────────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(roles.router)
app.include_router(agents.router)
app.include_router(sedes.router)
app.include_router(config.router)
app.include_router(alerts.router)
app.include_router(discovery.router)
app.include_router(reports.router)
app.include_router(blocked_sites.router)
app.include_router(block_schedules.router)
app.include_router(block_reports.router)
app.include_router(network_gate.router)
app.include_router(block_attempts.router)
app.include_router(headscale.router)
app.include_router(assets.router)
app.include_router(agent_uninstall_codes.router)

# ── Static files ───────────────────────────────────────────────────────────
static_path = Path("/app/static")
if static_path.exists():
    app.mount("/static", StaticFiles(directory="/app/static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def root():
    index = Path("/app/static/index.html")
    if index.exists():
        return HTMLResponse(index.read_text())
    return HTMLResponse("<h1>SmartMonitor v3</h1>")

@app.get("/smartmonitor-ca.crt")
async def download_ca_cert():
    """Mismo certificado que ya sirve dns_blocker.py por HTTP plano en el
    puerto 80 (ver tls_ca.ca_cert_pem) - esta copia va por HTTPS, detras de
    nginx, con el dominio real. Descargar un .crt por HTTP directo a una IP
    (sin dominio, sin cifrar) es un patron que la heuristica de varios
    antivirus (Kaspersky confirmado) marca como sitio malintencionado -
    los instaladores deberian preferir esta URL cuando el servidor
    configurado sea un dominio con HTTPS valido."""
    from tls_ca import ca_cert_pem
    return Response(
        content=ca_cert_pem(),
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": "attachment; filename=smartmonitor-ca.crt"},
    )

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pathlib import Path
import os, threading, time as _time

from core.db import engine, get_db, hash_password, Session as DBSession
from models.models import Base, User, ServiceCheck
from routers import auth, agents, sedes, config, alerts, services, discovery, reports
from routers import notifications, tags, status_pages, maintenance, proxies, blocked_sites, block_schedules, block_reports, network_gate, block_attempts
from routers import roles
from routers.services import run_check_and_save
from dns_blocker import start_dns_blocker
from sqlalchemy.orm import Session
from datetime import datetime

app = FastAPI(title="SmartMonitor v3", docs_url=None, redoc_url=None)

# ── Init DB ────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup():
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
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS device_type VARCHAR",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS device_type_manual BOOLEAN DEFAULT FALSE",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS display_name_manual BOOLEAN DEFAULT FALSE",
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_agents_serial_number ON agents (serial_number)",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS assigned_at DATE",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS returned_at DATE",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS assignment_notes TEXT",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS return_notes TEXT",
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

        admin_email = os.getenv("ADMIN_EMAIL", "admin@smartmonitor.local")
        admin_pass  = os.getenv("ADMIN_PASSWORD", "Admin2024!")
        if not db.query(User).filter(User.email == admin_email).first():
            db.add(User(
                name="Administrador",
                email=admin_email,
                password=hash_password(admin_pass),
                role="admin",
                role_id=role_ids["admin"],
            ))
            db.commit()
            print(f"[SmartMonitor] Admin creado: {admin_email}")

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
    finally:
        db.close()

    # Resolver DNS central con filtrado (Fase 1) + pagina de bloqueo (Fase 2)
    try:
        start_dns_blocker()
    except Exception as e:
        print(f"[DNSBlocker] No se inicio el bloqueo DNS central: {e}")

    threading.Thread(target=_service_scheduler, daemon=True).start()

# ── Service auto-scheduler ─────────────────────────────────────────────────
_last_attempt_purge = 0.0

def _service_scheduler():
    global _last_attempt_purge
    _time.sleep(15)  # esperar inicio completo
    while True:
        try:
            db = DBSession()
            now = datetime.utcnow()
            svcs = db.query(ServiceCheck).filter(ServiceCheck.active == True).all()
            for svc in svcs:
                elapsed = (now - svc.last_check).total_seconds() if svc.last_check else float("inf")
                if elapsed >= svc.interval_sec:
                    try:
                        run_check_and_save(db, svc)
                    except Exception as e:
                        print(f"[SvcCheck] {svc.name}: {e}")
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
            db.close()
        except Exception as e:
            print(f"[SvcScheduler] {e}")
        _time.sleep(15)

# ── Routers ────────────────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(roles.router)
app.include_router(agents.router)
app.include_router(sedes.router)
app.include_router(config.router)
app.include_router(alerts.router)
app.include_router(services.router)
app.include_router(discovery.router)
app.include_router(reports.router)
app.include_router(notifications.router)
app.include_router(tags.router)
app.include_router(status_pages.router)
app.include_router(maintenance.router)
app.include_router(proxies.router)
app.include_router(blocked_sites.router)
app.include_router(block_schedules.router)
app.include_router(block_reports.router)
app.include_router(network_gate.router)
app.include_router(block_attempts.router)

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

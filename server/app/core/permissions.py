from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session
from core.db import get_db, get_current_user

# ── Catálogo de secciones (una por cada área controlable de la app) ────────
SECTIONS = {
    "dashboard":            "Dashboard",
    "events":               "Eventos",
    "inventory":            "Inventario",
    "discovery":            "Descubrimiento",
    "areas":                "Áreas",
    "parental_categories":  "Control parental — Categorías",
    "parental_blocked":     "Control parental — Bloqueo de sitios",
    "parental_schedule":    "Control parental — Horario",
    "parental_attempts":    "Control parental — Intentos bloqueados",
    "alerts":               "Umbrales de alerta",
    "monitors":             "Monitores de servicio (uptime)",
    "notifications":        "Canales de notificación",
    "tags":                 "Etiquetas",
    "status_pages":         "Páginas de estado",
    "maintenance":          "Ventanas de mantenimiento",
    "proxies":              "Proxies",
    "users":                "Usuarios y roles",
    "settings":             "Configuración",
}

LEVELS = ["none", "view", "edit", "manage"]
LEVEL_ORDER = {"none": 0, "view": 1, "edit": 2, "manage": 3}


def get_permission_map(db: Session, user) -> dict:
    """{section: level} para el rol del usuario. Sin rol asignado = sin permisos."""
    from models.models import RolePermission
    if not getattr(user, "role_id", None):
        return {}
    rows = db.query(RolePermission).filter(RolePermission.role_id == user.role_id).all()
    return {r.section: r.level for r in rows}


def get_section_level(db: Session, user, section: str) -> str:
    from models.models import RolePermission
    if not getattr(user, "role_id", None):
        return "none"
    row = (
        db.query(RolePermission)
        .filter(RolePermission.role_id == user.role_id, RolePermission.section == section)
        .first()
    )
    return row.level if row else "none"


def has_permission(db: Session, user, section: str, min_level: str = "view") -> bool:
    return LEVEL_ORDER.get(get_section_level(db, user, section), 0) >= LEVEL_ORDER.get(min_level, 0)


def require_permission(section: str, min_level: str = "view"):
    """Dependencia FastAPI: exige que el usuario autenticado tenga al menos
    min_level en la sección dada, según los permisos de su rol."""
    def _dep(user=Depends(get_current_user), db: Session = Depends(get_db)):
        if not has_permission(db, user, section, min_level):
            raise HTTPException(403, "No tienes permiso para realizar esta acción")
        return user
    return _dep

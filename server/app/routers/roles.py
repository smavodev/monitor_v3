from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Dict, Optional

from core.db import get_db
from core.permissions import require_permission, SECTIONS, LEVELS
from models.models import Role, RolePermission, User

router = APIRouter(prefix="/api/roles", tags=["roles"])

# ── Permisos del rol "Admin" sembrado por defecto: control total en todo ───
DEFAULT_ADMIN_PERMISSIONS = {k: "manage" for k in SECTIONS}

# ── Permisos del rol "Técnico" sembrado por defecto: refleja el acceso que
# ya tenía cualquier usuario autenticado antes de este sistema de roles, para
# no romper nada al migrar (ver/editar donde ya podía, solo ver donde antes
# solo se podía ver, nada en Usuarios que antes era exclusivo de admin). ──
DEFAULT_TECHNICIAN_PERMISSIONS = {
    "dashboard": "edit", "events": "edit", "inventory": "edit", "discovery": "edit",
    "areas": "view",
    "parental_categories": "view", "parental_blocked": "view",
    "parental_schedule": "view", "parental_attempts": "view",
    "alerts": "edit", "monitors": "edit", "notifications": "edit", "tags": "edit",
    "status_pages": "edit", "maintenance": "edit", "proxies": "edit",
    "settings": "edit",
    "users": "none",
}


def seed_default_roles(db: Session) -> dict:
    """Crea (si no existen) los roles Admin, Técnico y Usuario, y devuelve sus
    ids ({'admin': id, 'technician': id, 'user': id}) para poder migrar
    usuarios viejos.

    "Usuario" (sin permisos en ninguna sección) es el rol pensado para
    cuentas que solo existen para asignarles equipos (ej. un empleado sin
    rol de TI) - nunca inician sesión de verdad. Antes no se sembraba acá:
    en producción alguien lo había creado a mano desde la pantalla de Roles,
    así que ya existía, pero una instalación nueva no lo tenía y el
    selector de rol al crear un usuario cambiaba por defecto a "Admin"
    (el primero por fecha de creación) si nadie lo tocaba - ver
    openNewUser()/_populateUserRolePicker() en el frontend, que ahora
    selecciona este rol por nombre en vez de depender del orden."""
    ids = {}
    admin = db.query(Role).filter(Role.name == "Admin").first()
    if not admin:
        admin = Role(name="Admin", is_admin_role=True)
        db.add(admin)
        db.commit()
        db.refresh(admin)
        for section, level in DEFAULT_ADMIN_PERMISSIONS.items():
            db.add(RolePermission(role_id=admin.id, section=section, level=level))
        db.commit()
    ids["admin"] = admin.id

    tech = db.query(Role).filter(Role.name == "Técnico").first()
    if not tech:
        tech = Role(name="Técnico", is_admin_role=False)
        db.add(tech)
        db.commit()
        db.refresh(tech)
        for section, level in DEFAULT_TECHNICIAN_PERMISSIONS.items():
            if level == "none":
                continue
            db.add(RolePermission(role_id=tech.id, section=section, level=level))
        db.commit()
    ids["technician"] = tech.id

    usuario = db.query(Role).filter(Role.name == "Usuario").first()
    if not usuario:
        usuario = Role(name="Usuario", is_admin_role=False)
        db.add(usuario)
        db.commit()
        db.refresh(usuario)
        # sin RolePermission - "none" en todas las secciones a propósito
    ids["user"] = usuario.id

    return ids


def _fmt_role(db: Session, role: Role) -> dict:
    perms = {p.section: p.level for p in db.query(RolePermission).filter(RolePermission.role_id == role.id).all()}
    full = {k: perms.get(k, "none") for k in SECTIONS}
    user_count = db.query(User).filter(User.role_id == role.id).count()
    return {
        "id": role.id, "name": role.name, "is_admin_role": bool(role.is_admin_role),
        "permissions": full, "user_count": user_count,
    }


def _validate_permissions(perms: Dict[str, str]):
    for section, level in perms.items():
        if section not in SECTIONS:
            raise HTTPException(400, f"Sección inválida: {section}")
        if level not in LEVELS:
            raise HTTPException(400, f"Nivel inválido: {level}")


def _set_permissions(db: Session, role_id: str, perms: Dict[str, str]):
    db.query(RolePermission).filter(RolePermission.role_id == role_id).delete()
    for section, level in perms.items():
        if level == "none":
            continue
        db.add(RolePermission(role_id=role_id, section=section, level=level))


@router.get("/sections")
def list_sections(user=Depends(require_permission("users", "view"))):
    return [{"key": k, "label": v} for k, v in SECTIONS.items()]


@router.get("")
def list_roles(user=Depends(require_permission("users", "view")), db: Session = Depends(get_db)):
    return [_fmt_role(db, r) for r in db.query(Role).order_by(Role.created_at).all()]


class RoleCreate(BaseModel):
    name: str
    permissions: Dict[str, str] = {}


class RoleUpdate(BaseModel):
    name: Optional[str] = None
    permissions: Optional[Dict[str, str]] = None


@router.post("")
def create_role(data: RoleCreate, user=Depends(require_permission("users", "manage")), db: Session = Depends(get_db)):
    name = data.name.strip()
    if not name:
        raise HTTPException(400, "El nombre del rol es obligatorio")
    if db.query(Role).filter(Role.name == name).first():
        raise HTTPException(400, "Ya existe un rol con ese nombre")
    _validate_permissions(data.permissions)
    role = Role(name=name, is_admin_role=False)
    db.add(role)
    db.commit()
    db.refresh(role)
    _set_permissions(db, role.id, data.permissions)
    db.commit()
    return _fmt_role(db, role)


@router.put("/{role_id}")
def update_role(role_id: str, data: RoleUpdate, user=Depends(require_permission("users", "manage")), db: Session = Depends(get_db)):
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(404, "Rol no encontrado")
    if data.name is not None:
        name = data.name.strip()
        if not name:
            raise HTTPException(400, "El nombre del rol es obligatorio")
        if db.query(Role).filter(Role.name == name, Role.id != role_id).first():
            raise HTTPException(400, "Ya existe un rol con ese nombre")
        role.name = name
    if data.permissions is not None:
        _validate_permissions(data.permissions)
        # El rol Admin siempre debe conservar control total sobre "Usuarios y
        # roles" — si no, alguien podría quitarles a todos los admins la
        # capacidad de arreglar el propio sistema de permisos.
        if role.is_admin_role and data.permissions.get("users", "manage") != "manage":
            raise HTTPException(400, "El rol Admin siempre debe conservar control total sobre 'Usuarios y roles'")
        _set_permissions(db, role.id, data.permissions)
    db.commit()
    return _fmt_role(db, role)


@router.delete("/{role_id}")
def delete_role(role_id: str, user=Depends(require_permission("users", "manage")), db: Session = Depends(get_db)):
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(404, "Rol no encontrado")
    if role.is_admin_role:
        raise HTTPException(400, "No puedes eliminar el rol Admin")
    in_use = db.query(User).filter(User.role_id == role_id).count()
    if in_use > 0:
        raise HTTPException(400, f"No puedes eliminar este rol: hay {in_use} usuario(s) con este rol asignado. Reasígnalos primero.")
    db.query(RolePermission).filter(RolePermission.role_id == role_id).delete()
    db.delete(role)
    db.commit()
    return {"ok": True}

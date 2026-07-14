import random
import string
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from core.db import get_db, verify_password, create_token, get_current_user, hash_password
from core.permissions import require_permission, get_permission_map, has_permission
from models.models import User, PasswordPolicy, PasswordHistory, Role

router = APIRouter(prefix="/api/auth", tags=["auth"])

POLICY_ID = "default"


# ── Política de contraseñas ─────────────────────────────────────────────────
def seed_default_password_policy(db: Session):
    if db.query(PasswordPolicy).filter(PasswordPolicy.id == POLICY_ID).first():
        return
    db.add(PasswordPolicy(id=POLICY_ID))
    db.commit()


def _get_policy(db: Session) -> PasswordPolicy:
    p = db.query(PasswordPolicy).filter(PasswordPolicy.id == POLICY_ID).first()
    if not p:
        p = PasswordPolicy(id=POLICY_ID)
        db.add(p)
        db.commit()
        db.refresh(p)
    return p


def _fmt_policy(p: PasswordPolicy) -> dict:
    return {
        "min_length": p.min_length,
        "require_uppercase": p.require_uppercase,
        "require_lowercase": p.require_lowercase,
        "require_number": p.require_number,
        "require_special": p.require_special,
        "expiration_enabled": p.expiration_enabled,
        "expire_days": p.expire_days,
        "prevent_reuse": p.prevent_reuse,
        "reuse_remember_count": p.reuse_remember_count,
    }


def _validate_password_policy(pw: str, policy: PasswordPolicy) -> str | None:
    """Devuelve un mensaje de error si pw no cumple la política, o None si es válida."""
    if len(pw) < policy.min_length:
        return f"La contraseña debe tener al menos {policy.min_length} caracteres"
    if policy.require_uppercase and not any(c.isupper() for c in pw):
        return "La contraseña debe incluir al menos una letra mayúscula"
    if policy.require_lowercase and not any(c.islower() for c in pw):
        return "La contraseña debe incluir al menos una letra minúscula"
    if policy.require_number and not any(c.isdigit() for c in pw):
        return "La contraseña debe incluir al menos un número"
    if policy.require_special and not any(not c.isalnum() for c in pw):
        return "La contraseña debe incluir al menos un carácter especial (ej. ! @ # $ % ^ &)"
    return None


def _check_password_reuse(db: Session, user_id: str, plain_pw: str, policy: PasswordPolicy) -> bool:
    history = (
        db.query(PasswordHistory)
        .filter(PasswordHistory.user_id == user_id)
        .order_by(PasswordHistory.created_at.desc())
        .limit(policy.reuse_remember_count)
        .all()
    )
    return any(verify_password(plain_pw, h.password) for h in history)


def _apply_password(db: Session, u: User, plain_pw: str, policy: PasswordPolicy, check_reuse: bool = True):
    """Valida la contraseña contra la política, la aplica, actualiza
    password_changed_at y registra el historial (recortado a lo que la
    política manda recordar). No toca must_change_password — eso lo decide
    cada endpoint según su propio flujo."""
    err = _validate_password_policy(plain_pw, policy)
    if err:
        raise HTTPException(400, err)
    if check_reuse and policy.prevent_reuse and _check_password_reuse(db, u.id, plain_pw, policy):
        raise HTTPException(400, f"No puedes reutilizar ninguna de tus últimas {policy.reuse_remember_count} contraseñas")
    u.password = hash_password(plain_pw)
    u.password_changed_at = datetime.utcnow()
    db.add(PasswordHistory(user_id=u.id, password=u.password))
    db.flush()
    keep = max(policy.reuse_remember_count, 1)
    old_rows = (
        db.query(PasswordHistory)
        .filter(PasswordHistory.user_id == u.id)
        .order_by(PasswordHistory.created_at.desc())
        .offset(keep)
        .all()
    )
    for row in old_rows:
        db.delete(row)


def _gen_temp_password(policy: PasswordPolicy) -> str:
    length = max(policy.min_length, 8)
    pools = []
    if policy.require_uppercase: pools.append(string.ascii_uppercase)
    if policy.require_lowercase: pools.append(string.ascii_lowercase)
    if policy.require_number:    pools.append(string.digits)
    if policy.require_special:   pools.append("!@#$%^&*()-_=+")
    if not pools:
        pools = [string.ascii_letters + string.digits]
    chars = [random.choice(pool) for pool in pools]
    all_allowed = "".join(pools)
    while len(chars) < length:
        chars.append(random.choice(all_allowed))
    random.shuffle(chars)
    return "".join(chars)


def _fmt_user(db: Session, u: User) -> dict:
    role = db.query(Role).filter(Role.id == u.role_id).first() if u.role_id else None
    return {
        "id": u.id, "name": u.name, "email": u.email,
        "role_id": u.role_id, "role_name": role.name if role else "Sin rol",
        "active": u.active,
        "must_change_password": bool(u.must_change_password),
    }


def _remaining_users_with_permission(db: Session, section: str, min_level: str, exclude_id: str) -> int:
    """Cuántos usuarios activos (sin contar exclude_id) seguirían teniendo al
    menos min_level en section. La regla es sobre el sistema (siempre debe
    quedar alguien que pueda gestionar usuarios/roles), no sobre la
    identidad de quién hace el cambio — así que un usuario sí puede
    desactivarse/eliminarse a sí mismo (o a otro), mientras quede alguien
    más con ese mismo nivel de acceso."""
    users = db.query(User).filter(User.active == True, User.id != exclude_id, User.role_id.isnot(None)).all()
    return sum(1 for u in users if has_permission(db, u, section, min_level))


class LoginRequest(BaseModel):
    email: str
    password: str


class UserCreate(BaseModel):
    name: str
    email: str
    role_id: str
    # password is optional — if omitted, a temp password is auto-generated
    password: str | None = None


class UserUpdate(BaseModel):
    name: str | None = None
    email: str | None = None
    role_id: str | None = None
    active: bool | None = None


class UserAccessUpdate(BaseModel):
    disable: bool = False
    password_mode: str | None = None  # "auto" | "custom" — requerido cuando disable=False
    custom_password: str | None = None
    force_change: bool = False
    revoke_sessions: bool = False


class PasswordPolicyUpdate(BaseModel):
    min_length: int = 8
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_number: bool = True
    require_special: bool = True
    expiration_enabled: bool = False
    expire_days: int = 90
    prevent_reuse: bool = True
    reuse_remember_count: int = 3


@router.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email, User.active == True).first()
    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    policy = _get_policy(db)
    if policy.expiration_enabled and user.password_changed_at and not user.must_change_password:
        age_days = (datetime.utcnow() - user.password_changed_at).days
        if age_days >= policy.expire_days:
            user.must_change_password = True
            db.commit()

    token = create_token({"sub": user.id, "name": user.name, "tv": user.token_version or 0})
    role = db.query(Role).filter(Role.id == user.role_id).first() if user.role_id else None
    return {
        "token": token,
        "role_name": role.name if role else "Sin rol",
        "name": user.name,
        "id": user.id,
        "must_change_password": bool(user.must_change_password),
        "permissions": get_permission_map(db, user),
    }


@router.get("/me")
def me(user=Depends(get_current_user), db: Session = Depends(get_db)):
    role = db.query(Role).filter(Role.id == user.role_id).first() if user.role_id else None
    return {
        "id": user.id, "name": user.name, "email": user.email,
        "role_name": role.name if role else "Sin rol",
        "must_change_password": bool(user.must_change_password),
        "permissions": get_permission_map(db, user),
    }


@router.get("/setup-status")
def setup_status(user=Depends(get_current_user), db: Session = Depends(get_db)):
    admin_email = "admin@smartmonitor.local"
    admin = db.query(User).filter(User.email == admin_email).first()
    is_default = bool(admin and verify_password("Admin2024!", admin.password))
    return {"is_default": is_default}


@router.put("/change-password")
def change_password(data: dict, user=Depends(get_current_user), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user.id).first()
    # If it's a forced change (temp password), skip current-password verification
    if not bool(u.must_change_password):
        if not verify_password(data.get("current_password", ""), u.password):
            raise HTTPException(status_code=400, detail="Contraseña actual incorrecta")
    policy = _get_policy(db)
    _apply_password(db, u, data.get("new_password", ""), policy)
    u.must_change_password = False
    db.commit()
    return {"ok": True}


# ── Política de contraseñas ─────────────────────────────────────────────────

@router.get("/password-policy")
def get_password_policy(user=Depends(get_current_user), db: Session = Depends(get_db)):
    return _fmt_policy(_get_policy(db))


@router.put("/password-policy")
def update_password_policy(data: PasswordPolicyUpdate, user=Depends(require_permission("settings", "edit")), db: Session = Depends(get_db)):
    if not (6 <= data.min_length <= 128):
        raise HTTPException(400, "La longitud mínima debe estar entre 6 y 128")
    if not (1 <= data.expire_days <= 1095):
        raise HTTPException(400, "Los días de expiración deben estar entre 1 y 1095")
    if not (1 <= data.reuse_remember_count <= 24):
        raise HTTPException(400, "El historial a recordar debe estar entre 1 y 24")
    p = _get_policy(db)
    p.min_length = data.min_length
    p.require_uppercase = data.require_uppercase
    p.require_lowercase = data.require_lowercase
    p.require_number = data.require_number
    p.require_special = data.require_special
    p.expiration_enabled = data.expiration_enabled
    p.expire_days = data.expire_days
    p.prevent_reuse = data.prevent_reuse
    p.reuse_remember_count = data.reuse_remember_count
    db.commit()
    return _fmt_policy(p)


# ── Usuarios ─────────────────────────────────────────────────────────────────

@router.get("/users")
def list_users(user=Depends(require_permission("users", "view")), db: Session = Depends(get_db)):
    return [_fmt_user(db, u) for u in db.query(User).all()]


@router.post("/users")
def create_user(data: UserCreate, user=Depends(require_permission("users", "manage")), db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email ya registrado")
    if not db.query(Role).filter(Role.id == data.role_id).first():
        raise HTTPException(status_code=400, detail="Rol no válido")

    policy = _get_policy(db)
    if data.password:
        plain = data.password
        is_temp = False
        err = _validate_password_policy(plain, policy)
        if err:
            raise HTTPException(400, err)
    else:
        plain = _gen_temp_password(policy)
        is_temp = True

    new_user = User(
        name=data.name,
        email=data.email,
        password=hash_password(plain),
        role_id=data.role_id,
        must_change_password=is_temp,
        password_changed_at=datetime.utcnow(),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    db.add(PasswordHistory(user_id=new_user.id, password=new_user.password))
    db.commit()
    result = _fmt_user(db, new_user)
    if is_temp:
        result["temp_password"] = plain
    return result


@router.put("/users/{user_id}")
def update_user(user_id: str, data: UserUpdate, user=Depends(require_permission("users", "edit")), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if data.role_id is not None and not db.query(Role).filter(Role.id == data.role_id).first():
        raise HTTPException(status_code=400, detail="Rol no válido")

    # Un usuario no puede desactivarse a sí mismo: debe hacerlo otro admin
    # (o alguien con permiso de gestión de usuarios).
    if data.active is False and u.id == user.id:
        raise HTTPException(status_code=403, detail="No puedes desactivar tu propia cuenta")

    currently_manages_users = has_permission(db, u, "users", "manage") and u.active
    will_lose_it = currently_manages_users and (
        (data.role_id is not None and data.role_id != u.role_id) or data.active is False
    )
    if will_lose_it:
        # simular el nuevo rol para saber si de verdad perdería el permiso
        still_has_it = data.role_id == u.role_id if data.role_id is not None else True
        if not still_has_it or data.active is False:
            if _remaining_users_with_permission(db, "users", "manage", u.id) == 0:
                raise HTTPException(400, "No puedes quitarle el rol ni desactivar al último usuario con permiso de gestión de usuarios y roles")

    if data.name is not None:     u.name = data.name
    if data.email is not None:    u.email = data.email
    if data.role_id is not None:  u.role_id = data.role_id
    if data.active is not None:   u.active = data.active
    db.commit()
    return _fmt_user(db, u)


@router.post("/users/{user_id}/access")
def update_user_access(user_id: str, data: UserAccessUpdate, user=Depends(require_permission("users", "edit")), db: Session = Depends(get_db)):
    """Gestión de acceso estilo IAM: desactivar la cuenta, o restablecer su
    contraseña (autogenerada o personalizada) con opción de forzar cambio en
    el próximo inicio de sesión y/o revocar las sesiones ya iniciadas."""
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "Usuario no encontrado")

    if data.disable:
        if u.id == user.id:
            raise HTTPException(403, "No puedes desactivar tu propia cuenta")
        if has_permission(db, u, "users", "manage") and _remaining_users_with_permission(db, "users", "manage", u.id) == 0:
            raise HTTPException(400, "No puedes desactivar al último usuario con permiso de gestión de usuarios y roles")
        u.active = False
        db.commit()
        return {"ok": True}

    policy = _get_policy(db)
    u.active = True
    temp_password = None
    if data.password_mode == "custom":
        pw = data.custom_password or ""
        _apply_password(db, u, pw, policy)
    else:
        temp_password = _gen_temp_password(policy)
        _apply_password(db, u, temp_password, policy, check_reuse=False)
    u.must_change_password = bool(data.force_change)

    if data.revoke_sessions:
        u.token_version = (u.token_version or 0) + 1

    db.commit()
    result = {"ok": True}
    if temp_password:
        result["temp_password"] = temp_password
    return result


@router.delete("/users/{user_id}")
def delete_user(user_id: str, user=Depends(require_permission("users", "manage")), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if u.id == user.id:
        raise HTTPException(status_code=403, detail="No puedes eliminar tu propia cuenta")
    if u.active and has_permission(db, u, "users", "manage") and _remaining_users_with_permission(db, "users", "manage", u.id) == 0:
        raise HTTPException(status_code=400, detail="No puedes eliminar al último usuario con permiso de gestión de usuarios y roles")
    db.delete(u)
    db.commit()
    return {"ok": True}

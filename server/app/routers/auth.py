import random
import secrets
import string
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel
from core.db import get_db, verify_password, create_token, get_current_user, hash_password
from core.permissions import require_permission, get_permission_map, has_permission
from models.models import User, PasswordPolicy, PasswordHistory, Role, LoginAttempt, PasswordResetToken

router = APIRouter(prefix="/api/auth", tags=["auth"])

POLICY_ID = "default"
RESET_TOKEN_EXPIRY_MINUTES = 30


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
        "has_access": bool(u.has_access) if u.has_access is not None else True,
        "must_change_password": bool(u.must_change_password),
        "is_default_admin": bool(u.is_default_admin),
    }


def _remaining_users_with_permission(db: Session, section: str, min_level: str, exclude_id: str) -> int:
    """Cuántos usuarios activos y con acceso a la consola (sin contar
    exclude_id) seguirían teniendo al menos min_level en section. La regla es
    sobre el sistema (siempre debe quedar alguien que pueda gestionar
    usuarios/roles), no sobre la identidad de quién hace el cambio — así que
    un usuario sí puede desactivarse/eliminarse a sí mismo (o a otro),
    mientras quede alguien más con ese mismo nivel de acceso. Un usuario sin
    acceso a la consola (has_access=False) no cuenta aunque tenga un rol con
    permisos, porque no puede iniciar sesión para ejercerlos."""
    users = db.query(User).filter(
        User.active == True, User.has_access == True,
        User.id != exclude_id, User.role_id.isnot(None),
    ).all()
    return sum(1 for u in users if has_permission(db, u, section, min_level))


class LoginRequest(BaseModel):
    email: str
    password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class UserCreate(BaseModel):
    name: str
    email: str
    role_id: str
    has_access: bool = True
    # password is optional — if omitted, a temp password is auto-generated
    password: str | None = None


class UserUpdate(BaseModel):
    name: str | None = None
    email: str | None = None
    role_id: str | None = None
    active: bool | None = None
    has_access: bool | None = None


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


def _client_ip(request: Request) -> str | None:
    """IP real del cliente. El panel admin (dominio con TLS real) llega acá
    a traves de un proxy nginx local que agrega X-Forwarded-For con la IP
    real - solo se confia en ese header cuando la conexion TCP en si misma
    vino de localhost (nuestro propio nginx), nunca si alguien le pega
    directo al puerto de la app, para que no se pueda falsificar."""
    direct_ip = request.client.host if request.client else None
    if direct_ip in ("127.0.0.1", "::1"):
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return direct_ip

def _log_login(db: Session, email: str, success: bool, reason: str, user_id: str, request: Request):
    ip = _client_ip(request)
    db.add(LoginAttempt(email=email, user_id=user_id, success=success, reason=reason, ip_address=ip))
    db.commit()

@router.post("/login")
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    # Se busca SIN filtrar por active/has_access para poder registrar en el
    # historial de accesos el motivo REAL del fallo (cuenta desactivada, sin
    # acceso a consola, contraseña incorrecta) - el mensaje que ve el cliente
    # sigue siendo siempre el mismo "Credenciales incorrectas" (no se le
    # revela al usuario si el email existe o no), el detalle solo queda en
    # el historial que ven los administradores.
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_password(data.password, user.password):
        _log_login(db, data.email, False, "Credenciales incorrectas", user.id if user else None, request)
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    if not user.active:
        _log_login(db, data.email, False, "Cuenta desactivada", user.id, request)
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    if user.has_access is False:
        # Existe solo para asignarle equipos (estilo "sin acceso a consola" de
        # AWS IAM) — no puede iniciar sesión aunque la contraseña sea correcta.
        _log_login(db, data.email, False, "Sin acceso a la consola", user.id, request)
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    policy = _get_policy(db)
    if policy.expiration_enabled and user.password_changed_at and not user.must_change_password:
        age_days = (datetime.utcnow() - user.password_changed_at).days
        if age_days >= policy.expire_days:
            user.must_change_password = True
            db.commit()

    token = create_token({"sub": user.id, "name": user.name, "tv": user.token_version or 0})
    role = db.query(Role).filter(Role.id == user.role_id).first() if user.role_id else None
    _log_login(db, data.email, True, "Inicio de sesión exitoso", user.id, request)
    return {
        "token": token,
        "role_name": role.name if role else "Sin rol",
        "name": user.name,
        "id": user.id,
        "must_change_password": bool(user.must_change_password),
        "permissions": get_permission_map(db, user),
    }


# ── Recuperación de contraseña por email ────────────────────────────────────
_FORGOT_PASSWORD_GENERIC_MSG = "Si el correo existe, te enviamos un enlace para restablecer tu contraseña."


@router.post("/forgot-password")
def forgot_password(data: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """Sin revelar si el email existe o no (mismo criterio que /login) - la
    respuesta es siempre la misma, exista o no una cuenta con ese correo, y
    aunque el envío de correo mismo falle (SMTP sin configurar, etc.) - eso
    no debe ser visible para quien pide el reset, solo queda en los logs del
    server."""
    user = db.query(User).filter(
        User.email == data.email, User.active == True, User.has_access != False,
    ).first()
    if user:
        # A lo sumo un token vigente a la vez, igual que los códigos de
        # equipo (uninstall/pause) - invalida cualquier pedido anterior sin usar.
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        ).delete()
        reset_token = secrets.token_urlsafe(32)
        db.add(PasswordResetToken(
            user_id=user.id, token=reset_token,
            expires_at=datetime.utcnow() + timedelta(minutes=RESET_TOKEN_EXPIRY_MINUTES),
        ))
        db.commit()
        from core.notify import send_password_reset_email_silent
        send_password_reset_email_silent(user.name, user.email, reset_token)
    return {"ok": True, "message": _FORGOT_PASSWORD_GENERIC_MSG}


@router.post("/reset-password")
def reset_password(data: ResetPasswordRequest, db: Session = Depends(get_db)):
    rec = db.query(PasswordResetToken).filter(PasswordResetToken.token == data.token).first()
    if not rec or rec.used_at is not None:
        raise HTTPException(400, "El enlace no es válido o ya fue usado")
    if rec.expires_at < datetime.utcnow():
        raise HTTPException(400, "El enlace expiró — pedí uno nuevo desde \"¿Olvidaste tu contraseña?\"")
    u = db.query(User).filter(User.id == rec.user_id).first()
    if not u:
        raise HTTPException(404, "Usuario no encontrado")
    policy = _get_policy(db)
    _apply_password(db, u, data.new_password, policy)
    u.must_change_password = False
    # Restablecer la contraseña cierra cualquier otra sesión ya iniciada -
    # mismo criterio que "revoke_sessions" al restablecer desde Usuarios.
    u.token_version = (u.token_version or 0) + 1
    rec.used_at = datetime.utcnow()
    db.commit()
    return {"ok": True}


# ── Historial de accesos ────────────────────────────────────────────────────
@router.get("/login-attempts")
def list_login_attempts(
    email:   str  = Query(None),
    success: bool = Query(None),
    from_date: str = Query(None),
    to_date:   str = Query(None),
    limit:   int  = Query(200),
    user = Depends(require_permission("users", "view")),
    db: Session = Depends(get_db),
):
    q = db.query(LoginAttempt)
    if email:
        q = q.filter(LoginAttempt.email.ilike(f"%{email}%"))
    if success is not None:
        q = q.filter(LoginAttempt.success == success)
    if from_date:
        try:
            q = q.filter(LoginAttempt.timestamp >= datetime.fromisoformat(from_date))
        except ValueError:
            pass
    if to_date:
        try:
            q = q.filter(LoginAttempt.timestamp < datetime.fromisoformat(to_date) + timedelta(days=1))
        except ValueError:
            pass
    rows = q.order_by(desc(LoginAttempt.timestamp)).limit(max(1, min(limit, 2000))).all()
    user_ids = {r.user_id for r in rows if r.user_id}
    users_map = {u.id: u for u in db.query(User).filter(User.id.in_(user_ids)).all()}
    return [{
        "id": r.id,
        "email": r.email,
        "user_name": (users_map[r.user_id].name if r.user_id in users_map else None),
        "success": r.success,
        "reason": r.reason,
        "ip_address": r.ip_address,
        "timestamp": r.timestamp.isoformat(),
    } for r in rows]


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
    is_temp = False
    if not data.has_access:
        # Nunca va a iniciar sesión (solo existe para asignarle equipos): la
        # contraseña es puro relleno para la columna NOT NULL, no hace falta
        # que cumpla la política ni mostrarla como temporal.
        plain = _gen_temp_password(policy)
    elif data.password:
        plain = data.password
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
        has_access=data.has_access,
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
    if data.has_access:
        from core.notify import send_welcome_email_silent
        send_welcome_email_silent(data.name, data.email, plain, is_temp)
    return result


@router.put("/users/{user_id}")
def update_user(user_id: str, data: UserUpdate, user=Depends(require_permission("users", "edit")), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if data.role_id is not None and not db.query(Role).filter(Role.id == data.role_id).first():
        raise HTTPException(status_code=400, detail="Rol no válido")

    # Un usuario no puede desactivarse (ni quitarse el acceso a la consola) a
    # sí mismo: debe hacerlo otro admin (o alguien con permiso de gestión de
    # usuarios).
    if data.active is False and u.id == user.id:
        raise HTTPException(status_code=403, detail="No puedes desactivar tu propia cuenta")
    if data.has_access is False and u.id == user.id:
        raise HTTPException(status_code=403, detail="No puedes quitarte tu propio acceso a la consola")

    currently_manages_users = has_permission(db, u, "users", "manage") and u.active and u.has_access is not False
    will_lose_it = currently_manages_users and (
        (data.role_id is not None and data.role_id != u.role_id) or data.active is False or data.has_access is False
    )
    if will_lose_it:
        # simular el nuevo rol para saber si de verdad perdería el permiso
        still_has_it = data.role_id == u.role_id if data.role_id is not None else True
        if not still_has_it or data.active is False or data.has_access is False:
            if _remaining_users_with_permission(db, "users", "manage", u.id) == 0:
                raise HTTPException(400, "No puedes quitarle el rol, el acceso ni desactivar al último usuario con permiso de gestión de usuarios y roles")

    if data.name is not None:       u.name = data.name
    if data.email is not None:      u.email = data.email
    if data.role_id is not None:    u.role_id = data.role_id
    if data.active is not None:     u.active = data.active
    if data.has_access is not None: u.has_access = data.has_access
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
    if u.is_default_admin:
        raise HTTPException(status_code=403, detail="El administrador por defecto no se puede eliminar desde el panel — solo puedes desactivarlo o restablecer su contraseña")
    if u.active and has_permission(db, u, "users", "manage") and _remaining_users_with_permission(db, "users", "manage", u.id) == 0:
        raise HTTPException(status_code=400, detail="No puedes eliminar al último usuario con permiso de gestión de usuarios y roles")
    db.delete(u)
    db.commit()
    return {"ok": True}

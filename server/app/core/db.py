import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://smartmonitor:SmartMonitor2024!@db:5432/smartmonitor")
SECRET_KEY   = os.getenv("SECRET_KEY", "dev-secret-key-cambiar-en-produccion")
ALGORITHM    = "HS256"
TOKEN_EXPIRE = 60 * 24  # 24 horas en minutos

engine  = create_engine(DATABASE_URL, pool_pre_ping=True)
Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer  = HTTPBearer(auto_error=False)

def get_db():
    db = Session()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def create_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
    db = Depends(get_db)
):
    from models.models import User
    exc = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No autenticado")
    if not credentials:
        raise exc
    try:
        payload = decode_token(credentials.credentials)
        user_id = payload.get("sub")
        if not user_id:
            raise exc
    except JWTError:
        raise exc
    user = db.query(User).filter(User.id == user_id, User.active == True).first()
    if not user or user.has_access is False or payload.get("tv", 0) != (user.token_version or 0):
        raise exc
    return user

def require_admin(user = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Se requiere rol admin")
    return user

def get_user_from_token_param(token: str = "", db = Depends(get_db)):
    """Valida JWT desde query param ?token=... (usado por SSE/EventSource)."""
    from models.models import User
    exc = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No autenticado")
    if not token:
        raise exc
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        if not user_id:
            raise exc
    except JWTError:
        raise exc
    user = db.query(User).filter(User.id == user_id, User.active == True).first()
    if not user or user.has_access is False or payload.get("tv", 0) != (user.token_version or 0):
        raise exc
    return user

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import re
from core.db import get_db
from core.permissions import require_permission
from models.models import BlockedSite, Agent, BlockCategory, Sede, Event
from routers.block_schedules import _local_now, _parse_expires

router = APIRouter(prefix="/api/blocked-sites", tags=["blocked-sites"])

# ── Catálogo de categorías (al estilo Cloudflare Gateway) ──────────────────
# Todas las categorías (predefinidas o creadas por el admin) viven en la tabla
# block_categories, así todas se pueden editar/eliminar por igual. Las
# predefinidas de abajo solo se usan una vez, para sembrar la tabla si está
# vacía (ver seed_default_categories, llamada desde main.py al iniciar).
GROUPS = {
    "parental":     "Control parental",
    "productividad": "Productividad / Empresa",
}

SEED_CATEGORIES = [
    {
        "label": "Contenido para adultos",
        "group": "parental",
        "domains": ["pornhub.com", "xvideos.com", "xnxx.com", "onlyfans.com"],
    },
    {
        "label": "Apuestas / casinos",
        "group": "parental",
        "domains": [
            "bet365.com", "pokerstars.com", "betway.com", "williamhill.com",
            "bwin.com", "888casino.com", "codere.com", "betsson.com",
        ],
    },
    {
        "label": "Redes sociales",
        "group": "parental",
        "domains": [
            "facebook.com", "instagram.com", "twitter.com", "x.com",
            "tiktok.com", "snapchat.com", "linkedin.com", "reddit.com",
            "pinterest.com", "threads.net",
        ],
    },
    {
        "label": "Videojuegos",
        "group": "parental",
        "domains": [
            "steampowered.com", "epicgames.com", "roblox.com", "minecraft.net",
            "ea.com", "playstation.com", "xbox.com", "battle.net",
            "riotgames.com", "ubisoft.com",
        ],
    },
    {
        "label": "Streaming de video",
        "group": "productividad",
        "domains": [
            "youtube.com", "netflix.com", "twitch.tv", "primevideo.com",
            "disneyplus.com", "max.com", "hbomax.com", "hulu.com",
            "vimeo.com", "dailymotion.com", "crunchyroll.com", "peacocktv.com",
        ],
    },
    {
        "label": "IA generativa",
        "group": "productividad",
        "domains": [
            "chatgpt.com", "openai.com", "claude.ai", "gemini.google.com",
            "copilot.microsoft.com", "character.ai",
        ],
    },
]

def seed_default_categories(db: Session):
    if db.query(BlockCategory).count() > 0:
        return
    for c in SEED_CATEGORIES:
        db.add(BlockCategory(label=c["label"], domains=c["domains"], group_key=c["group"]))
    db.commit()

def _clean_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = re.sub(r'^https?://', '', d)
    d = d.split('/')[0].split(':')[0]
    if d.startswith('www.'):
        d = d[4:]
    return d

_DOMAIN_SUFFIXES = [
    "", "www", "m", "mobile", "music", "app", "api", "cdn", "static", "play",
    "tv", "studio", "pay", "support", "help", "blog", "accounts", "ad", "ads",
    "dev", "feed", "gaming", "kids", "oauth", "redirect", "settings", "shop",
    "tv", "upload", "watch", "gaming", "pay", "redirect", "accounts", "support",
]

def _expand_domain(base: str) -> set:
    base = base.strip().lower()
    if not base:
        return set()
    out = set()
    for s in _DOMAIN_SUFFIXES:
        if not s:
            out.add(base)
        else:
            out.add(f"{s}.{base}")
    return out

def resolve_domains_for_agent(agent: Optional[Agent], active_sites: list) -> set:
    """Dominios finales bloqueados para un equipo (o global si agent es None).
    Se unen los bloqueos de los 3 niveles (global + área + equipo) y se restan
    las excepciones vigentes de esos mismos 3 niveles — una excepción en
    cualquier nivel cancela el dominio para ese alcance, sin importar de dónde
    vino el bloqueo. Reutilizada por el endpoint que consultan los agentes y
    por el reporte."""
    now = _local_now(None)

    def not_expired(s):
        return s.expires_at is None or s.expires_at > now

    global_blocks = {s.domain for s in active_sites if s.agent_id is None and s.sede_id is None and not s.is_exception}
    global_exceptions = {s.domain for s in active_sites if s.agent_id is None and s.sede_id is None and s.is_exception and not_expired(s)}
    if not agent:
        return global_blocks - global_exceptions

    sede_blocks = sede_exceptions = set()
    if agent.sede_id:
        sede_blocks = {s.domain for s in active_sites if s.sede_id == agent.sede_id and not s.is_exception}
        sede_exceptions = {s.domain for s in active_sites if s.sede_id == agent.sede_id and s.is_exception and not_expired(s)}

    agent_blocks = {s.domain for s in active_sites if s.agent_id == agent.id and not s.is_exception}
    agent_exceptions = {s.domain for s in active_sites if s.agent_id == agent.id and s.is_exception and not_expired(s)}

    all_blocks = global_blocks | sede_blocks | agent_blocks
    all_exceptions = global_exceptions | sede_exceptions | agent_exceptions
    raw = all_blocks - all_exceptions
    out = set()
    for d in raw:
        out.update(_expand_domain(d))
    return out

def resolve_all_configured_domains(agent: Optional[Agent], active_sites: list) -> set:
    """Todos los dominios bloqueados a nivel Global/Área/Equipo para este agente,
    SIN restar excepciones ni considerar horario/red WiFi. No se usa para decidir
    qué bloquear (eso es resolve_domains_for_agent) sino solo para que el agente
    pueda detectar y reportar 'intentos exitosos': visitas a un dominio que está
    en la configuración de bloqueo pero que en ese momento se dejó pasar (por
    excepción, fuera de horario, o por el toggle de red WiFi)."""
    global_blocks = {s.domain for s in active_sites if s.agent_id is None and s.sede_id is None and not s.is_exception}
    if not agent:
        return global_blocks
    sede_blocks = set()
    if agent.sede_id:
        sede_blocks = {s.domain for s in active_sites if s.sede_id == agent.sede_id and not s.is_exception}
    agent_blocks = {s.domain for s in active_sites if s.agent_id == agent.id and not s.is_exception}
    return global_blocks | sede_blocks | agent_blocks

class BlockedSiteCreate(BaseModel):
    domain: str
    agent_id: Optional[str] = None
    sede_id: Optional[str] = None
    reason: Optional[str] = None
    is_exception: bool = False
    section: Optional[str] = None  # "parental" si se crea desde esa página
    expires_at: Optional[str] = None  # solo tiene sentido cuando is_exception=True

class BlockedSiteUpdate(BaseModel):
    active: Optional[bool] = None
    reason: Optional[str] = None
    expires_at: Optional[str] = None

class CategoryApply(BaseModel):
    agent_id: Optional[str] = None
    sede_id: Optional[str] = None
    reason: Optional[str] = None
    is_exception: bool = False
    expires_at: Optional[str] = None

class CustomCategoryCreate(BaseModel):
    label: str
    domains: list[str]
    group: str = "parental"

class CustomCategoryUpdate(BaseModel):
    label: Optional[str] = None
    domains: Optional[list[str]] = None
    group: Optional[str] = None

def _resolve_category(key: str, db: Session):
    """Devuelve {'label':..., 'domains':[...]} para la categoría con ese id, o None."""
    cat = db.query(BlockCategory).filter(BlockCategory.id == key).first()
    if cat:
        return {"label": cat.label, "domains": cat.domains or []}
    return None

def _category_label(key: Optional[str], db: Session) -> Optional[str]:
    if not key:
        return None
    cat = db.query(BlockCategory).filter(BlockCategory.id == key).first()
    return cat.label if cat else None

def _fmt(b: BlockedSite, db: Session) -> dict:
    return {
        "id": b.id,
        "domain": b.domain,
        "agent_id": b.agent_id,
        "agent_name": (b.agent.display_name or b.agent.hostname) if b.agent else None,
        "sede_id": b.sede_id,
        "sede_name": b.sede.name if b.sede else None,
        "is_exception": b.is_exception,
        "category": b.category,
        "category_label": _category_label(b.category, db),
        "section": b.section,
        "reason": b.reason,
        "active": b.active,
        "expires_at": b.expires_at.isoformat() if b.expires_at else None,
        "created_at": b.created_at.isoformat() if b.created_at else None,
    }

def _exception_scope_desc(site: BlockedSite, db: Session) -> str | None:
    """Descripcion legible de a que nivel aplica una excepcion, para el
    registro en Eventos (reportes). El equipo no se incluye aqui porque ya
    lo muestra la propia columna de equipo/hostname del evento; solo aporta
    algo nuevo cuando el alcance es area o global."""
    if site.agent_id:
        return None
    if site.sede_id:
        sede = db.query(Sede).filter(Sede.id == site.sede_id).first()
        name = sede.name if sede else "área eliminada"
        return f"área: {name}"
    return "global (todos los equipos)"

def _log_exception_event(db: Session, site: BlockedSite, when=None):
    """Registra en Eventos la creacion de una excepcion, para que quede en
    reportes: dominio, a que nivel aplica (area/global, si no es un equipo
    puntual) y fecha de expiracion si tiene. El motivo (site.reason) va en su
    propia columna Event.reason, no embebido en el detalle. La fecha de
    creacion es el propio timestamp del evento - "when" solo se usa para el
    respaldo historico (backfill de excepciones que ya existian antes de
    este registro)."""
    detail = f"Excepción: {site.domain}"
    scope = _exception_scope_desc(site, db)
    if scope:
        detail += f" — {scope}"
    if site.expires_at:
        detail += f" — Expira: {site.expires_at.strftime('%Y-%m-%d %H:%M')}"
    ev = Event(
        agent_id=site.agent_id, sede_id=site.sede_id, type="exception_created",
        detail=detail, reason=(site.reason or "Excepción de bloqueo agregada manualmente"),
    )
    if when:
        ev.timestamp = when
    db.add(ev)

def _log_expired_exception_event(db: Session, site: BlockedSite):
    """Igual que _log_exception_event, pero para cuando una excepcion
    expira y se borra sola (ver _purge_expired_sites) - sin esto no queda
    NINGUN rastro de que existio: la fila se borra de blocked_sites y no
    hay otro lado donde quedara guardada. Es la unica forma de poder
    responder despues "que excepciones expiraron" (ver tarjeta
    "Expirados" en Sitios bloqueados)."""
    detail = f"Excepción expirada: {site.domain}"
    scope = _exception_scope_desc(site, db)
    if scope:
        detail += f" — {scope}"
    db.add(Event(
        agent_id=site.agent_id, sede_id=site.sede_id, type="exception_expired",
        detail=detail, reason=site.reason,
    ))

def _purge_expired_sites(db: Session):
    now = _local_now(None)
    candidates = db.query(BlockedSite).filter(
        BlockedSite.is_exception == True, BlockedSite.expires_at.isnot(None),
    ).all()
    changed = False
    for s in candidates:
        if s.expires_at <= now:
            _log_expired_exception_event(db, s)
            db.delete(s)
            changed = True
    if changed:
        db.commit()

@router.get("")
def list_blocked_sites(user=Depends(require_permission("parental_blocked", "view")), db: Session = Depends(get_db)):
    _purge_expired_sites(db)
    sites = db.query(BlockedSite).order_by(BlockedSite.created_at.desc()).all()
    return [_fmt(s, db) for s in sites]

@router.post("")
def create_blocked_site(data: BlockedSiteCreate, user=Depends(require_permission("parental_blocked", "edit")), db: Session = Depends(get_db)):
    domain = _clean_domain(data.domain)
    if not domain:
        raise HTTPException(400, "Dominio inválido")
    if data.agent_id and data.sede_id:
        raise HTTPException(400, "Elige un equipo o un área, no ambos")
    if data.is_exception and not data.agent_id and not data.sede_id:
        raise HTTPException(400, "Una excepción debe especificar un equipo o un área")
    if data.section and data.section not in ("parental",):
        raise HTTPException(400, "Sección inválida")
    if data.agent_id and not db.query(Agent).filter(Agent.id == data.agent_id).first():
        raise HTTPException(404, "Equipo no encontrado")
    if data.sede_id and not db.query(Sede).filter(Sede.id == data.sede_id).first():
        raise HTTPException(404, "Área no encontrada")
    site = BlockedSite(
        domain=domain,
        agent_id=data.agent_id or None,
        sede_id=data.sede_id or None,
        is_exception=data.is_exception,
        section=data.section,
        reason=data.reason,
        expires_at=_parse_expires(data.expires_at) if data.is_exception else None,
    )
    db.add(site)
    db.commit()
    db.refresh(site)
    if site.is_exception:
        _log_exception_event(db, site)
        db.commit()
    return _fmt(site, db)

@router.get("/categories")
def list_categories(user=Depends(require_permission("parental_categories", "view")), db: Session = Depends(get_db)):
    applied = db.query(BlockedSite).filter(BlockedSite.category.isnot(None)).all()
    applied_by_cat = {}
    for s in applied:
        entry = applied_by_cat.setdefault(s.category, {
            "global": False, "agents": set(), "sedes": set(),
            "agent_exceptions": set(), "sede_exceptions": set(),
        })
        if s.is_exception:
            if s.agent_id: entry["agent_exceptions"].add(s.agent_id)
            if s.sede_id: entry["sede_exceptions"].add(s.sede_id)
        else:
            if s.agent_id: entry["agents"].add(s.agent_id)
            elif s.sede_id: entry["sedes"].add(s.sede_id)
            else: entry["global"] = True

    result = []
    for cc in db.query(BlockCategory).order_by(BlockCategory.created_at.desc()).all():
        gkey = cc.group_key if cc.group_key in GROUPS else "parental"
        entry = applied_by_cat.get(cc.id, {})
        result.append({
            "key": cc.id,
            "label": cc.label,
            "domain_count": len(cc.domains or []),
            "group": gkey,
            "group_label": GROUPS[gkey],
            "applied_global": entry.get("global", False),
            "applied_agent_ids": sorted(entry.get("agents", set())),
            "applied_sede_ids": sorted(entry.get("sedes", set())),
            "excepted_agent_ids": sorted(entry.get("agent_exceptions", set())),
            "excepted_sede_ids": sorted(entry.get("sede_exceptions", set())),
        })
    return result

# ── Categorías personalizadas (definidas por el admin) ──────────────────────
@router.get("/custom-categories")
def list_custom_categories(user=Depends(require_permission("parental_categories", "view")), db: Session = Depends(get_db)):
    cats = db.query(BlockCategory).order_by(BlockCategory.created_at.desc()).all()
    return [{"id": c.id, "label": c.label, "domains": c.domains or [], "group": c.group_key} for c in cats]

@router.post("/custom-categories")
def create_custom_category(data: CustomCategoryCreate, user=Depends(require_permission("parental_categories", "edit")), db: Session = Depends(get_db)):
    label = data.label.strip()
    if not label:
        raise HTTPException(400, "El nombre de la categoría es obligatorio")
    if data.group not in GROUPS:
        raise HTTPException(400, "Grupo inválido")
    domains = sorted({_clean_domain(d) for d in data.domains if _clean_domain(d)})
    if not domains:
        raise HTTPException(400, "Agrega al menos un dominio válido")
    cat = BlockCategory(label=label, domains=domains, group_key=data.group)
    db.add(cat)
    db.commit()
    db.refresh(cat)
    return {"id": cat.id, "label": cat.label, "domains": cat.domains, "group": cat.group_key}

@router.put("/custom-categories/{cat_id}")
def update_custom_category(cat_id: str, data: CustomCategoryUpdate, user=Depends(require_permission("parental_categories", "edit")), db: Session = Depends(get_db)):
    cat = db.query(BlockCategory).filter(BlockCategory.id == cat_id).first()
    if not cat:
        raise HTTPException(404, "Categoría no encontrada")
    if data.label is not None:
        label = data.label.strip()
        if not label:
            raise HTTPException(400, "El nombre de la categoría es obligatorio")
        cat.label = label
    if data.group is not None:
        if data.group not in GROUPS:
            raise HTTPException(400, "Grupo inválido")
        cat.group_key = data.group
    sync = {"added": 0, "removed": 0}
    if data.domains is not None:
        new_domains = sorted({_clean_domain(d) for d in data.domains if _clean_domain(d)})
        if not new_domains:
            raise HTTPException(400, "Agrega al menos un dominio válido")
        old_domains = set(cat.domains or [])
        added   = set(new_domains) - old_domains
        removed = old_domains - set(new_domains)
        cat.domains = new_domains

        if added or removed:
            # Replicar el cambio en todos los alcances donde ya está aplicada
            # esta categoría (global y/o equipos específicos), para que editar
            # la categoría no requiera "reaplicarla" a mano en cada uno.
            scopes = {
                s.agent_id for s in db.query(BlockedSite).filter(
                    BlockedSite.category == cat_id, BlockedSite.is_exception == False
                ).all()
            }
            for agent_id in scopes:
                if removed:
                    sync["removed"] += db.query(BlockedSite).filter(
                        BlockedSite.category == cat_id,
                        BlockedSite.agent_id == agent_id,
                        BlockedSite.domain.in_(removed),
                    ).delete(synchronize_session=False)
                for d in added:
                    db.add(BlockedSite(domain=d, agent_id=agent_id, category=cat_id))
                    sync["added"] += 1
    db.commit()
    db.refresh(cat)
    return {"id": cat.id, "label": cat.label, "domains": cat.domains, "group": cat.group_key, "sync": sync}

@router.delete("/custom-categories/{cat_id}")
def delete_custom_category(cat_id: str, user=Depends(require_permission("parental_categories", "edit")), db: Session = Depends(get_db)):
    cat = db.query(BlockCategory).filter(BlockCategory.id == cat_id).first()
    if not cat:
        raise HTTPException(404, "Categoría no encontrada")
    db.query(BlockedSite).filter(BlockedSite.category == cat_id).delete(synchronize_session=False)
    db.delete(cat)
    db.commit()
    return {"ok": True}

@router.post("/categories/{key}")
def apply_category(key: str, data: CategoryApply, user=Depends(require_permission("parental_categories", "edit")), db: Session = Depends(get_db)):
    cat = _resolve_category(key, db)
    if not cat:
        raise HTTPException(404, "Categoría no encontrada")
    if data.agent_id and data.sede_id:
        raise HTTPException(400, "Elige un equipo o un área, no ambos")
    if data.is_exception and not data.agent_id and not data.sede_id:
        raise HTTPException(400, "Una excepción debe especificar un equipo o un área")
    if data.agent_id and not db.query(Agent).filter(Agent.id == data.agent_id).first():
        raise HTTPException(404, "Equipo no encontrado")
    if data.sede_id and not db.query(Sede).filter(Sede.id == data.sede_id).first():
        raise HTTPException(404, "Área no encontrada")

    existing = {
        s.domain for s in db.query(BlockedSite).filter(
            BlockedSite.category == key,
            BlockedSite.agent_id == data.agent_id,
            BlockedSite.sede_id == data.sede_id,
            BlockedSite.is_exception == data.is_exception,
        ).all()
    }
    created = 0
    new_sites = []
    for domain in cat["domains"]:
        if domain in existing:
            continue
        site = BlockedSite(
            domain=domain, agent_id=data.agent_id or None, sede_id=data.sede_id or None,
            category=key, reason=data.reason, is_exception=data.is_exception,
            expires_at=_parse_expires(data.expires_at) if data.is_exception else None,
        )
        db.add(site)
        new_sites.append(site)
        created += 1
    if data.is_exception:
        # Un evento por dominio (no uno solo resumido) - misma trazabilidad
        # que crear una excepcion individual, aunque aca se apliquen varias
        # de una sola vez (categoria completa).
        for site in new_sites:
            _log_exception_event(db, site)
    db.commit()
    return {"ok": True, "created": created, "skipped": len(cat["domains"]) - created}

@router.delete("/categories/{key}")
def remove_category(
    key: str, agent_id: Optional[str] = None, sede_id: Optional[str] = None,
    is_exception: bool = False, user=Depends(require_permission("parental_categories", "edit")), db: Session = Depends(get_db),
):
    q = db.query(BlockedSite).filter(
        BlockedSite.category == key, BlockedSite.agent_id == agent_id,
        BlockedSite.sede_id == sede_id, BlockedSite.is_exception == is_exception,
    )
    count = q.delete(synchronize_session=False)
    db.commit()
    return {"ok": True, "deleted": count}

@router.put("/{site_id}")
def update_blocked_site(site_id: str, data: BlockedSiteUpdate, user=Depends(require_permission("parental_blocked", "edit")), db: Session = Depends(get_db)):
    site = db.query(BlockedSite).filter(BlockedSite.id == site_id).first()
    if not site:
        raise HTTPException(404, "Sitio no encontrado")
    if data.active is not None:
        site.active = data.active
    if data.reason is not None:
        site.reason = data.reason
    if data.expires_at is not None:
        site.expires_at = _parse_expires(data.expires_at) if data.expires_at else None
    db.commit()
    db.refresh(site)
    return _fmt(site, db)

@router.delete("/{site_id}")
def delete_blocked_site(site_id: str, user=Depends(require_permission("parental_blocked", "edit")), db: Session = Depends(get_db)):
    site = db.query(BlockedSite).filter(BlockedSite.id == site_id).first()
    if not site:
        raise HTTPException(404, "Sitio no encontrado")
    db.delete(site)
    db.commit()
    return {"ok": True}

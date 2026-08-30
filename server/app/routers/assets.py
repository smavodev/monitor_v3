from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified
from sqlalchemy import desc
from datetime import datetime
from core.db import get_db
from core.permissions import require_permission
from models.models import Asset, AssetType, AssetAssignmentLog, Event, User, Sede

router = APIRouter(prefix="/api/assets", tags=["assets"])

DEFAULT_ASSET_TYPES = [
    {"name": "Monitor",                 "icon": "monitor",  "kind": "serialized", "extra_fields": []},
    {"name": "CPU / Torre",             "icon": "desktop",  "kind": "serialized", "extra_fields": []},
    {"name": "Celular",                 "icon": "phone",    "kind": "serialized", "extra_fields": [{"key": "imei", "label": "IMEI", "type": "text"}]},
    {"name": "Línea telefónica",        "icon": "phone",    "kind": "serialized", "extra_fields": [
        {"key": "operador", "label": "Operador", "type": "select", "options": ["Claro", "Movistar", "Entel", "Bitel"]},
        {"key": "plan", "label": "Plan", "type": "text"},
    ]},
    {"name": "Televisor",               "icon": "monitor",  "kind": "serialized", "extra_fields": []},
    {"name": "Cooler",                  "icon": "other",    "kind": "serialized", "extra_fields": []},
    {"name": "Soporte de aluminio",     "icon": "other",    "kind": "serialized", "extra_fields": []},
    {"name": "Cable VGA",               "icon": "other",    "kind": "stock",      "extra_fields": []},
    {"name": "Cable HDMI",              "icon": "other",    "kind": "stock",      "extra_fields": []},
    {"name": "Cable de poder",          "icon": "other",    "kind": "stock",      "extra_fields": []},
]

def seed_default_asset_types(db: Session):
    if db.query(AssetType).first():
        return
    created = {}
    for t in DEFAULT_ASSET_TYPES:
        obj = AssetType(name=t["name"], icon=t["icon"], kind=t["kind"], extra_fields=t["extra_fields"])
        db.add(obj)
        created[t["name"]] = obj
    db.commit()
    # Celular <-> Línea telefónica: solo se puede vincular entre estos dos
    # tipos (el filtrado bidireccional lo resuelve _linkable_type_ids abajo,
    # con setearlo de un solo lado alcanza).
    celular = created.get("Celular")
    linea = created.get("Línea telefónica")
    if celular and linea:
        celular.linkable_type_id = linea.id
        db.commit()

def migrate_device_types_into_asset_types(db: Session):
    """Unifica 'Tipos de dispositivo' (antes en /data/config.json, solo para
    Agent.device_type) dentro de la misma tabla asset_types que ya usa el
    inventario general - un solo lugar para todas las categorias, en vez de
    dos sistemas separados. Preserva los iconos ya subidos (incluye los
    'data:' URI). Idempotente: solo crea lo que todavia no exista por nombre."""
    import json
    try:
        cfg = json.load(open("/data/config.json"))
    except Exception:
        return
    old_types = cfg.get("device_types") or []
    if not old_types:
        return
    existing_names = {t.name for t in db.query(AssetType).all()}
    changed = False
    for t in old_types:
        name = str((t or {}).get("name", "")).strip()
        if not name or name in existing_names:
            continue
        db.add(AssetType(name=name, icon=(t.get("icon") or "other"), kind="serialized", extra_fields=[]))
        existing_names.add(name)
        changed = True
    if changed:
        db.commit()

def _parse_date(v):
    if not v:
        return None
    try:
        return datetime.strptime(str(v)[:10], "%Y-%m-%d").date()
    except Exception:
        return None

def _log_asset_event(db: Session, asset: Asset, etype: str, detail: str, reason: str = None):
    db.add(Event(asset_id=asset.id, sede_id=asset.sede_id, type=etype, detail=detail, reason=reason))

STATUS_LABELS = {
    "nuevo": "Nuevo", "almacen": "En almacén", "asignado": "Asignado",
    "dañado": "Dañado", "baja": "Dado de baja",
}

# ── Tipos de activo ──────────────────────────────────────────────────────
def _fmt_asset_type(t: AssetType) -> dict:
    return {
        "id": t.id, "name": t.name, "icon": t.icon, "kind": t.kind,
        "extra_fields": t.extra_fields or [],
        "linkable_type_id": t.linkable_type_id,
    }

@router.get("/types")
def list_asset_types(user=Depends(require_permission("inventory", "view")), db: Session = Depends(get_db)):
    return [_fmt_asset_type(t) for t in db.query(AssetType).order_by(AssetType.name).all()]

@router.post("/types")
def create_asset_type(data: dict, user=Depends(require_permission("inventory", "manage")), db: Session = Depends(get_db)):
    name = str(data.get("name", "")).strip()
    if not name:
        raise HTTPException(400, "El nombre es obligatorio")
    if db.query(AssetType).filter(AssetType.name == name).first():
        raise HTTPException(400, "Ya existe un tipo con ese nombre")
    kind = data.get("kind") if data.get("kind") in ("serialized", "stock") else "serialized"
    t = AssetType(
        name=name, icon=str(data.get("icon", "other")) or "other", kind=kind,
        extra_fields=data.get("extra_fields") or [],
        linkable_type_id=data.get("linkable_type_id") or None,
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return _fmt_asset_type(t)

@router.put("/types/{type_id}")
def update_asset_type(type_id: str, data: dict, user=Depends(require_permission("inventory", "manage")), db: Session = Depends(get_db)):
    t = db.query(AssetType).filter(AssetType.id == type_id).first()
    if not t:
        raise HTTPException(404, "Tipo no encontrado")
    # "kind" no se deja cambiar una vez que ya hay activos de ese tipo: cambia
    # por completo como se calculan/muestran (serializado vs por cantidad) y
    # dejaria datos inconsistentes (ej. activos con stock_total pero sin serie).
    has_assets = db.query(Asset).filter(Asset.type_id == type_id).first() is not None
    if "kind" in data and has_assets and data["kind"] != t.kind:
        raise HTTPException(400, "No puedes cambiar el tipo (serializado/por cantidad) de una categoría que ya tiene activos")
    if "name" in data:
        name = str(data.get("name", "")).strip()
        if not name:
            raise HTTPException(400, "El nombre es obligatorio")
        t.name = name
    if "icon" in data:
        t.icon = str(data.get("icon", "other")) or "other"
    if "kind" in data and not has_assets:
        t.kind = data["kind"] if data["kind"] in ("serialized", "stock") else t.kind
    if "extra_fields" in data:
        t.extra_fields = data.get("extra_fields") or []
    if "linkable_type_id" in data:
        t.linkable_type_id = data.get("linkable_type_id") or None
    db.commit()
    return {"ok": True}

@router.delete("/types/{type_id}")
def delete_asset_type(type_id: str, user=Depends(require_permission("inventory", "manage")), db: Session = Depends(get_db)):
    if db.query(Asset).filter(Asset.type_id == type_id).first():
        raise HTTPException(400, "No puedes eliminar una categoría que todavía tiene activos registrados")
    t = db.query(AssetType).filter(AssetType.id == type_id).first()
    if not t:
        raise HTTPException(404, "Tipo no encontrado")
    db.delete(t)
    db.commit()
    return {"ok": True}

@router.post("/types/{type_id}/extra-field-option")
def add_extra_field_option(type_id: str, data: dict, user=Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    """Agrega una opción nueva a un campo tipo 'select' (ej. un operador
    nuevo que no estaba en la lista) sin tener que editar toda la categoría
    - se llama desde el mismo formulario de crear/editar activo."""
    t = db.query(AssetType).filter(AssetType.id == type_id).first()
    if not t:
        raise HTTPException(404, "Tipo no encontrado")
    field_key = data.get("field_key")
    option = str(data.get("option", "")).strip()
    if not (field_key and option):
        raise HTTPException(400, "Faltan datos")
    # Copia nueva (no in-place) porque SQLAlchemy no detecta mutaciones
    # dentro de una columna JSON existente - solo nota el cambio si el
    # objeto Python asignado es uno distinto al que ya tenia. flag_modified
    # de mas, por si acaso, para no volver a pisarme con esto.
    fields = [dict(f) for f in (t.extra_fields or [])]
    found = False
    for f in fields:
        if f.get("key") == field_key:
            opts = list(f.get("options") or [])
            if option not in opts:
                opts.append(option)
            f["options"] = opts
            found = True
            break
    if not found:
        raise HTTPException(404, "Campo no encontrado en esta categoría")
    t.extra_fields = fields
    flag_modified(t, "extra_fields")
    db.commit()
    return _fmt_asset_type(t)

# ── Activos ──────────────────────────────────────────────────────────────
def _fmt_asset(a: Asset, db: Session) -> dict:
    t = a.asset_type
    sede = a.sede
    assigned = db.query(User).filter(User.id == a.assigned_user).first() if a.assigned_user else None
    linked = db.query(Asset).filter(Asset.id == a.linked_asset_id).first() if a.linked_asset_id else None
    return {
        "id": a.id,
        "type_id": a.type_id,
        "type_name": t.name if t else "?",
        "type_icon": t.icon if t else "other",
        "type_kind": t.kind if t else "serialized",
        "name": a.name,
        "code": a.code,
        "status": a.status,
        "status_label": STATUS_LABELS.get(a.status, a.status),
        "sede_id": a.sede_id,
        "sede_name": sede.name if sede else None,
        "assigned_user": a.assigned_user,
        "assigned_user_name": assigned.name if assigned else None,
        "assigned_at": a.assigned_at.isoformat() if a.assigned_at else None,
        "purchase_date": a.purchase_date.isoformat() if a.purchase_date else None,
        "invoice_number": a.invoice_number,
        "notes": a.notes,
        "extra_data": a.extra_data or {},
        "linked_asset_id": a.linked_asset_id,
        "linked_asset_name": linked.name if linked else None,
        "stock_total": a.stock_total,
        "stock_assigned": a.stock_assigned,
        "stock_available": (a.stock_total - (a.stock_assigned or 0)) if a.stock_total is not None else None,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }

@router.get("")
def list_assets(
    type_id: str = Query(None), status: str = Query(None), sede_id: str = Query(None),
    assigned_user: str = Query(None), search: str = Query(None),
    user=Depends(require_permission("inventory", "view")), db: Session = Depends(get_db),
):
    q = db.query(Asset)
    if type_id: q = q.filter(Asset.type_id == type_id)
    if status: q = q.filter(Asset.status == status)
    if sede_id: q = q.filter(Asset.sede_id == sede_id)
    if assigned_user: q = q.filter(Asset.assigned_user == assigned_user)
    assets = q.order_by(Asset.name).all()
    result = [_fmt_asset(a, db) for a in assets]
    if search:
        s = search.lower()
        result = [r for r in result if s in (r["name"] or "").lower() or s in (r["code"] or "").lower()]
    return result

@router.get("/{asset_id}")
def get_asset(asset_id: str, user=Depends(require_permission("inventory", "view")), db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Activo no encontrado")
    out = _fmt_asset(a, db)
    rows = db.query(AssetAssignmentLog).filter(AssetAssignmentLog.asset_id == asset_id)\
             .order_by(desc(AssetAssignmentLog.assigned_at), desc(AssetAssignmentLog.created_at)).all()
    out["assignments"] = [{
        "id": r.id, "assigned_to": r.assigned_to, "assigned_to_name": r.assigned_to_name,
        "quantity": r.quantity, "returned_quantity": r.returned_quantity,
        "assigned_at": r.assigned_at.isoformat() if r.assigned_at else None,
        "delivery_notes": r.delivery_notes,
        "returned_at": r.returned_at.isoformat() if r.returned_at else None,
        "return_notes": r.return_notes,
        "changed_by": r.changed_by,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    } for r in rows]
    return out

@router.post("")
def create_asset(data: dict, user=Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    type_id = data.get("type_id")
    t = db.query(AssetType).filter(AssetType.id == type_id).first()
    if not t:
        raise HTTPException(400, "Tipo de activo inválido")
    name = str(data.get("name", "")).strip()
    if not name:
        raise HTTPException(400, "El nombre es obligatorio")
    status = data.get("status") if data.get("status") in STATUS_LABELS else "nuevo"

    a = Asset(
        type_id=type_id, name=name, code=(data.get("code") or None), status=status,
        sede_id=(data.get("sede_id") or None),
        purchase_date=_parse_date(data.get("purchase_date")),
        invoice_number=(data.get("invoice_number") or None),
        notes=(data.get("notes") or None),
        extra_data=data.get("extra_data") or {},
        linked_asset_id=(data.get("linked_asset_id") or None),
    )
    if t.kind == "stock":
        a.stock_total = int(data.get("stock_total") or 0)
        a.stock_assigned = 0
    db.add(a)
    db.commit()
    db.refresh(a)

    detail = f"Activo creado: {a.name} ({t.name})"
    if status == "baja":
        detail += " — dado de baja al registrarlo"
    _log_asset_event(db, a, "asset_created", detail, reason=data.get("reason") or None)
    db.commit()
    return _fmt_asset(a, db)

@router.put("/{asset_id}")
def update_asset(asset_id: str, data: dict, user=Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Activo no encontrado")

    old_status = a.status
    if "name" in data:
        name = str(data.get("name", "")).strip()
        if not name:
            raise HTTPException(400, "El nombre es obligatorio")
        a.name = name
    if "code" in data: a.code = data.get("code") or None
    if "sede_id" in data: a.sede_id = data.get("sede_id") or None
    if "purchase_date" in data: a.purchase_date = _parse_date(data.get("purchase_date"))
    if "invoice_number" in data: a.invoice_number = data.get("invoice_number") or None
    if "notes" in data: a.notes = data.get("notes") or None
    if "extra_data" in data: a.extra_data = data.get("extra_data") or {}
    if "linked_asset_id" in data:
        new_link = data.get("linked_asset_id") or None
        old_link = a.linked_asset_id
        if new_link != old_link:
            # El vinculo es una pareja real (celular <-> linea), no un puntero
            # de un solo lado - si no se sincroniza el otro extremo, ese otro
            # activo se ve "sin vincular" aunque este SI apunte a el.
            if old_link:
                prev = db.query(Asset).filter(Asset.id == old_link).first()
                if prev and prev.linked_asset_id == a.id:
                    prev.linked_asset_id = None
            a.linked_asset_id = new_link
            if new_link:
                linked = db.query(Asset).filter(Asset.id == new_link).first()
                if linked:
                    # si el nuevo activo ya estaba vinculado con un tercero,
                    # se rompe ese vinculo viejo tambien (uno-a-uno de verdad)
                    if linked.linked_asset_id and linked.linked_asset_id != a.id:
                        other = db.query(Asset).filter(Asset.id == linked.linked_asset_id).first()
                        if other and other.linked_asset_id == linked.id:
                            other.linked_asset_id = None
                    linked.linked_asset_id = a.id
                _log_asset_event(db, a, "asset_linked", f"Vinculado con: {linked.name if linked else new_link}")
            else:
                _log_asset_event(db, a, "asset_linked", "Se quitó el vínculo")
    if "status" in data and data["status"] in STATUS_LABELS and data["status"] != old_status:
        a.status = data["status"]
        _log_asset_event(
            db, a, "asset_status_changed",
            f"{a.name}: {STATUS_LABELS.get(old_status, old_status)} → {STATUS_LABELS.get(a.status, a.status)}",
            reason=data.get("reason") or None,
        )
        # Dar de baja o mandar a dañado limpia la asignación vigente - no
        # tiene sentido que siga figurando "asignado a X" un equipo de baja.
        if a.status in ("baja", "dañado") and a.assigned_user:
            a.assigned_user = None
            a.assigned_at = None
    db.commit()
    return _fmt_asset(a, db)

@router.delete("/{asset_id}")
def delete_asset(asset_id: str, user=Depends(require_permission("inventory", "manage")), db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Activo no encontrado")
    name = a.name
    # No se puede borrar un activo si otro esta vinculado a el (ej. una linea
    # que todavia tiene un celular apuntandole) - primero hay que desvincular.
    if db.query(Asset).filter(Asset.linked_asset_id == asset_id).first():
        raise HTTPException(400, "Hay otro activo vinculado a este — desvíncalo primero")
    db.query(Event).filter(Event.asset_id == asset_id).update({"asset_id": None})
    db.delete(a)
    db.commit()
    return {"ok": True, "name": name}

# ── Asignaciones (sirve tanto para serializado como para stock) ─────────────
@router.post("/{asset_id}/assignments")
def create_assignment(asset_id: str, data: dict, user=Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Activo no encontrado")
    t = a.asset_type
    assigned_to = data.get("assigned_to") or None
    name = data.get("assigned_to_name")
    if not name and assigned_to:
        u = db.query(User).filter(User.id == assigned_to).first()
        name = u.name if u else None
    assigned_at = _parse_date(data.get("assigned_at")) or datetime.utcnow().date()

    if t.kind == "stock":
        qty = int(data.get("quantity") or 1)
        available = (a.stock_total or 0) - (a.stock_assigned or 0)
        if qty <= 0:
            raise HTTPException(400, "La cantidad debe ser mayor a cero")
        if qty > available:
            raise HTTPException(400, f"Solo hay {available} disponibles")
        a.stock_assigned = (a.stock_assigned or 0) + qty
        rec = AssetAssignmentLog(
            asset_id=asset_id, assigned_to=assigned_to, assigned_to_name=name, quantity=qty,
            assigned_at=assigned_at, delivery_notes=data.get("delivery_notes") or None,
            changed_by=(user.name or user.email if user else None),
        )
        db.add(rec)
        _log_asset_event(db, a, "asset_assigned", f"{qty}x {a.name} asignado(s) a {name or 'desconocido'}")
    else:
        if not assigned_to:
            raise HTTPException(400, "Selecciona a quién se asigna")
        rec = AssetAssignmentLog(
            asset_id=asset_id, assigned_to=assigned_to, assigned_to_name=name, quantity=1,
            assigned_at=assigned_at, delivery_notes=data.get("delivery_notes") or None,
            changed_by=(user.name or user.email if user else None),
        )
        db.add(rec)
        a.assigned_user = assigned_to
        a.assigned_at = assigned_at
        a.status = "asignado"
        _log_asset_event(db, a, "asset_assigned", f"{a.name} asignado a {name or 'desconocido'}")
    db.commit()
    return {"ok": True}

@router.put("/{asset_id}/assignments/{record_id}")
def update_assignment(asset_id: str, record_id: int, data: dict, user=Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    """Se usa principalmente para "Devolver" - agrega fecha/observaciones de
    devolución (total o parcial, si es de stock) al registro ya abierto."""
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Activo no encontrado")
    rec = db.query(AssetAssignmentLog).filter(AssetAssignmentLog.id == record_id, AssetAssignmentLog.asset_id == asset_id).first()
    if not rec:
        raise HTTPException(404, "Registro no encontrado")
    t = a.asset_type

    if "return_quantity" in data or "returned_at" in data:
        return_qty = int(data.get("return_quantity") or (rec.quantity - rec.returned_quantity))
        open_qty = rec.quantity - rec.returned_quantity
        if return_qty <= 0 or return_qty > open_qty:
            raise HTTPException(400, f"Cantidad de devolución inválida (quedan {open_qty} sin devolver)")
        rec.returned_quantity = rec.returned_quantity + return_qty
        rec.return_notes = data.get("return_notes") or rec.return_notes
        if rec.returned_quantity >= rec.quantity:
            rec.returned_at = _parse_date(data.get("returned_at")) or datetime.utcnow().date()
        rec.changed_by = (user.name or user.email if user else None)

        if t.kind == "stock":
            a.stock_assigned = max(0, (a.stock_assigned or 0) - return_qty)
            _log_asset_event(db, a, "asset_returned", f"{return_qty}x {a.name} devuelto(s) por {rec.assigned_to_name or 'desconocido'}")
        else:
            a.assigned_user = None
            a.assigned_at = None
            if a.status == "asignado":
                a.status = "almacen"
            _log_asset_event(db, a, "asset_returned", f"{a.name} devuelto por {rec.assigned_to_name or 'desconocido'}")
    else:
        if "delivery_notes" in data: rec.delivery_notes = data.get("delivery_notes") or None
        rec.changed_by = (user.name or user.email if user else None)
    db.commit()
    return {"ok": True}

@router.delete("/{asset_id}/assignments/{record_id}")
def delete_assignment(asset_id: str, record_id: int, user=Depends(require_permission("inventory", "manage")), db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Activo no encontrado")
    rec = db.query(AssetAssignmentLog).filter(AssetAssignmentLog.id == record_id, AssetAssignmentLog.asset_id == asset_id).first()
    if not rec:
        raise HTTPException(404, "Registro no encontrado")
    t = a.asset_type
    open_qty = rec.quantity - rec.returned_quantity
    if t.kind == "stock":
        a.stock_assigned = max(0, (a.stock_assigned or 0) - open_qty)
    elif a.assigned_user == rec.assigned_to and not rec.returned_at:
        a.assigned_user = None
        a.assigned_at = None
        if a.status == "asignado":
            a.status = "almacen"
    db.delete(rec)
    db.commit()
    return {"ok": True}

# ── Stock: agregar unidades nuevas (compras) ────────────────────────────────
@router.post("/{asset_id}/stock/add")
def add_stock(asset_id: str, data: dict, user=Depends(require_permission("inventory", "edit")), db: Session = Depends(get_db)):
    a = db.query(Asset).filter(Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Activo no encontrado")
    if a.asset_type.kind != "stock":
        raise HTTPException(400, "Este activo no es de tipo 'por cantidad'")
    qty = int(data.get("quantity") or 0)
    if qty <= 0:
        raise HTTPException(400, "La cantidad debe ser mayor a cero")
    a.stock_total = (a.stock_total or 0) + qty
    _log_asset_event(db, a, "asset_stock_added", f"+{qty} {a.name} agregados al almacén", reason=data.get("notes") or None)
    db.commit()
    return _fmt_asset(a, db)

"""
Resolver DNS central con filtrado por equipo/área + registro de intentos +
página de bloqueo. Único punto de bloqueo del sistema: TODOS los agentes
(Linux y Windows) apuntan su DNS aquí, sin ningún bloqueo local propio.

  - Resuelve DNS aplicando la blocklist real de QUIEN pregunta (Global +
    Área + Equipo, con excepciones ya restadas), identificando al equipo por
    su IP de origen (la misma IP que reporta en /api/agents/metrics).
  - Si no reconoce la IP de origen (dispositivo que no es un agente
    SmartMonitor), aplica solo la blocklist GLOBAL como fallback seguro.
  - Dominios bloqueados -> responde con la IP del server (que sirve la
    página de bloqueo). Resto -> reenvía a un DNS real.
  - Registra cada intento (bloqueado, o "dejado pasar" por excepción/horario/
    red) en la tabla BlockAttempt, en batch, sin bloquear la resolución DNS.
"""

import os
import socket
import time
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from dnslib import DNSRecord, QTYPE, RR, A
from dnslib.server import BaseResolver, DNSServer

from core.db import Session
from models.models import Agent, BlockedSite
from routers.blocked_sites import resolve_domains_for_agent, resolve_all_configured_domains
from routers.block_schedules import _local_now
from routers.block_attempts import upsert_attempts


UPSTREAM_DNS = os.getenv("DNS_UPSTREAM", "1.1.1.1")
STATE_REFRESH_SEC = 15   # qué tan seguido se releen agentes/blocklist de la DB
ATTEMPT_FLUSH_SEC = 10   # qué tan seguido se vuelcan los intentos acumulados


def _detect_self_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


REDIRECT_IP = os.getenv("DNS_BLOCK_REDIRECT_IP", _detect_self_ip())


# ── Estado: mapa IP-de-equipo -> blocklist real de ESE equipo ───────────────
# Se recalcula cada STATE_REFRESH_SEC. Mientras tanto se sirve el último
# estado bueno conocido (si la DB falla momentáneamente, no se cae el
# bloqueo: se sigue filtrando con la última config válida).
_state_lock = threading.Lock()
_state = {"ts": 0.0, "by_ip": {}, "global_blocked": set(), "global_all": set()}


def _build_state():
    db = Session()
    try:
        active = db.query(BlockedSite).filter(BlockedSite.active == True).all()
        agents = db.query(Agent).filter(Agent.ip.isnot(None), Agent.ip != "").all()

        by_ip = {}
        for a in agents:
            # Si dos equipos comparten IP momentáneamente (DHCP cambiando),
            # nos quedamos con el visto más recientemente.
            by_ip[a.ip] = {
                "agent_id": a.id,
                "blocked": resolve_domains_for_agent(a, active),
                "all": resolve_all_configured_domains(a, active),
            }

        return {
            "ts": time.time(),
            "by_ip": by_ip,
            "global_blocked": resolve_domains_for_agent(None, active),
            "global_all": resolve_all_configured_domains(None, active),
        }
    finally:
        db.close()


def _get_state():
    with _state_lock:
        if time.time() - _state["ts"] > STATE_REFRESH_SEC:
            try:
                fresh = _build_state()
                _state.update(fresh)
            except Exception as e:
                print(f"[DNSBlocker] error recargando blocklist (se sigue usando la anterior): {e}")
        return _state


def _domain_matches(qname, domain_set):
    qname = qname.lower().rstrip(".")
    for d in domain_set:
        if qname == d or qname.endswith("." + d):
            return True
    return False


# ── Registro de intentos (batch, no bloquea la resolución DNS) ─────────────
_attempt_lock = threading.Lock()
_attempt_counts = {}  # (agent_id, domain, blocked) -> count


def _record_attempt(agent_id, domain, blocked):
    if not agent_id:
        return  # IP no reconocida como agente: no hay a quién atribuirlo
    with _attempt_lock:
        key = (agent_id, domain, blocked)
        _attempt_counts[key] = _attempt_counts.get(key, 0) + 1


def _flush_attempts():
    global _attempt_counts
    with _attempt_lock:
        if not _attempt_counts:
            return
        snapshot = _attempt_counts
        _attempt_counts = {}

    by_agent = {}
    for (agent_id, domain, blocked), count in snapshot.items():
        by_agent.setdefault(agent_id, []).append((domain, count, blocked))

    db = Session()
    failed = {}
    try:
        # Si un equipo fue borrado del panel entre que se registró el intento
        # y este flush, insertarlo violaría la FK y (si no se filtra antes)
        # tumbaría la transacción completa, reintentando para siempre y
        # bloqueando también los intentos válidos de los demás equipos. Se
        # descarta silenciosamente lo de agentes que ya no existen.
        existing_ids = {a for (a,) in db.query(Agent.id).filter(Agent.id.in_(by_agent.keys())).all()}
        now = _local_now(None)
        for agent_id, entries in by_agent.items():
            if agent_id not in existing_ids:
                print(f"[DNSBlocker] descartando {len(entries)} intento(s) de un agente que ya no existe ({agent_id})")
                continue
            try:
                upsert_attempts(db, agent_id, entries, now=now)
                db.commit()
            except Exception as e:
                db.rollback()
                print(f"[DNSBlocker] error guardando intentos del agente {agent_id}: {e}")
                failed[agent_id] = entries
    except Exception as e:
        print(f"[DNSBlocker] error guardando intentos de acceso: {e}")
        db.rollback()
        failed = by_agent
    finally:
        db.close()

    if failed:
        with _attempt_lock:
            for agent_id, entries in failed.items():
                for domain, count, blocked in entries:
                    key = (agent_id, domain, blocked)
                    _attempt_counts[key] = _attempt_counts.get(key, 0) + count


class BlockResolver(BaseResolver):
    def resolve(self, request, handler):
        try:
            qname = str(request.q.qname).rstrip(".")
            qtype = request.q.qtype
        except Exception:
            return request.reply()

        client_ip = None
        try:
            client_ip = handler.client_address[0]
        except Exception:
            pass

        state = _get_state()
        entry = state["by_ip"].get(client_ip) if client_ip else None
        if entry:
            blocked_set, all_set, agent_id = entry["blocked"], entry["all"], entry["agent_id"]
        else:
            # IP no asociada a ningún agente conocido: fallback seguro a la
            # blocklist global (no se pueden aplicar reglas de área/equipo
            # para un dispositivo que no sabemos quién es).
            blocked_set, all_set, agent_id = state["global_blocked"], state["global_all"], None

        qname_l = qname.lower()

        if _domain_matches(qname_l, blocked_set):
            _record_attempt(agent_id, qname_l, True)
            reply = request.reply()
            if qtype == QTYPE.A:
                reply.add_answer(RR(qname, QTYPE.A, ttl=30, rdata=A(REDIRECT_IP)))
            return reply

        # No bloqueado ahora mismo, pero si está en la config del equipo
        # (Global+Área+Equipo) es que una excepción/horario/red lo dejó
        # pasar: lo registramos igual para que quede visible en los reportes.
        if agent_id and _domain_matches(qname_l, all_set):
            _record_attempt(agent_id, qname_l, False)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(request.pack(), (UPSTREAM_DNS, 53))
            data, _ = sock.recvfrom(4096)
            sock.close()
            return DNSRecord.parse(data)
        except Exception:
            return request.reply()


BLOCK_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Acceso restringido</title>
<style>
body{
font-family:Segoe UI,Arial,sans-serif;
background:#0f172a;
color:#e2e8f0;
display:flex;
align-items:center;
justify-content:center;
height:100vh;
margin:0;
}
.box{
text-align:center;
max-width:440px;
padding:32px;
}
.icon{
font-size:40px;
margin-bottom:12px;
}
h1{
font-size:20px;
margin:0 0 8px;
}
p{
color:#94a3b8;
font-size:14px;
line-height:1.5;
}
</style>
</head>
<body>
<div class="box">
<div class="icon">&#128683;</div>
<h1>Acceso restringido</h1>
<p>
Este sitio ha sido bloqueado de acuerdo con las políticas de uso de la empresa.
<br>
Si consideras que esto es un error, contacta al administrador del sistema.
</p>
</div>
</body>
</html>
"""


class _BlockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(BLOCK_HTML.encode("utf-8"))

    def log_message(self, *args):
        pass


def _supervised(name, fn, restart_delay=5):
    """Corre fn() en loop: si truena por algo no controlado, lo loguea y lo
    reintenta en vez de dejar el hilo muerto en silencio (eso dejaría el
    bloqueo o el registro de intentos caídos sin que nadie se entere)."""
    while True:
        try:
            fn()
            return  # fn terminó por su cuenta (no debería pasar, pero no reintentamos en loop infinito si sí)
        except Exception as e:
            print(f"[DNSBlocker] {name} se cayó, reintentando en {restart_delay}s: {e}")
            time.sleep(restart_delay)


def _run_dns():
    server = DNSServer(BlockResolver(), address="0.0.0.0", port=53)
    print(f"[DNSBlocker] Resolver DNS iniciado. Redirigiendo a {REDIRECT_IP}")
    server.start()


def _run_block_page():
    # Enlazar a REDIRECT_IP (IP externa del server). No usamos solo 0.0.0.0:80
    # porque otro proceso puede ya ocupar 127.0.0.1:80 y fallaria el bind; asi
    # la pagina queda accesible para los clientes que resuelven el dominio
    # bloqueado a la IP del server.
    last_err = None
    for addr in ("0.0.0.0", REDIRECT_IP):
        try:
            httpd = HTTPServer((addr, 80), _BlockHandler)
            print(f"[DNSBlocker] Página de bloqueo iniciada en {addr}:80")
            httpd.serve_forever()
            return
        except Exception as e:
            last_err = e
            print(f"[DNSBlocker] No se pudo enlazar pagina en {addr}:80: {e}")
    if last_err:
        raise last_err


def _run_attempt_flusher():
    while True:
        time.sleep(ATTEMPT_FLUSH_SEC)
        _flush_attempts()


def start_dns_blocker():
    threading.Thread(target=_supervised, args=("Resolver DNS", _run_dns), daemon=True).start()
    threading.Thread(target=_supervised, args=("Página de bloqueo", _run_block_page), daemon=True).start()
    threading.Thread(target=_supervised, args=("Registro de intentos", _run_attempt_flusher), daemon=True).start()

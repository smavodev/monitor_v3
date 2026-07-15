"""
Resolver DNS central con filtrado por equipo/área + registro de intentos +
página de bloqueo (HTTP y HTTPS). Único punto de bloqueo del sistema: TODOS
los agentes (Linux y Windows) apuntan su DNS aquí, sin ningún bloqueo local
propio.

  - Resuelve DNS aplicando la blocklist real de QUIEN pregunta (Global +
    Área + Equipo, con excepciones ya restadas), identificando al equipo por
    su IP de origen (la misma IP que reporta en /api/agents/metrics).
  - Si no reconoce la IP de origen (dispositivo que no es un agente
    SmartMonitor), aplica solo la blocklist GLOBAL como fallback seguro.
  - Dominios bloqueados -> responde con la IP del server (que sirve la
    página de bloqueo). Resto -> reenvía a un DNS real.
  - Registra cada intento (bloqueado, o "dejado pasar" por excepción/horario/
    red) en la tabla BlockAttempt, en batch, sin bloquear la resolución DNS.
  - La página de bloqueo se sirve tanto en :80 (HTTP) como en :443 (HTTPS,
    con un certificado por dominio firmado al vuelo por la CA propia del
    server — ver tls_ca.py) para que también se muestre en sitios HTTPS.
    Los equipos deben confiar en esa CA (la instalan los agentes).
"""

import os
import socket
import ssl
import time
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

from dnslib import DNSRecord, QTYPE, RR, A
from dnslib.server import BaseResolver, DNSServer

from core.db import Session
from models.models import Agent, BlockedSite
from routers.blocked_sites import resolve_domains_for_agent, resolve_all_configured_domains
from routers.block_schedules import _local_now
from routers.block_attempts import upsert_attempts
import tls_ca


UPSTREAM_DNS = os.getenv("DNS_UPSTREAM", "1.1.1.1")
STATE_REFRESH_SEC = 15   # qué tan seguido se releen agentes/blocklist de la DB
ATTEMPT_FLUSH_SEC = 10   # qué tan seguido se vuelcan los intentos acumulados

# Puertos de la página de bloqueo, configurables: en despliegues donde el 443
# público lo atiende un proxy propio (ej. para enrutar por dominio hacia el
# panel admin con un certificado real), la página de bloqueo HTTPS se mueve a
# un puerto interno (ej. 127.0.0.1:9443) y el proxy la reenvía ahí para todo
# lo que no sea el dominio del panel. El HTTP (:80) NO se ve afectado por
# esto — nunca hay ambigüedad de a dónde enrutarlo, así que siempre sigue
# público, tenga o no el despliegue un proxy propio delante.
BLOCK_HTTP_PORT  = int(os.getenv("DNS_BLOCK_HTTP_PORT", "80"))
BLOCK_HTTPS_PORT = int(os.getenv("DNS_BLOCK_HTTPS_PORT", "443"))
BLOCK_HTTPS_BIND = os.getenv("DNS_BLOCK_HTTPS_BIND")  # si se define, la página HTTPS usa SOLO esta dirección (sin probar 0.0.0.0/REDIRECT_IP)


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
        # Ordenado por last_seen ascendente: si dos equipos comparten IP
        # (mismo router/NAT), el bucle de abajo va pisando by_ip[ip] en este
        # orden, así que el último en escribir —y el que queda vigente— es
        # el visto más recientemente (antes no había order_by y el que
        # ganaba el empate era arbitrario).
        agents = db.query(Agent).filter(Agent.ip.isnot(None), Agent.ip != "")\
                    .order_by(Agent.last_seen.asc()).all()

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


CA_CERT_PATH = "/smartmonitor-ca.crt"  # ruta fija para que el agente la descargue e instale

# Dominio propio del panel admin (ej. monitoreo.smarthrlatam.com), si el
# despliegue tiene uno (ver DNS_BLOCK_HTTPS_BIND / nginx SNI en EC2). Una
# petición HTTP (:80, sin cifrar) a ese Host se redirige a HTTPS en vez de
# mostrar la página de bloqueo — si no, entrar por http:// al dominio del
# panel (en vez de https://) mostraría el bloqueo por error, ya que el :80
# no distingue de quién es la solicitud, solo bloquea.
ADMIN_PANEL_DOMAIN = os.getenv("ADMIN_PANEL_DOMAIN")


class _BlockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == CA_CERT_PATH:
            self.send_response(200)
            self.send_header("Content-Type", "application/x-x509-ca-cert")
            self.send_header("Content-Disposition", "attachment; filename=smartmonitor-ca.crt")
            self.end_headers()
            self.wfile.write(tls_ca.ca_cert_pem())
            return
        host = (self.headers.get("Host") or "").split(":")[0].strip().lower()
        if ADMIN_PANEL_DOMAIN and host == ADMIN_PANEL_DOMAIN.lower():
            self.send_response(301)
            self.send_header("Location", f"https://{ADMIN_PANEL_DOMAIN}{self.path}")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(BLOCK_HTML.encode("utf-8"))

    def log_message(self, *args):
        pass


class _TLSHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTPServer que envuelve cada conexión aceptada en TLS, eligiendo el
    certificado según el SNI (nombre de dominio) que pide el navegador —
    así un mismo puerto 443 sirve un certificado distinto por cada dominio
    bloqueado, firmado al vuelo por la CA propia (ver tls_ca.py)."""
    daemon_threads = True

    def __init__(self, server_address, handler_cls):
        super().__init__(server_address, handler_cls)
        # Contexto "por defecto" antes de que el callback de SNI elija el real
        # (el handshake TLS exige tener algún certificado cargado de entrada).
        self._base_ctx = tls_ca.get_context_for_host(None)
        self._base_ctx.sni_callback = self._on_sni

    @staticmethod
    def _on_sni(ssl_sock, server_name, ssl_ctx):
        try:
            ssl_sock.context = tls_ca.get_context_for_host(server_name)
        except Exception as e:
            print(f"[DNSBlocker] error generando certificado para SNI={server_name!r}: {e}")

    def get_request(self):
        sock, addr = super().get_request()
        ssl_sock = self._base_ctx.wrap_socket(sock, server_side=True)
        return ssl_sock, addr


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
    # Enlazar a REDIRECT_IP (IP externa del server). No usamos solo 0.0.0.0
    # porque otro proceso puede ya ocupar 127.0.0.1 y fallaria el bind; asi
    # la pagina queda accesible para los clientes que resuelven el dominio
    # bloqueado a la IP del server. Siempre público — a diferencia del HTTPS,
    # aquí no hay ambigüedad de dominio que justifique moverlo detrás de un
    # proxy propio.
    last_err = None
    for addr in ("0.0.0.0", REDIRECT_IP):
        try:
            httpd = HTTPServer((addr, BLOCK_HTTP_PORT), _BlockHandler)
            print(f"[DNSBlocker] Página de bloqueo iniciada en {addr}:{BLOCK_HTTP_PORT}")
            httpd.serve_forever()
            return
        except Exception as e:
            last_err = e
            print(f"[DNSBlocker] No se pudo enlazar pagina en {addr}:{BLOCK_HTTP_PORT}: {e}")
    if last_err:
        raise last_err


def _run_block_page_tls():
    # Misma lógica de bind que _run_block_page, pero con TLS: el certificado
    # se elige por SNI (ver _TLSHTTPServer / tls_ca.py). Si DNS_BLOCK_HTTPS_BIND
    # está definido (despliegues detrás de un proxy propio que enruta por SNI,
    # ej. EC2 con dominio propio para el panel), se usa solo esa dirección en
    # vez del bind público habitual.
    last_err = None
    for addr in (BLOCK_HTTPS_BIND,) if BLOCK_HTTPS_BIND else ("0.0.0.0", REDIRECT_IP):
        try:
            httpd = _TLSHTTPServer((addr, BLOCK_HTTPS_PORT), _BlockHandler)
            print(f"[DNSBlocker] Página de bloqueo (HTTPS) iniciada en {addr}:{BLOCK_HTTPS_PORT}")
            httpd.serve_forever()
            return
        except Exception as e:
            last_err = e
            print(f"[DNSBlocker] No se pudo enlazar pagina HTTPS en {addr}:{BLOCK_HTTPS_PORT}: {e}")
    if last_err:
        raise last_err


def _run_attempt_flusher():
    while True:
        time.sleep(ATTEMPT_FLUSH_SEC)
        _flush_attempts()


def start_dns_blocker():
    tls_ca.ensure_ca()
    threading.Thread(target=_supervised, args=("Resolver DNS", _run_dns), daemon=True).start()
    threading.Thread(target=_supervised, args=("Página de bloqueo", _run_block_page), daemon=True).start()
    threading.Thread(target=_supervised, args=("Página de bloqueo HTTPS", _run_block_page_tls), daemon=True).start()
    threading.Thread(target=_supervised, args=("Registro de intentos", _run_attempt_flusher), daemon=True).start()

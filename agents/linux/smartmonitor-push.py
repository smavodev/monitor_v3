#!/usr/bin/env python3
"""SmartMonitor v3 - Agente Linux (push de métricas reales)"""
import sys; sys.dont_write_bytecode = True
import subprocess, json, re, os, time, urllib.request, urllib.parse, hashlib

SERVER    = "http://172.27.142.107:8000"   # ← IP del servidor SmartMonitor
HOSTNAME  = os.uname().nodename           # ← auto-detecta el hostname del equipo
AGENT_DIR = os.path.dirname(os.path.abspath(__file__))  # ← carpeta donde vive este .py
SW_HASH_CACHE = f"{AGENT_DIR}/.sw_hash"

# IP unica del equipo dentro del tunel WireGuard (Headscale), si esta
# conectado. None hasta que setup_wireguard_tunnel() lo resuelva. Se manda en
# cada send_once() para que dns_blocker.py identifique a este equipo sin
# depender de la IP publica compartida de la oficina.
tailnet_ip = None
tailnet_server_ip = None

def get_wifi_ssid():
    """SSID de la red WiFi actual, o None si está por cable / sin WiFi detectable."""
    try:
        out = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True, timeout=3)
        ssid = out.stdout.strip()
        if ssid:
            return ssid
    except Exception:
        pass
    try:
        out = subprocess.run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                              capture_output=True, text=True, timeout=3)
        for line in out.stdout.splitlines():
            if line.startswith("yes:"):
                ssid = line.split(":", 1)[1].strip()
                if ssid:
                    return ssid
    except Exception:
        pass
    return None

def get_blocklist():
    try:
        ssid = urllib.parse.quote(get_wifi_ssid() or "")
        # El hostname puede repetirse entre equipos distintos (clonación,
        # error humano); mandar el serial deja que el server identifique a
        # este equipo sin ambigüedad si hay otro con el mismo nombre.
        serial = urllib.parse.quote(hw.get("serial_number", "") or "")
        r = urllib.request.urlopen(
            f"{SERVER}/api/agents/blocklist?hostname={HOSTNAME}&ssid={ssid}&serial={serial}", timeout=5)
        j = json.loads(r.read())
        all_domains = j.get("all_domains", [])
        should_block = j.get("should_block", True)
        return should_block, all_domains
    except:
        return None, None

# ── Modo centralizado (Fase 1 + 2): el server filtra el DNS ──────────────────
# El agente ya no hace sinkhole/hosts local: apunta el DNS del equipo al server,
# que aplica la blocklist centralmente. Para vencer DoH (Fase 2) desactiva el
# "Secure DNS" del navegador y bloquea los endpoints DoH en el firewall.

RESOLV_CONF = "/etc/resolv.conf"
CENTRAL_DNS_MARKER = "# SmartMonitor CENTRAL DNS"
DOH_IPS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"]

def _server_dns_ip():
    # Si el tunel WireGuard esta activo, el DNS se apunta a la IP del server
    # DENTRO del tunel (unica de verdad) en vez de la IP publica compartida
    # de la oficina - asi dns_blocker.py identifica a este equipo sin
    # ambiguedad. Si el tunel no esta disponible, se cae al comportamiento
    # de siempre (IP publica) sin que el bloqueo deje de funcionar.
    if tailnet_ip and tailnet_server_ip:
        return tailnet_server_ip
    m = re.search(r"https?://([^:/]+)", SERVER)
    return m.group(1) if m else SERVER

def get_tailscale_ip():
    try:
        if not sh("command -v tailscale"):
            return None
        out = sh("tailscale ip -4").strip()
        return out or None
    except Exception:
        return None

def setup_wireguard_tunnel():
    """Registra este equipo en el tunel WireGuard (Headscale) si todavia no
    lo esta. No es indispensable para que el agente funcione: si esto falla
    o tailscale no esta instalado, el bloqueo sigue funcionando igual que
    siempre por la IP publica (ver _server_dns_ip)."""
    global tailnet_ip, tailnet_server_ip
    try:
        if not sh("command -v tailscale"):
            return
        existing_ip = get_tailscale_ip()
        if existing_ip:
            tailnet_ip = existing_ip
            if not tailnet_server_ip:
                try:
                    body = json.dumps({"hostname": HOSTNAME}).encode()
                    req = urllib.request.Request(
                        f"{SERVER}/api/agents/wireguard/preauthkey",
                        data=body, headers={"Content-Type": "application/json"}, method="POST")
                    reg = json.loads(urllib.request.urlopen(req, timeout=10).read())
                    tailnet_server_ip = reg.get("server_tailnet_ip")
                except Exception:
                    pass
            return
        print("WireGuard: sin conectar, pidiendo pre-auth key al servidor...")
        body = json.dumps({"hostname": HOSTNAME}).encode()
        req = urllib.request.Request(
            f"{SERVER}/api/agents/wireguard/preauthkey",
            data=body, headers={"Content-Type": "application/json"}, method="POST")
        reg = json.loads(urllib.request.urlopen(req, timeout=10).read())
        tailnet_server_ip = reg.get("server_tailnet_ip")
        sh(f"tailscale up --login-server={reg['login_server']} --authkey={reg['authkey']} "
           f"--hostname={HOSTNAME} --accept-dns=false --reset --timeout=30s")
        time.sleep(3)
        tailnet_ip = get_tailscale_ip()
        if tailnet_ip:
            print(f"WireGuard: conectado, IP={tailnet_ip} (server={tailnet_server_ip})")
        else:
            print("WARN: WireGuard no conecto (reintenta solo)")
    except Exception as e:
        print(f"WARN: no se pudo configurar WireGuard: {e}")

def _nm_active_connections():
    """Nombres de las conexiones activas de NetworkManager (una por interfaz
    con red real; se listan aparte las de docker/bridges que no aplican)."""
    if not (sh("command -v nmcli") and sh("systemctl is-active NetworkManager") == "active"):
        return []
    out = sh("nmcli -t -f NAME,DEVICE connection show --active")
    names = []
    for line in out.splitlines():
        if not line.strip():
            continue
        name, _, device = line.partition(":")
        if device and not device.startswith(("docker", "br-", "veth", "lo")):
            names.append(name)
    return names

def set_central_dns():
    ip = _server_dns_ip()
    conns = _nm_active_connections()
    if conns:
        # Con NetworkManager activo, editar /etc/resolv.conf a mano es una
        # pelea perdida: NM lo regenera y, peor, si no se limpia bien lo
        # anterior en cada ciclo (como pasaba antes) el archivo acumula
        # nameservers duplicados hasta que el nuestro queda más allá del
        # límite de 3 que usa glibc y nunca se llega a usar. nmcli es la
        # forma correcta de fijar el DNS por conexión, y ya es idempotente
        # (no reconecta si el valor no cambió).
        for name in conns:
            current = sh(f'nmcli -g ipv4.dns connection show "{name}"').strip()
            if current == ip:
                continue
            sh(f'nmcli connection modify "{name}" ipv4.dns "{ip}" ipv4.ignore-auto-dns yes '
               f'ipv6.ignore-auto-dns yes 2>/dev/null')
            sh(f'nmcli connection up "{name}" 2>/dev/null')
        return
    try:
        if sh("command -v resolvectl") or sh("command -v systemd-resolve"):
            sh(f"resolvectl dns * {ip} 2>/dev/null")
            sh("resolvectl domain * ~. 2>/dev/null")
            return
    except Exception:
        pass
    try:
        lines = []
        if os.path.exists(RESOLV_CONF):
            with open(RESOLV_CONF) as f:
                # Se descarta CUALQUIER nameserver previo (no solo el marcador
                # o 127.0.0.1): si no, cada ciclo de 10s acumula uno más hasta
                # superar el límite de 3 nameservers de glibc y el nuestro
                # nunca llega a usarse de verdad.
                lines = [l for l in f.read().splitlines()
                         if l.strip() != CENTRAL_DNS_MARKER and not l.strip().startswith("nameserver")]
        lines.insert(0, CENTRAL_DNS_MARKER)
        lines.insert(1, f"nameserver {ip}")
        with open(RESOLV_CONF, "w") as f:
            f.write("\n".join(lines) + "\n")
    except Exception as e:
        print(f"WARN: no se pudo apuntar el DNS al server: {e}")

def restore_dns_central():
    conns = _nm_active_connections()
    if conns:
        for name in conns:
            current = sh(f'nmcli -g ipv4.dns connection show "{name}"').strip()
            if not current:
                continue
            sh(f'nmcli connection modify "{name}" ipv4.dns "" ipv4.ignore-auto-dns no '
               f'ipv6.ignore-auto-dns no 2>/dev/null')
            sh(f'nmcli connection up "{name}" 2>/dev/null')
        return
    try:
        if sh("command -v resolvectl") or sh("command -v systemd-resolve"):
            sh("resolvectl revert * 2>/dev/null")
    except Exception:
        pass
    try:
        if os.path.exists(RESOLV_CONF):
            with open(RESOLV_CONF) as f:
                lines = [l for l in f.read().splitlines() if l.strip() != CENTRAL_DNS_MARKER]
            with open(RESOLV_CONF, "w") as f:
                f.write("\n".join(lines) + "\n")
    except Exception:
        pass

# Fase 2: cerrar la via de DoH para que el DNS central se use de verdad
def _write_doh_policy(base):
    try:
        os.makedirs(base, exist_ok=True)
        path = os.path.join(base, "policies.json")
        data = '{"policies":{"DNSOverHTTPS":{"Enabled":false,"Locked":true}}}'
        with open(path, "w") as f:
            f.write(data)
    except Exception:
        pass

def disable_browser_doh_linux():
    # Cubre los navegadores mas comunes, incl. Brave (que usa su propia ruta de
    # politicas y NO la de Chrome), para que no usen DoH y se vean forzados a
    # usar el DNS centralizado del server (si lo usaran, las reglas iptables de
    # block_doh_endpoints los bloquearian y el navegador quedaria sin internet).
    for base in ("/etc/chromium/policies/managed", "/etc/opt/chrome/policies/managed",
                 "/etc/brave/policies/managed", "/opt/brave/policies/managed",
                 "/usr/lib/brave/policies/managed",
                 "/usr/lib/firefox/distribution", "/usr/lib64/firefox/distribution",
                 "/opt/firefox/distribution"):
        _write_doh_policy(base)

def block_doh_endpoints_linux():
    try:
        for ip in DOH_IPS:
            sh(f"iptables -D OUTPUT -d {ip} -j DROP 2>/dev/null")
            sh(f"iptables -A OUTPUT -d {ip} -j DROP 2>/dev/null")
            sh(f"nft add rule inet filter output ip daddr {ip} drop 2>/dev/null")
    except Exception as e:
        print(f"WARN: no se pudo bloquear endpoints DoH: {e}")

def sh(cmd, default=""):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           env={**os.environ, "LC_ALL":"C", "LANG":"C"})
        return r.stdout.strip()
    except:
        return default

def read_cpu():
    with open("/proc/stat") as f:
        parts = f.readline().split()
    return int(parts[4]), sum(int(x) for x in parts[1:8])

def _get_ram_slots():
    """Devuelve (slots_usados, slots_totales). Requiere root para dmidecode."""
    try:
        r = subprocess.run(
            ["dmidecode", "-t", "memory"],
            capture_output=True, text=True,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"}
        )
        if r.returncode != 0 or "Permission denied" in r.stderr:
            return 0, 0
        blocks = r.stdout.split("Memory Device")
        total = len(blocks) - 1  # primer bloque es cabecera
        used  = sum(
            1 for b in blocks[1:]
            if "Size:" in b
            and "No Module Installed" not in b
            and "Not Installed" not in b
            and b.split("Size:")[1].split("\n")[0].strip() not in ("Unknown", "0", "")
        )
        return used, total
    except Exception:
        return 0, 0

def get_installed_software():
    """Retorna lista de {name, version} usando el gestor de paquetes disponible."""
    # Debian / Ubuntu / Parrot / Kali
    out = sh("dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null")
    if out:
        pkgs = []
        for line in out.splitlines():
            parts = line.split('\t', 1)
            if len(parts) == 2 and parts[0]:
                pkgs.append({"name": parts[0], "version": parts[1]})
        return sorted(pkgs, key=lambda x: x['name'].lower())
    # RPM (Fedora / CentOS / RHEL)
    out = sh("rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null")
    if out:
        pkgs = []
        for line in out.splitlines():
            parts = line.split('\t', 1)
            if len(parts) == 2 and parts[0]:
                pkgs.append({"name": parts[0], "version": parts[1]})
        return sorted(pkgs, key=lambda x: x['name'].lower())
    # Arch / Manjaro
    out = sh("pacman -Q 2>/dev/null")
    if out:
        pkgs = []
        for line in out.splitlines():
            parts = line.split(' ', 1)
            if len(parts) == 2:
                pkgs.append({"name": parts[0], "version": parts[1]})
        return sorted(pkgs, key=lambda x: x['name'].lower())
    return []

def get_device_type():
    """Detecta si es Laptop / Desktop / Tablet / Other usando el chassis DMI,
    la presencia de batería y, como último recurso, hostnamectl."""
    ct = None
    try:
        t = open("/sys/class/dmi/id/chassis_type").read().strip()
        if t.isdigit():
            ct = int(t)
    except Exception:
        pass

    LAPTOP = {8, 9, 10, 11, 14, 31, 32}
    TABLET = {30}
    DESKTOP = {3, 4, 5, 6, 7, 13, 15, 16, 17, 23, 24, 34, 35, 36}

    if ct in TABLET:
        return "Tablet"
    if ct in LAPTOP:
        return "Laptop"
    if ct in DESKTOP:
        return "Desktop"

    # Refuerzo: si tiene batería, es portátil.
    try:
        if os.path.exists("/sys/class/power_supply") and \
           any(n.startswith("BAT") for n in os.listdir("/sys/class/power_supply")):
            return "Laptop"
    except Exception:
        pass

    # hostnamectl como último recurso
    try:
        out = sh("hostnamectl 2>/dev/null | grep -i chassis")
        val = out.split(":", 1)[1].strip().lower() if ":" in out else ""
        if val in ("tablet",):
            return "Tablet"
        if val in ("laptop", "notebook", "convertible", "detachable", "handset", "handheld"):
            return "Laptop"
        if val in ("desktop", "tower", "all-in-one", "allinone", "server", "mini"):
            return "Desktop"
    except Exception:
        pass

    # Sin información concluyente: sin batería ni chassis de portátil, lo más
    # probable es una PC/escritorio.
    return "Desktop"

def physical_ram_gb(usable_gb):
    """Redondea al tamaño comercial de RAM más cercano (4,8,12,16,20,24,32,64...)"""
    standards = [1,2,3,4,6,8,10,12,16,20,24,32,48,64,96,128,192,256]
    for s in standards:
        if usable_gb <= s + 0.5:
            return s
    return round(usable_gb)

# ── Hardware (cachea en /tmp para no re-leer cada push) ──────────────────
CACHE_FILE = "/tmp/sm_hw.json"
hw = {}
if not os.path.exists(CACHE_FILE):
    try:
        hw["manufacturer"] = open("/sys/class/dmi/id/sys_vendor").read().strip()
        hw["model"]        = open("/sys/class/dmi/id/product_version").read().strip() \
                             + " (" + open("/sys/class/dmi/id/product_name").read().strip() + ")"
    except:
        hw["manufacturer"] = hw["model"] = ""
    hw["cpu_model"] = sh("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'")
    hw["cpu_cores"] = int(sh("nproc", "0") or 0)

    serial = ""
    try:
        s = open("/sys/class/dmi/id/product_serial").read().strip()
        if s and s not in ("None", "Default string", "To Be Filled By O.E.M.", ""):
            serial = s
    except: pass
    hw["serial_number"] = serial

    slots_total, slots_used = _get_ram_slots()
    hw["ram_slots_total"]  = slots_total
    hw["ram_slots_used"]   = slots_used
    hw["ram_slots_detail"] = []

    with open(CACHE_FILE, "w") as f:
        json.dump(hw, f)
else:
    with open(CACHE_FILE) as f:
        hw = json.load(f)

# device_type se re-detecta en cada arranque: el caché puede venir de una
# versión anterior del agente que no lo incluía, y además es barato.
hw["device_type"] = get_device_type()

def get_interval():
    try:
        r = urllib.request.urlopen(f"{SERVER}/api/config/interval", timeout=3)
        cfg = json.loads(r.read())
        return max(3, int(cfg.get("interval", 5))), max(3, int(cfg.get("blocklist_interval", 10)))
    except:
        return 5, 10

def send_once():
    # ── Procesos top (agrupados por nombre) ──────────────────────────────
    seen_p = {}
    for line in sh("ps aux --no-headers --sort=-%cpu | grep -vE '\\[|ps |grep' | head -200").splitlines():
        parts = line.split(None, 10)
        if len(parts) < 11: continue
        name = re.sub(r'.*/','', parts[10].split()[0])
        name = re.sub(r'[^a-zA-Z0-9_\-\.]', '', name)[:20]
        if not name: continue
        cpu_p, mem_p = float(parts[2]), float(parts[3])
        if name in seen_p:
            seen_p[name]["cpu"] = round(seen_p[name]["cpu"] + cpu_p, 1)
            seen_p[name]["mem"] = round(seen_p[name]["mem"] + mem_p, 1)
        else:
            seen_p[name] = {"name": name, "cpu": cpu_p, "mem": mem_p}
    procs = sorted(seen_p.values(), key=lambda x: -x["cpu"])[:100]

    # ── RAM ───────────────────────────────────────────────────────────────
    meminfo = {}
    for line in open("/proc/meminfo"):
        k, v = line.split(":")
        meminfo[k.strip()] = int(v.strip().split()[0])
    ram_total_mb = meminfo["MemTotal"]
    ram_avail_mb = meminfo["MemAvailable"]
    ram_used_mb  = ram_total_mb - ram_avail_mb
    ram_usable_gb = round(ram_total_mb / 1024 / 1024, 2)
    ram_total_gb  = physical_ram_gb(ram_usable_gb)
    ram_used_gb   = round(ram_used_mb / 1024 / 1024, 2)
    ram_pct       = round(ram_used_mb / ram_total_mb * 100, 1)

    # ── CPU ───────────────────────────────────────────────────────────────
    idle1, tot1 = read_cpu()
    time.sleep(1)
    idle2, tot2 = read_cpu()
    cpu_pct = round((1 - (idle2-idle1) / max(tot2-tot1, 1)) * 100, 1)

    # ── Disco ─────────────────────────────────────────────────────────────
    dk = sh("df / | awk 'NR==2{gsub(\"%\",\"\",$5); printf \"%s %s %s\",$2,$3,$5}'").split()
    disk_pct = float(dk[2]) if len(dk) >= 3 else 0.0

    disks, seen = [], set()
    for line in sh("df -x tmpfs -x devtmpfs -x overlay --output=source,target,size,used,pcent 2>/dev/null | tail -n +2").splitlines():
        p = line.split()
        if len(p) < 5: continue
        dev, mnt = p[0], p[1]
        tgb = round(int(p[2]) / 1024 / 1024, 1)
        ugb = round(int(p[3]) / 1024 / 1024, 1)
        pct = float(p[4].rstrip('%'))
        if tgb < 0.1 or dev in seen: continue
        seen.add(dev)
        disks.append({"device": dev, "mountpoint": mnt, "total_gb": tgb, "used_gb": ugb, "percent": pct})

    # ── Red ───────────────────────────────────────────────────────────────
    net_dev = sh("ip route | grep default | awk '{print $5}' | head -1")
    rx_mb = tx_mb = 0.0
    if net_dev:
        try:
            rx_mb = round(int(open(f"/sys/class/net/{net_dev}/statistics/rx_bytes").read()) / 1024 / 1024, 1)
            tx_mb = round(int(open(f"/sys/class/net/{net_dev}/statistics/tx_bytes").read()) / 1024 / 1024, 1)
        except: pass

    # ── Temperatura ───────────────────────────────────────────────────────
    cpu_temp = None
    for zone in sorted(os.listdir("/sys/class/thermal/")):
        if "thermal_zone" in zone:
            try:
                t = int(open(f"/sys/class/thermal/{zone}/temp").read()) / 1000
                if t > 25: cpu_temp = round(t, 1); break
            except: pass

    # ── Software instalado (solo si cambió) ──────────────────────────────
    installed_software = []
    sw_list = get_installed_software()
    sw_hash = hashlib.md5(json.dumps(sw_list, sort_keys=True).encode()).hexdigest()
    prev_hash = open(SW_HASH_CACHE).read().strip() if os.path.exists(SW_HASH_CACHE) else ""
    if sw_hash != prev_hash:
        installed_software = sw_list
        with open(SW_HASH_CACHE, 'w') as f:
            f.write(sw_hash)

    payload = {
        "hostname":           HOSTNAME,
        "os":                 "parrot",
        "os_version":         "7.3",
        "manufacturer":       hw.get("manufacturer", ""),
        "model":              hw.get("model", ""),
        "serial_number":      hw.get("serial_number", ""),
        "cpu_model":          hw.get("cpu_model", ""),
        "cpu_cores":          hw.get("cpu_cores", 0),
        "ram_slots_total":    hw.get("ram_slots_total") or None,
        "ram_slots_used":     hw.get("ram_slots_used") or None,
        "ram_slots_detail":   hw.get("ram_slots_detail") or [],
        "ram_total_gb":       ram_total_gb,
        "cpu_percent":        cpu_pct,
        "ram_percent":        ram_pct,
        "ram_used_gb":        ram_used_gb,
        "disk_percent":       disk_pct,
        "net_rx_mb":          rx_mb,
        "net_tx_mb":          tx_mb,
        "cpu_temp":           cpu_temp,
        "latency_ms":         None,
        "disks":              disks,
        "top_processes":      procs,
        "installed_software": installed_software,
        "device_type":        hw.get("device_type", ""),
        "tailnet_ip":         tailnet_ip,
    }
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        f"{SERVER}/api/agents/metrics",
        data=data, headers={"Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(req, timeout=5)

# ── Loop principal ────────────────────────────────────────────────────────
# El bloqueo (dominios/excepciones/horario/red) se revisa cada BLOCKLIST_POLL_SEC,
# independiente del intervalo de métricas — así una excepción que agregas o
# quitas se refleja rápido sin esperar el intervalo (que puede ser de varios
# minutos) configurado para el reporte de métricas. Ambos son configurables
# por separado desde el servidor (Configuración), sin tocar este archivo.
BLOCKLIST_POLL_SEC = 10

# Server y hostname bien visibles al arrancar: si el agente alguna vez queda
# apuntando al servidor equivocado (ej. una reinstalación que no reemplazó el
# archivo de verdad, como pasó una vez), esto lo delata de inmediato con
# 'journalctl -u smartmonitor-agent' sin tener que diagnosticar por SSH
# cuánto tráfico llega a cada server.
print(f"Servidor configurado: {SERVER} | Hostname: {HOSTNAME}")

# Fase 2: cerrar la via de DoH para que el DNS central se use de verdad
disable_browser_doh_linux()
block_doh_endpoints_linux()

# Intento inicial de conectar el tunel WireGuard (no bloqueante: si falla,
# el agente sigue funcionando por IP publica igual que siempre)
setup_wireguard_tunnel()

interval, BLOCKLIST_POLL_SEC = get_interval()
last_metrics = 0.0
last_wireguard_retry = time.time()
while True:
    try:
        now_t = time.time()
        if now_t - last_metrics >= interval:
            send_once()
            interval, BLOCKLIST_POLL_SEC = get_interval()
            last_metrics = time.time()
        # Se revalida en CADA ciclo si el tunel sigue realmente vivo (no solo
        # una vez al conectar): si Tailscale se cae despues de haber estado
        # conectado, tailnet_ip quedaba en un valor viejo para siempre, y el
        # agente seguia apuntando el DNS a una IP del tunel que ya no
        # respondia -> el equipo terminaba usando otro DNS sin filtrar y el
        # bloqueo se saltaba por completo.
        tailnet_ip = get_tailscale_ip()

        # Reintenta conectar el tunel WireGuard cada ~60s si todavia no lo
        # logro (ej. tailscaled tardo en arrancar, se cayo, o el server no
        # tenia Headscale configurado en ese momento).
        if not tailnet_ip and time.time() - last_wireguard_retry >= 60:
            setup_wireguard_tunnel()
            last_wireguard_retry = time.time()
        should_block, all_domains = get_blocklist()
        if should_block is not None:
            all_domains = all_domains or []
            if should_block and all_domains:
                set_central_dns()
                print("BLOCKLIST modo=DNS-central (el server filtra)")
            else:
                restore_dns_central()
                print("BLOCKLIST modo=off")
        else:
            print("BLOCKLIST sin respuesta del servidor (None)")
    except Exception as e:
        import sys; print(f"Error: {e}", file=sys.stderr)
    time.sleep(BLOCKLIST_POLL_SEC)

#!/usr/bin/env python3
"""SmartMonitor v3 - Agente Linux (push de métricas reales)"""
import sys; sys.dont_write_bytecode = True
import subprocess, json, re, os, time, urllib.request, urllib.parse, hashlib, threading

SERVER    = "http://monitoreo.smarthrlatam.com:8000"   # ← valor real por defecto (mismo que SMARTMONITOR_DEFAULT_SERVER_IP en install-agent-linux.sh). Antes era un placeholder que el instalador reemplazaba - un despliegue manual (copiar este .py directo, sin pasar por el instalador) lo dejaba roto con el texto literal del placeholder, sin resolver DNS. install-agent-linux.sh igual lo puede pisar con otro server via "sed -i s|^SERVER...|" si hace falta apuntar a otro.
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
    """(nombre, interfaz) de las conexiones activas de NetworkManager (una por
    interfaz con red real; se listan aparte las de docker/bridges que no
    aplican). Se necesita la interfaz ademas del nombre para poder aplicar
    cambios de DNS sin reconectar (ver set_central_dns/restore_dns_central) -
    "nmcli device reapply" pide el nombre de la interfaz, no el de la
    conexion (pueden diferir, ej. una conexion "INDIGITAL 2.4G" sobre la
    interfaz "wlp1s0")."""
    if not (sh("command -v nmcli") and sh("systemctl is-active NetworkManager") == "active"):
        return []
    out = sh("nmcli -t -f NAME,DEVICE connection show --active")
    conns = []
    for line in out.splitlines():
        if not line.strip():
            continue
        name, _, device = line.partition(":")
        if device and not device.startswith(("docker", "br-", "veth", "lo")):
            conns.append((name, device))
    return conns

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
        #
        # Bug real reportado (LAP-ISAAVEDRA): "nmcli connection up" NO solo
        # aplica el cambio de config - fuerza una reactivacion real de la
        # conexion (baja y vuelve a subir), que en wifi es una desconexion/
        # reconexion de verdad, de unos segundos, perceptible en medio de
        # una reunion. Con _watch_network_changes() disparando esto cada vez
        # que el fingerprint SSID+gateway se movia (747 veces en ~3.5 dias en
        # este equipo, journal mediante), cada disparo era un corte de wifi
        # real. "nmcli device reapply <interfaz>" aplica los mismos cambios
        # (incluido DNS) a la conexion YA activa sin bajarla - confirmado en
        # este mismo equipo que no toca connection.timestamp (que si cambia
        # con "connection up"), es decir no hay reactivacion real.
        for name, device in conns:
            current = sh(f'nmcli -g ipv4.dns connection show "{name}"').strip()
            if current == ip:
                continue
            sh(f'nmcli connection modify "{name}" ipv4.dns "{ip}" ipv4.ignore-auto-dns yes '
               f'ipv6.ignore-auto-dns yes 2>/dev/null')
            sh(f'nmcli device reapply "{device}" 2>/dev/null')
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
        # Mismo motivo que en set_central_dns(): "reapply" en vez de "up"
        # para no forzar una reconexion real de la interfaz.
        for name, device in conns:
            current = sh(f'nmcli -g ipv4.dns connection show "{name}"').strip()
            if not current:
                continue
            sh(f'nmcli connection modify "{name}" ipv4.dns "" ipv4.ignore-auto-dns no '
               f'ipv6.ignore-auto-dns no 2>/dev/null')
            sh(f'nmcli device reapply "{device}" 2>/dev/null')
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

# Contraparte de disable_browser_doh_linux/block_doh_endpoints_linux: antes
# estas dos se llamaban una sola vez al arrancar el agente y nunca se
# deshacian, sin importar horario ni red permitida - a diferencia de
# set_central_dns/restore_dns_central (que si respetan eso). Un equipo que
# sale de la red de oficina se quedaba con estas 6 IPs bloqueadas por
# iptables/nft para siempre, y si su router resolvia DNS a traves de alguna
# de ellas (Cloudflare/Google/Quad9 son las mas comunes), perdia internet por
# completo fuera de la oficina - mismo bug que tenia el agente de Windows.
def enable_browser_doh_linux():
    for base in ("/etc/chromium/policies/managed", "/etc/opt/chrome/policies/managed",
                 "/etc/brave/policies/managed", "/opt/brave/policies/managed",
                 "/usr/lib/brave/policies/managed",
                 "/usr/lib/firefox/distribution", "/usr/lib64/firefox/distribution",
                 "/opt/firefox/distribution"):
        try:
            path = os.path.join(base, "policies.json")
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

def unblock_doh_endpoints_linux():
    try:
        for ip in DOH_IPS:
            sh(f"iptables -D OUTPUT -d {ip} -j DROP 2>/dev/null")
        # nft no permite borrar por coincidencia (a diferencia de iptables -D):
        # hay que ubicar el "handle" de cada regla agregada y borrarla por eso.
        out = sh("nft -a list chain inet filter output 2>/dev/null")
        for line in out.splitlines():
            if "drop" in line and "handle" in line and any(ip in line for ip in DOH_IPS):
                m = re.search(r"handle (\d+)", line)
                if m:
                    sh(f"nft delete rule inet filter output handle {m.group(1)} 2>/dev/null")
    except Exception as e:
        print(f"WARN: no se pudo desbloquear endpoints DoH: {e}")

def sh(cmd, default=""):
    # timeout obligatorio: sin esto, un comando colgado (ej. "df" sobre un
    # punto de montaje que dejo de responder) congela este proceso para
    # siempre - deja de reportar metricas y de refrescar el bloqueo, aunque
    # el DNS ya apuntado antes siga "funcionando" por inercia (lo resuelve el
    # servidor, no este proceso), dando la falsa impresion de que el agente
    # sigue vivo cuando en realidad esta trabado.
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           env={**os.environ, "LC_ALL":"C", "LANG":"C"}, timeout=5)
        return r.stdout.strip()
    except:
        return default

def _base_disk(dev):
    """'/dev/nvme0n1p2' -> 'nvme0n1', '/dev/sda1' -> 'sda' - el disco fisico
    detras de una particion, para no contar cada particion como un disco
    distinto (ej. la EFI y la raiz son particiones del MISMO disco)."""
    name = dev.replace('/dev/', '')
    m = re.match(r'(nvme\d+n\d+|mmcblk\d+)p\d+$', name)
    if m: return m.group(1)
    m = re.match(r'([a-z]+)\d+$', name)
    if m: return m.group(1)
    return name

def _is_removable(dev):
    """True si el disco detras de esta particion es removible (USB, tarjeta
    SD, etc.) - esos no cuentan como 'otro disco fisico' del equipo."""
    try:
        return open(f"/sys/block/{_base_disk(dev)}/removable").read().strip() == "1"
    except Exception:
        return False

def _physical_disk_size_gb(base_dev):
    """Tamano REAL del disco fisico (desde el kernel, en sectores de 512
    bytes) - no la suma de sus particiones, que puede no cubrir el 100% del
    disco (espacio sin particionar, particiones no montadas, etc.)."""
    try:
        sectors = int(open(f"/sys/block/{base_dev}/size").read().strip())
        return round(sectors * 512 / 1024**3, 1)
    except Exception:
        return None

def _disk_media_type(base_dev):
    """"NVMe SSD"/"SSD"/"HDD"/None si no se pudo determinar. NVMe se
    detecta por el nombre del device (nvme0n1...); para el resto,
    /sys/block/<dev>/queue/rotational (0=no rotativo=SSD, 1=rotativo=HDD)
    es el mismo dato que usa lsblk -d -o rota."""
    if base_dev.startswith("nvme"):
        return "NVMe SSD"
    try:
        rota = open(f"/sys/block/{base_dev}/queue/rotational").read().strip()
        if rota == "0":
            return "SSD"
        if rota == "1":
            return "HDD"
    except Exception:
        pass
    return None

def _disk_model(base_dev):
    """Marca/modelo real del disco (ej. "Samsung SSD 980 500GB") desde
    /sys/block/<dev>/device/model - mismo dato que muestra 'lsblk -d -o
    model'. None si el device no expone esa ruta (discos virtuales, etc.)."""
    try:
        model = open(f"/sys/block/{base_dev}/device/model").read().strip()
        return model or None
    except Exception:
        return None

def _disk_interface(base_dev):
    """Interfaz fisica real ("PCIe Gen3 x4", "SATA", "USB"...) o None si no
    se pudo determinar - mismo criterio honesto que el lado Windows (ver
    _get_disk_interface en smartmonitor_agent.py): nunca se inventa.
    Para NVMe, current_link_speed/current_link_width vienen gratis en sysfs
    (el mismo dato que expone `lspci -vv` para el controlador) - sin
    necesitar leer nada del disco en si. Para SATA/USB alcanza con mirar de
    que bus real cuelga el device (realpath de /sys/block/<dev>)."""
    if base_dev.startswith("nvme"):
        ctrl = re.sub(r"n\d+$", "", base_dev)  # nvme0n1 -> nvme0 (controlador, no el namespace)
        try:
            speed_raw = open(f"/sys/class/nvme/{ctrl}/device/current_link_speed").read().strip()
            width_raw = open(f"/sys/class/nvme/{ctrl}/device/current_link_width").read().strip()
            gts = float(speed_raw.split()[0])
            gen = {2.5: 1, 5.0: 2, 8.0: 3, 16.0: 4, 32.0: 5}.get(gts)
            width = int(width_raw)
            if gen and width:
                return f"PCIe Gen{gen} x{width}"
        except Exception:
            pass
        return None
    try:
        real_path = os.path.realpath(f"/sys/block/{base_dev}")
        if "usb" in real_path:
            return "USB"
        if "/ata" in real_path:
            return "SATA"
    except Exception:
        pass
    return None

def read_cpu():
    with open("/proc/stat") as f:
        parts = f.readline().split()
    return int(parts[4]), sum(int(x) for x in parts[1:8])

def _total_process_count():
    """Cantidad total de procesos vivos - mismo criterio que EnumProcesses()
    del agente Windows (todos, no solo los que entran en el top-100 de abajo)."""
    try:
        return sum(1 for e in os.listdir("/proc") if e.isdigit())
    except Exception:
        return 0

def _proc_io_bytes(pid):
    """Bytes leidos+escritos acumulados por este PID desde que arranco (no es
    una tasa - eso se calcula comparando contra la lectura del ciclo
    anterior, ver _prev_proc_io mas abajo). Requiere root (el agente ya lo
    necesita para dmidecode), si no siempre devuelve None."""
    try:
        rb = wb = 0
        with open(f"/proc/{pid}/io") as f:
            for line in f:
                if line.startswith("read_bytes:"):
                    rb = int(line.split(":", 1)[1])
                elif line.startswith("write_bytes:"):
                    wb = int(line.split(":", 1)[1])
        return rb + wb
    except Exception:
        return None

def _read_diskstats():
    """Suma de sectores leidos/escritos (en bytes) de /proc/diskstats, solo
    discos fisicos completos (no particiones, no loop/ram/removibles) - mismo
    criterio de fisico-vs-particion que ya usa physical_disks mas abajo."""
    read_b = write_b = 0
    try:
        for line in open("/proc/diskstats"):
            parts = line.split()
            if len(parts) < 10:
                continue
            name = parts[2]
            if re.match(r'^(loop|ram|sr\d)', name):
                continue
            if _base_disk("/dev/" + name) != name:
                continue  # es una particion, no el disco completo
            if _is_removable("/dev/" + name):
                continue
            read_b  += int(parts[5]) * 512   # sectores leidos, 512 bytes c/u
            write_b += int(parts[9]) * 512   # sectores escritos
    except Exception:
        pass
    return read_b, write_b

# Estado entre ciclos para calcular tasas (KB/s, MB/s, Mbps) por diferencia -
# ninguno de /proc/[pid]/io, /proc/diskstats o las stats de red da una tasa
# directamente, solo contadores acumulados desde que arranco el proceso/equipo.
_prev_proc_io  = {}
_prev_disk_io  = None   # (read_bytes, write_bytes)
_prev_net_io   = None   # (rx_bytes, tx_bytes)
_prev_sample_ts = None

def _parse_ram_block(b):
    """Parsea un bloque 'Memory Device' de dmidecode a un dict con el mismo
    esquema que ya manda el agente Windows (slot/size_gb/type/speed/
    manufacturer/part_number/installed) - por linea, no por texto-dentro-de-
    texto, para que 'Bank Locator:' no se confunda con 'Locator:'."""
    fields = {}
    for line in b.splitlines():
        line = line.strip()
        if ":" not in line: continue
        k, _, v = line.partition(":")
        fields[k.strip()] = v.strip()
    size_str = fields.get("Size", "")
    installed = size_str not in ("", "Unknown", "0", "No Module Installed", "Not Installed")
    size_gb = 0
    if installed:
        m = re.match(r'(\d+)\s*(GB|MB)', size_str)
        if m:
            n = int(m.group(1))
            size_gb = n if m.group(2) == "GB" else round(n / 1024)
    mem_type = fields.get("Type", "")
    if mem_type in ("", "Unknown"): mem_type = "DDR"
    speed = fields.get("Speed", "")
    if speed in ("Unknown", "Not Specified"): speed = ""
    manufacturer = fields.get("Manufacturer", "")
    if manufacturer in ("Unknown", "Not Specified"): manufacturer = ""
    part_number = fields.get("Part Number", "")
    if part_number in ("Unknown", "Not Specified"): part_number = ""
    # "Form Factor" (DIMM de escritorio vs SODIMM de portatil/compacto) SI
    # esta en el SMBIOS Type 17 estandar que lee dmidecode - a diferencia
    # de la latencia CAS, que NO esta en ningun lado accesible sin leer el
    # SPD crudo por I2C/SMBus (fuera de alcance: mismo tipo de operacion de
    # bajo nivel que la lectura de disco fisico via IOCTL que se probo y
    # descarto en Windows por bloqueo del antivirus - no vale la pena el
    # riesgo/complejidad por un dato informativo).
    form_factor = fields.get("Form Factor", "")
    if form_factor in ("Unknown", ""): form_factor = None
    return {"slot": fields.get("Locator", ""), "size_gb": size_gb, "type": mem_type,
            "speed": speed, "manufacturer": manufacturer, "part_number": part_number,
            "installed": installed, "form_factor": form_factor}

def _get_ram_slots():
    """Devuelve (slots_usados, slots_totales, detalle_por_ranura,
    capacidad_maxima_gb). Requiere root para dmidecode."""
    try:
        r = subprocess.run(
            ["dmidecode", "-t", "memory"],
            capture_output=True, text=True,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"}, timeout=5
        )
        if r.returncode != 0 or "Permission denied" in r.stderr:
            return 0, 0, [], None
        # "Maximum Capacity" vive en el bloque "Physical Memory Array" (uno
        # solo, antes del primer "Memory Device") - el limite de RAM que
        # soporta la placa, no la suma de lo instalado.
        array_block = r.stdout.split("Memory Device")[0]
        max_cap_gb = None
        m = re.search(r'Maximum Capacity:\s*(\d+)\s*(GB|TB|MB)', array_block)
        if m:
            n, unit = int(m.group(1)), m.group(2)
            max_cap_gb = n * 1024 if unit == "TB" else (n if unit == "GB" else round(n / 1024))
        blocks = r.stdout.split("Memory Device")[1:]  # primer bloque es cabecera
        detail = [_parse_ram_block(b) for b in blocks if "Size:" in b]
        used = sum(1 for d in detail if d["installed"])
        return used, len(detail), detail, max_cap_gb
    except Exception:
        return 0, 0, [], None

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

def _screen_size_in():
    """Tamano de pantalla (diagonal, pulgadas) via EDID - solo si la pantalla
    es parte fisica del equipo: laptop (integrada siempre) o PC 'All in One'
    (chasis tipo 13). Un desktop normal con monitor aparte devuelve None a
    proposito, ese monitor no es del equipo y podria cambiarse sin que
    signifique nada."""
    try:
        t = open("/sys/class/dmi/id/chassis_type").read().strip()
        ct = int(t) if t.isdigit() else None
    except Exception:
        ct = None
    if ct not in ({8, 9, 10, 11, 14, 31, 32} | {13}):
        return None
    try:
        import glob
        for edid_path in glob.glob("/sys/class/drm/*/edid"):
            try:
                data = open(edid_path, "rb").read()
                # Header estandar de EDID (VESA) - si no calza, no es un EDID valido
                if len(data) < 23 or data[:8] != b"\x00\xff\xff\xff\xff\xff\xff\x00":
                    continue
                h_cm, v_cm = data[21], data[22]  # offset 0x15/0x16: tamano max en cm
                if h_cm and v_cm:
                    diag_in = ((h_cm ** 2 + v_cm ** 2) ** 0.5) / 2.54
                    return round(diag_in, 1)
            except Exception:
                continue
    except Exception:
        pass
    return None

def physical_ram_gb(usable_gb):
    """Redondea al tamaño comercial de RAM más cercano (4,8,12,16,20,24,32,64...)"""
    standards = [1,2,3,4,6,8,10,12,16,20,24,32,48,64,96,128,192,256]
    for s in standards:
        if usable_gb <= s + 0.5:
            return s
    return round(usable_gb)

# ── Hardware ──────────────────────────────────────────────────────────────
# Se recolecta fresco en cada send_once() (ver mas abajo), sin cachear en
# disco: son puros archivos de /sys y un dmidecode, nada caro de releer cada
# pocos minutos - y evita cualquier version de este agente quedando con datos
# de hardware desactualizados por un cache viejo (paso de verdad: un cache en
# /tmp de antes de que existiera ram_slots_detail se seguia usando para
# siempre, porque nada invalidaba ese archivo al actualizar el agente).
def collect_hw():
    hw = {}
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

    slots_used, slots_total, slots_detail, ram_max_capacity_gb = _get_ram_slots()
    hw["ram_slots_total"]     = slots_total
    hw["ram_slots_used"]      = slots_used
    hw["ram_slots_detail"]    = slots_detail
    hw["ram_max_capacity_gb"] = ram_max_capacity_gb
    hw["device_type"] = get_device_type()
    hw["screen_size_in"] = _screen_size_in()
    return hw

hw = collect_hw()

last_latency_ms = None
def get_interval():
    # Se aprovecha esta llamada (que el agente ya hace cada ciclo) para medir
    # la latencia al servidor, en vez de sumar una peticion de red aparte
    # solo para eso. Queda "un ciclo atras" del ultimo send_once() - no hace
    # falta mas precision para un dato informativo como este.
    global last_latency_ms
    try:
        t0 = time.time()
        r = urllib.request.urlopen(f"{SERVER}/api/config/interval", timeout=3)
        last_latency_ms = round((time.time() - t0) * 1000, 1)
        cfg = json.loads(r.read())
        return max(3, int(cfg.get("interval", 5))), max(60, int(cfg.get("blocklist_interval", 60)))
    except:
        return 5, 60

def send_once():
    global hw, _prev_proc_io, _prev_disk_io, _prev_net_io, _prev_sample_ts
    hw = collect_hw()

    now_ts = time.time()
    # None en el primer ciclo (no hay muestra anterior con la que restar) -
    # todas las tasas de abajo quedan en 0 esa primera vez, nunca con un
    # numero inventado.
    elapsed = (now_ts - _prev_sample_ts) if _prev_sample_ts else None

    # ── Procesos top (agrupados por nombre) ──────────────────────────────
    # user/pid/etimes(seg desde que arranco)/vsz se piden explicitos en vez
    # de parsear la columna COMMAND completa de "ps aux" (fragil con rutas
    # con espacios) - vsz=0 identifica hilos/procesos de kernel (sin memoria
    # de usuario), igual que antes hacia el filtro de "[...]" de ps aux.
    seen_p = {}
    cur_proc_io = {}
    for line in sh("ps -eo user:32,pid,pcpu,pmem,etimes,vsz,comm --no-headers --sort=-%cpu | head -300").splitlines():
        parts = line.split(None, 6)
        if len(parts) < 7: continue
        user, pid_s, cpu_s, mem_s, etimes_s, vsz_s, comm = parts
        if vsz_s == "0" or comm == "ps":
            continue
        try:
            pid = int(pid_s)
            cpu_p, mem_p = float(cpu_s), float(mem_s)
            etimes = int(etimes_s)
        except ValueError:
            continue
        name = re.sub(r'[^a-zA-Z0-9_\-\.]', '', comm)[:20]
        if not name: continue

        io_bytes = _proc_io_bytes(pid)
        disk_kb_s = 0.0
        if io_bytes is not None:
            cur_proc_io[pid] = io_bytes
            if elapsed and pid in _prev_proc_io:
                delta = io_bytes - _prev_proc_io[pid]
                if delta > 0:
                    disk_kb_s = round(delta / 1024 / elapsed, 1)

        if name in seen_p:
            g = seen_p[name]
            g["cpu"] = round(g["cpu"] + cpu_p, 1)
            g["mem"] = round(g["mem"] + mem_p, 1)
            g["disk_kb_s"] = round(g["disk_kb_s"] + disk_kb_s, 1)
            g["uptime_min"] = max(g["uptime_min"], round(etimes / 60, 1))
        else:
            seen_p[name] = {"name": name, "cpu": cpu_p, "mem": mem_p, "user": user,
                             "disk_kb_s": disk_kb_s, "uptime_min": round(etimes / 60, 1)}
    procs = sorted(seen_p.values(), key=lambda x: -x["cpu"])[:100]
    _prev_proc_io = cur_proc_io
    process_count = _total_process_count()

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
    disks, seen = [], set()
    for line in sh("df -x tmpfs -x devtmpfs -x overlay --output=source,target,size,used,pcent 2>/dev/null | tail -n +2").splitlines():
        p = line.split()
        if len(p) < 5: continue
        # size/used/pcent son SIEMPRE los ultimos 3 campos (nunca tienen
        # espacios); el mountpoint si puede tenerlos (ej. una USB con
        # etiqueta "NUEVO VOL") y desalineaba un split() de izquierda a
        # derecha, rompiendo send_once() con un ValueError en CADA envio -
        # bug real encontrado en produccion (LAP-ISAAVEDRA con una USB asi
        # montada dejo de reportar metricas por horas sin ningun otro sintoma).
        dev = p[0]
        mnt = " ".join(p[1:-3])
        try:
            tgb = round(int(p[-3]) / 1024 / 1024, 1)
            ugb = round(int(p[-2]) / 1024 / 1024, 1)
            pct = float(p[-1].rstrip('%'))
        except ValueError:
            continue
        if not mnt or tgb < 0.1 or dev in seen: continue
        seen.add(dev)
        disks.append({"device": dev, "mountpoint": mnt, "total_gb": tgb, "used_gb": ugb, "percent": pct})

    # Se descartan los removibles (USB, SD) - esos no cuentan como disco
    # fisico del equipo. Cada particion que queda se etiqueta con un
    # disk_index estable (0,1,2...) segun a que disco fisico pertenece.
    disks = [d for d in disks if not _is_removable(d["device"])]
    bases = sorted({_base_disk(d["device"]) for d in disks})
    index_of = {base: i for i, base in enumerate(bases)}
    for d in disks:
        d["disk_index"] = index_of[_base_disk(d["device"])]

    # Un disco fisico -> una entrada en physical_disks, con el tamano REAL
    # de hardware (/sys/block/*/size, no sumando particiones - eso puede no
    # cubrir el 100% del disco) y el uso combinado de sus particiones.
    used_by_base = {}
    for d in disks:
        base = _base_disk(d["device"])
        used_by_base.setdefault(base, {"used_gb": 0.0, "count": 0})
        used_by_base[base]["used_gb"] += d["used_gb"]
        used_by_base[base]["count"]   += 1
    physical_disks = []
    for base, i in index_of.items():
        info = used_by_base[base]
        used = round(info["used_gb"], 1)
        real_total = _physical_disk_size_gb(base)
        total = real_total if real_total is not None else used
        pct = round(used / total * 100, 1) if total > 0 else 0.0
        physical_disks.append({
            "disk_index": i, "total_gb": total, "used_gb": used,
            "percent": pct, "partitions": info["count"],
            "media_type": _disk_media_type(base),
            "model": _disk_model(base),
            "interface": _disk_interface(base),
        })

    # disk_percent (resumen) = el disco fisico que tiene la raiz "/" entre
    # sus particiones.
    root_partition = next((d for d in disks if d["mountpoint"] == "/"), None)
    disk_pct = physical_disks[root_partition["disk_index"]]["percent"] if root_partition \
        else (physical_disks[0]["percent"] if physical_disks else 0.0)

    # ── Red ───────────────────────────────────────────────────────────────
    net_dev = sh("ip route | grep default | awk '{print $5}' | head -1")
    rx_mb = tx_mb = 0.0
    net_down_mbps = net_up_mbps = 0.0
    if net_dev:
        try:
            rx_now = int(open(f"/sys/class/net/{net_dev}/statistics/rx_bytes").read())
            tx_now = int(open(f"/sys/class/net/{net_dev}/statistics/tx_bytes").read())
            rx_mb = round(rx_now / 1024 / 1024, 1)
            tx_mb = round(tx_now / 1024 / 1024, 1)
            if elapsed and _prev_net_io:
                prx, ptx = _prev_net_io
                net_down_mbps = round(max(rx_now - prx, 0) * 8 / 1_000_000 / elapsed, 2)
                net_up_mbps   = round(max(tx_now - ptx, 0) * 8 / 1_000_000 / elapsed, 2)
            _prev_net_io = (rx_now, tx_now)
        except: pass

    # ── Throughput de disco (todo el equipo, no por proceso) ────────────────
    disk_read_mb_s = disk_write_mb_s = 0.0
    rb, wb = _read_diskstats()
    if elapsed and _prev_disk_io:
        prb, pwb = _prev_disk_io
        disk_read_mb_s  = round(max(rb - prb, 0) / 1024 / 1024 / elapsed, 2)
        disk_write_mb_s = round(max(wb - pwb, 0) / 1024 / 1024 / elapsed, 2)
    _prev_disk_io = (rb, wb)
    _prev_sample_ts = now_ts

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
        "ram_slots_total":     hw.get("ram_slots_total") or None,
        "ram_slots_used":      hw.get("ram_slots_used") or None,
        "ram_slots_detail":    hw.get("ram_slots_detail") or [],
        "ram_max_capacity_gb": hw.get("ram_max_capacity_gb"),
        "ram_total_gb":       ram_total_gb,
        "cpu_percent":        cpu_pct,
        "ram_percent":        ram_pct,
        "ram_used_gb":        ram_used_gb,
        "disk_percent":       disk_pct,
        "net_rx_mb":          rx_mb,
        "net_tx_mb":          tx_mb,
        "process_count":      process_count,
        "disk_read_mb_s":     disk_read_mb_s,
        "disk_write_mb_s":    disk_write_mb_s,
        "net_down_mbps":      net_down_mbps,
        "net_up_mbps":        net_up_mbps,
        "cpu_temp":           cpu_temp,
        "latency_ms":         last_latency_ms,
        "disks":              disks,
        "physical_disks":     physical_disks,
        "top_processes":      procs,
        "installed_software": installed_software,
        "device_type":        hw.get("device_type", ""),
        "screen_size_in":     hw.get("screen_size_in"),
        "tailnet_ip":         tailnet_ip,
    }
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        f"{SERVER}/api/agents/metrics",
        data=data, headers={"Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(req, timeout=5)

# ── Loop principal ────────────────────────────────────────────────────────
# El bloqueo (dominios/excepciones/horario/red) se revisa cada BLOCKLIST_POLL_SEC,
# independiente del intervalo de métricas. Configurable desde el servidor
# (Configuración -> "Bloqueo cada"), con piso de 1 minuto pensado para
# producción a escala (cientos de equipos), sin tocar este archivo.
BLOCKLIST_POLL_SEC = 60

# Server y hostname bien visibles al arrancar: si el agente alguna vez queda
# apuntando al servidor equivocado (ej. una reinstalación que no reemplazó el
# archivo de verdad, como pasó una vez), esto lo delata de inmediato con
# 'journalctl -u smartmonitor-agent' sin tener que diagnosticar por SSH
# cuánto tráfico llega a cada server.
print(f"Servidor configurado: {SERVER} | Hostname: {HOSTNAME}")

# Fase 2 (cerrar la via de DoH) ya no se aplica aca de forma incondicional -
# se decide en el loop principal junto con set_central_dns/restore_dns_central,
# segun horario y red permitida (ver comentario en unblock_doh_endpoints_linux).

# Intento inicial de conectar el tunel WireGuard (no bloqueante: si falla,
# el agente sigue funcionando por IP publica igual que siempre)
setup_wireguard_tunnel()

# Reaccion inmediata a cambios de red (conectar/desconectar WiFi, cambiar de
# SSID, enchufar a otra red por cable, etc.), en vez de esperar hasta
# BLOCKLIST_POLL_SEC para notarlo. Un hilo en segundo plano compara SSID+
# gateway cada 2s (barato, sin tocar red) y prende una bandera apenas cambian;
# el loop principal corta su espera apenas la ve prendida (ver el sleep
# fraccionado de abajo).
_network_changed = threading.Event()

def _network_fingerprint():
    gw = sh("ip route show default 2>/dev/null | head -1").strip()
    return f"{get_wifi_ssid() or ''}|{gw}"

def _watch_network_changes():
    last = _network_fingerprint()
    while True:
        time.sleep(2)
        try:
            cur = _network_fingerprint()
            if cur != last:
                last = cur
                _network_changed.set()
        except Exception:
            pass

threading.Thread(target=_watch_network_changes, daemon=True).start()

interval, BLOCKLIST_POLL_SEC = get_interval()
last_metrics = 0.0
last_wireguard_retry = time.time()
while True:
    # Metricas y bloqueo/DNS van en try/except SEPARADOS: antes, si send_once()
    # fallaba (ej. un corte de red pasajero), la excepcion abortaba tambien la
    # revision de bloqueo/DNS de ESE mismo ciclo (estaban en un solo try). Con
    # BLOCKLIST_POLL_SEC pudiendo ser de varios minutos, eso podia dejar el
    # bloqueo sin refrescar por mucho tiempo solo porque el reporte de
    # metricas fallo, dos problemas sin relacion entre si.
    try:
        now_t = time.time()
        if now_t - last_metrics >= interval:
            send_once()
            interval, BLOCKLIST_POLL_SEC = get_interval()
            last_metrics = time.time()
    except Exception as e:
        print(f"Error enviando metricas: {e}", file=sys.stderr)

    try:
        # Se revalida en CADA ciclo si el tunel sigue realmente vivo (no solo
        # una vez al conectar): si Tailscale se cae despues de haber estado
        # conectado, tailnet_ip quedaba en un valor viejo para siempre, y el
        # agente seguia apuntando el DNS a una IP del tunel que ya no
        # respondia -> el equipo terminaba usando otro DNS sin filtrar y el
        # bloqueo se saltaba por completo.
        tailnet_ip = get_tailscale_ip()

        # Reintenta cada ~60s si el tunel no esta arriba, O si esta arriba
        # pero todavia no sabemos la IP del server dentro del tunel
        # (tailnet_server_ip): antes esto ultimo solo se pedia UNA vez, la
        # primera que tailnet_ip se ponia en verdadero - si ese pedido
        # fallaba por un hiccup de red al arrancar, el agente quedaba
        # atrapado usando la IP publica compartida de la oficina para
        # siempre (varios equipos detras del mismo NAT "contaminan" el
        # bloqueo entre si - ver el comentario de by_ip en dns_blocker.py),
        # sin ninguna forma de corregirse solo.
        if (not tailnet_ip or not tailnet_server_ip) and time.time() - last_wireguard_retry >= 60:
            setup_wireguard_tunnel()
            last_wireguard_retry = time.time()
        should_block, all_domains = get_blocklist()
        if should_block is not None:
            all_domains = all_domains or []
            if should_block and all_domains:
                set_central_dns()
                disable_browser_doh_linux()
                block_doh_endpoints_linux()
                print("BLOCKLIST modo=DNS-central (el server filtra)")
            else:
                restore_dns_central()
                unblock_doh_endpoints_linux()
                enable_browser_doh_linux()
                print("BLOCKLIST modo=off")
        else:
            print("BLOCKLIST sin respuesta del servidor (None)")
    except Exception as e:
        print(f"Error en bloqueo/DNS: {e}", file=sys.stderr)

    # Espera fraccionada (en vez de un solo sleep largo) para poder cortarla
    # apenas _network_changed se prenda - asi un cambio de red dispara la
    # revision del bloqueo casi al instante en vez de esperar el ciclo entero.
    waited = 0.0
    while waited < BLOCKLIST_POLL_SEC:
        if _network_changed.is_set():
            _network_changed.clear()
            print("Cambio de red detectado - revisando bloqueo de inmediato")
            time.sleep(3)  # debounce: dar tiempo a que la SSID/IP se asienten
            break
        time.sleep(2)
        waited += 2

#!/usr/bin/env python3
"""SmartMonitor v3 - Agente Windows (Python, empaquetado como .exe con PyInstaller)

Reemplaza a smartmonitor-push.ps1 (que se mantiene en el repo sin tocar, como
respaldo por-equipo durante la transicion). El cambio principal frente al
.ps1: el filtrado de contenido ya NO se hace apuntando/desapuntando el DNS del
sistema y creando/borrando reglas de firewall + politicas de registro en cada
ciclo (~60s) - ese patron de creacion/borrado repetido es lo que disparaba la
heuristica de comportamiento de Kaspersky (System Watcher, "Object deleted").

Ahora: el DNS del sistema se fija UNA sola vez a 127.0.0.1, donde corre
cloudflared.exe (proxy-dns) reenviando todo al endpoint DoH nuevo del server
(dns_blocker.py: /dns-query), que aplica el filtrado del lado servidor. La
decision de "bloquear ahora si/no" (horario/pausa/red permitida) tambien vive
100% del lado servidor para este camino - ver resolve_should_block() en
routers/agents.py y resolve_dns_query(apply_gate=True) en dns_blocker.py.
"""
import sys; sys.dont_write_bytecode = True
import os, re, json, time, socket, hashlib, threading, subprocess
import urllib.request, urllib.parse
import winreg

try:
    import pythoncom
    import win32com.client
    import win32pdh
    import win32api
    import win32file
    import win32process
    import win32con
    import win32security
except ImportError as _e:
    # Permite importar este modulo fuera de Windows (ej. para un smoke-test de
    # sintaxis en CI/Linux) - en la maquina real, pywin32 siempre esta presente
    # (viene empaquetado dentro del .exe via PyInstaller).
    try:
        with open(r"C:\SmartMonitor\import_error.log", "a", encoding="utf-8") as _f:
            import traceback as _tb
            _f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} import fallo: {_e!r}\n")
            _f.write(_tb.format_exc() + "\n")
    except Exception:
        pass
    win32com = None
    win32pdh = None
    win32api = None
    win32file = None
    win32process = None
    win32con = None
    win32security = None
    pythoncom = None

# ── Configuracion ────────────────────────────────────────────────────────────
AGENT_DIR       = r"C:\SmartMonitor"
CONFIG_FILE     = os.path.join(AGENT_DIR, "config.json")
LOG_FILE        = os.path.join(AGENT_DIR, "agent.log")
SW_HASH_FILE    = os.path.join(AGENT_DIR, ".sw_hash")
# cloudflared.exe va embebido dentro del .exe (PyInstaller --add-data), no
# copiado a AGENT_DIR - en tiempo de ejecucion el bootloader --onefile lo
# extrae a una carpeta temporal (sys._MEIPASS), valida mientras el proceso
# siga vivo. Fuera de un build congelado (ej. smoke-test de sintaxis en
# Linux/CI) _MEIPASS no existe, así que cae de vuelta a AGENT_DIR.
CLOUDFLARED_EXE = os.path.join(getattr(sys, "_MEIPASS", AGENT_DIR), "cloudflared.exe")
TAILSCALE_EXE   = r"C:\Program Files\Tailscale\tailscale.exe"
HOSTS_FILE      = r"C:\Windows\System32\drivers\etc\hosts"

DOH_HOSTNAME  = "dns.smartmonitor.local"  # nunca se resuelve publicamente - solo SNI local
HOSTS_MARKER  = "# SmartMonitor DoH upstream"
LOCAL_DNS_IP  = "127.0.0.1"

# El instalador (Inno Setup) escribe el valor real en config.json al momento
# de instalar - este default solo se usa si ese archivo no existe todavia (o
# se borro), igual que el placeholder __SMARTMONITOR_SERVER_IP__ del .ps1
# servia de "canario" visible si el reemplazo de texto no habia corrido.
DEFAULT_SERVER = "http://__SMARTMONITOR_SERVER_IP__:8000"

def _load_config():
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
            return cfg.get("server") or DEFAULT_SERVER
    except Exception:
        return DEFAULT_SERVER

SERVER      = _load_config()
HOSTNAME_PC = os.environ.get("COMPUTERNAME") or socket.gethostname()

# IP unica del equipo dentro del tunel WireGuard (Headscale), si esta
# conectado. None hasta que setup_wireguard_tunnel() lo resuelva. Tambien se
# usa para mantener la linea de hosts que le da a cloudflared una URL DoH con
# SNI valido hacia el server (ver ensure_hosts_entry).
tailnet_ip        = None
tailnet_server_ip = None
last_latency_ms   = None

MAX_LOG_BYTES     = 5 * 1024 * 1024
MAX_LOG_AGE_DAYS  = 7


def write_log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line)
    try:
        os.makedirs(AGENT_DIR, exist_ok=True)
        # Rotacion: semanal (fecha de creacion del archivo actual), con el
        # tamano (5MB) solo como red de seguridad extra - mismo criterio que
        # ya usaba el agente PowerShell.
        if os.path.exists(LOG_FILE):
            st = os.stat(LOG_FILE)
            too_old = (time.time() - st.st_ctime) >= MAX_LOG_AGE_DAYS * 86400
            too_big = st.st_size >= MAX_LOG_BYTES
            if too_old or too_big:
                try:
                    os.replace(LOG_FILE, LOG_FILE + ".old")
                except Exception:
                    pass
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


write_log(f"=== SmartMonitor iniciando (usuario: {os.environ.get('USERNAME', '?')}) ===")
# Servidor y hostname bien visibles en la primera linea del log: si el agente
# alguna vez queda apuntando al servidor equivocado, esto lo delata de
# inmediato sin tener que diagnosticar por SSH cuanto trafico llega a cada server.
write_log(f"Servidor configurado: {SERVER} | Hostname: {HOSTNAME_PC}")


# ── Espera a que la red este lista al arrancar (llamada desde main(), NO a
# nivel de modulo - ver comentario en main()) ────────────────────────────────
def _wait_for_network(max_wait=60):
    server_ip = re.sub(r"^https?://", "", SERVER)
    server_ip = server_ip.split(":")[0]
    write_log("Esperando red...")
    waited = 0
    while waited < max_wait:
        try:
            with socket.create_connection((server_ip, 8000), timeout=2):
                write_log(f"Red lista tras {waited}s")
                return
        except Exception:
            pass
        time.sleep(5)
        waited += 5
    write_log(f"WARN: Red no disponible tras {max_wait}s - continuando")


# ── WMI (helper minimo, conexiones cacheadas por namespace) ─────────────────
# Cacheadas POR HILO (threading.local), no en un dict global: un objeto COM
# de SWbemServices queda atado al apartment del hilo que lo creo (STA) - si
# dos hilos distintos (ej. el de main() y el de supervise_cloudflared(), ver
# main()) comparten el mismo objeto cacheado en un dict global, cualquier
# llamada desde el "otro" hilo revienta con RPC_E_WRONG_THREAD ("SWbemServicesEx
# ... la aplicacion llamo a una interfaz que se aplano para un diferente
# subproceso"). Bug real visto en produccion (LAP-ATAFUR) incluso DESPUES de
# agregar CoInitialize() en cada hilo - el CoInitialize por si solo no alcanza
# si el objeto en si se comparte entre apartments.
_wmi_local = threading.local()

def _wmi(namespace="root\\cimv2"):
    conns = getattr(_wmi_local, "conns", None)
    if conns is None:
        conns = {}
        _wmi_local.conns = conns
    if namespace not in conns:
        locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        conns[namespace] = locator.ConnectServer(".", namespace)
    return conns[namespace]

def _wmi_query(wql, namespace="root\\cimv2"):
    try:
        return list(_wmi(namespace).ExecQuery(wql))
    except Exception as e:
        # Antes se tragaba en silencio - visto en produccion: esta consulta
        # puede fallar de forma consistente (ciclo tras ciclo) en un equipo
        # puntual mientras otras consultas WMI en el mismo proceso siguen
        # funcionando, y sin este log no habia forma de saber cual fallaba ni
        # por que (ver bug real: RAM/disco reportando 0 en LAP-ATAFUR). No es
        # spam grave: write_log ya rota por tamano/antiguedad.
        write_log(f"WARN: WMI query fallo ({namespace}): {wql[:80]} - {e}")
        return []


# ── Interfaz fisica del disco (PCIe GenX xN / SATA) ─────────────────────────
# No hay clase WMI que exponga esto directamente (se probo: Win32_PnPDevice-
# PropertyUint32 vía WQL no devuelve nada para estas propiedades pese a que
# `Get-PnpDeviceProperty` de PowerShell sí las lee - ese cmdlet usa otro
# mecanismo interno, no una consulta WQL comun). Se lee entonces con la API
# nativa de Configuration Manager (cfgmgr32.dll, la misma que usa por debajo
# el Administrador de dispositivos) via ctypes - sin PowerShell, mismo
# criterio que el resto del agente. Verificado contra un valor real conocido
# en produccion (LAP-ATAFUR, Get-PnpDeviceProperty confirmo Gen3 x4 para su
# SSD) antes de integrarlo aca.
try:
    import ctypes as _ctypes
    from ctypes import wintypes as _wintypes

    class _GUID(_ctypes.Structure):
        _fields_ = [("Data1", _wintypes.DWORD), ("Data2", _wintypes.WORD), ("Data3", _wintypes.WORD),
                    ("Data4", _ctypes.c_ubyte * 8)]

    class _DEVPROPKEY(_ctypes.Structure):
        _fields_ = [("fmtid", _GUID), ("pid", _wintypes.ULONG)]

    # {3AB22E31-8264-4B4E-9AF5-A8D2D8E33E62} - FMTID compartido por las
    # propiedades DEVPKEY_PciDevice_* (confirmado con Get-PnpDeviceProperty,
    # no esta documentado con este nombre en un lugar unico de MSDN).
    _PCI_LINK_GUID = _GUID(0x3AB22E31, 0x8264, 0x4B4E,
                            (_ctypes.c_ubyte * 8)(0x9A, 0xF5, 0xA8, 0xD2, 0xD8, 0xE3, 0x3E, 0x62))
    _DEVPKEY_PciDevice_CurrentLinkSpeed = _DEVPROPKEY(_PCI_LINK_GUID, 9)
    _DEVPKEY_PciDevice_CurrentLinkWidth = _DEVPROPKEY(_PCI_LINK_GUID, 10)
    _cfgmgr32 = _ctypes.WinDLL("cfgmgr32")
except Exception:
    _cfgmgr32 = None

def _cm_get_uint32_property(devinst, propkey):
    proptype = _wintypes.ULONG()
    buf = _ctypes.c_uint32(0)
    bufsize = _wintypes.ULONG(_ctypes.sizeof(buf))
    ret = _cfgmgr32.CM_Get_DevNode_PropertyW(devinst, _ctypes.byref(propkey), _ctypes.byref(proptype),
                                              _ctypes.byref(buf), _ctypes.byref(bufsize), 0)
    return buf.value if ret == 0 else None

def _get_pcie_link_info(pnp_device_id):
    """(generacion, carriles) del enlace PCIe del disco, ej. (3, 4) para
    "Gen3 x4" - o None si el disco no es PCIe (SATA/USB) o si algo falla.
    El disco mismo (nodo SCSI\\DISK&VEN_NVME&...) no tiene esta propiedad -
    hay que subir por el arbol de dispositivos hasta el controlador NVMe
    (nodo PCI\\VEN_...) que sí la tiene; de ahi el bucle CM_Get_Parent."""
    if not _cfgmgr32 or not pnp_device_id:
        return None
    try:
        devinst = _wintypes.DWORD()
        if _cfgmgr32.CM_Locate_DevNodeW(_ctypes.byref(devinst), _ctypes.c_wchar_p(pnp_device_id), 0) != 0:
            return None
        cur = devinst.value
        for _ in range(6):  # tope de saltos hacia arriba en el arbol de dispositivos
            speed = _cm_get_uint32_property(cur, _DEVPKEY_PciDevice_CurrentLinkSpeed)
            if speed:
                width = _cm_get_uint32_property(cur, _DEVPKEY_PciDevice_CurrentLinkWidth)
                return (speed, width) if width else None
            parent = _wintypes.DWORD()
            if _cfgmgr32.CM_Get_Parent(_ctypes.byref(parent), cur, 0) != 0:
                return None
            cur = parent.value
    except Exception:
        pass
    return None

def _get_disk_interface(bus_type, pnp_device_id):
    """Cadena honesta de interfaz fisica ("PCIe Gen3 x4", "SATA"...) o None
    si no se pudo determinar - nunca inventa un dato (ver "Notas de diseño"
    sobre por que NO se muestra esto cuando no hay forma confiable de
    leerlo)."""
    if bus_type == 17:  # BusTypeNvme
        link = _get_pcie_link_info(pnp_device_id)
        return f"PCIe Gen{link[0]} x{link[1]}" if link else None
    if bus_type == 11:  # BusTypeSata
        return "SATA"
    if bus_type == 7:   # BusTypeUsb
        return "USB"
    return None


# ── Metricas de hardware/uso ─────────────────────────────────────────────────
_cpu_query = None
_cpu_counter = None

def get_cpu_percent():
    # Win32_Processor.LoadPercentage (WMI crudo) es conocido por no coincidir
    # con el Administrador de Tareas - se usa el mismo contador de rendimiento
    # real que usa Task Manager (\Processor(_Total)\% Processor Time), via
    # win32pdh, igual que el fix ya aplicado al agente PowerShell.
    global _cpu_query, _cpu_counter
    try:
        if _cpu_query is None:
            try:
                _cpu_query = win32pdh.OpenQuery()
                # AddEnglishCounter (no AddCounter): visto en produccion -
                # AddCounter con el nombre del contador en ingles puede fallar
                # en resolverse en un equipo con Windows instalado en otro
                # idioma (ej. espanol) si la tabla de nombres localizados no
                # coincide - problema conocido de la API PDH, nada que ver con
                # el hardware. AddEnglishCounter resuelve el contador de forma
                # independiente del idioma del sistema (confirmado con un
                # build real: AddCounter fallaba consistentemente en un
                # equipo real mientras AddEnglishCounter funciona igual en
                # cualquier locale).
                _cpu_counter = win32pdh.AddEnglishCounter(_cpu_query, r"\Processor(_Total)\% Processor Time")
                win32pdh.CollectQueryData(_cpu_query)
                time.sleep(0.2)
            except Exception:
                # Init parcial (ej. OpenQuery ok pero AddCounter fallo, visto
                # en produccion justo despues de instalar/arrancar, antes de
                # que el proveedor de contadores de rendimiento estuviera
                # listo) - bug real encontrado: _cpu_query quedaba asignado
                # (no-None) aunque _cpu_counter nunca se haya seteado, asi que
                # "if _cpu_query is None" de arriba pasaba a False para
                # siempre en los ciclos siguientes y este bloque NUNCA volvia
                # a reintentar - CPU quedaba atascado en 0% para siempre (no
                # solo el primer ciclo). Se resetean ambos a None para que el
                # PROXIMO ciclo reintente desde cero.
                _cpu_query, _cpu_counter = None, None
                raise
        win32pdh.CollectQueryData(_cpu_query)
        _, val = win32pdh.GetFormattedCounterValue(_cpu_counter, win32pdh.PDH_FMT_DOUBLE)
        return round(val, 1)
    except Exception:
        try:
            rows = _wmi_query("SELECT LoadPercentage FROM Win32_Processor")
            vals = [r.LoadPercentage for r in rows if r.LoadPercentage is not None]
            return round(sum(vals) / len(vals), 1) if vals else 0.0
        except Exception:
            return 0.0


def get_cpu_temp():
    # MSAcpi_ThermalZoneTemperature es la UNICA fuente de temperatura que
    # expone Windows sin software de terceros - muchas laptops de marca (Dell,
    # HP, Lenovo, con su propio controlador embebido) no publican esta zona
    # ACPI y esto no devuelve nada ahi; no es un bug de este agente.
    try:
        rows = _wmi_query("SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature", "root\\wmi")
        if rows:
            raw = rows[0].CurrentTemperature
            c = round((raw / 10) - 273.15, 1)
            if 0 < c < 150:
                return c
    except Exception:
        pass
    return None


LAPTOP_CHASSIS_CODES = {8, 9, 10, 11, 14, 31, 32}

def get_screen_size_in():
    # Solo tiene sentido si la pantalla es parte fisica del equipo: laptop
    # (integrada siempre) o PC "All in One" (chasis tipo 13) - un desktop con
    # monitor aparte devuelve None a proposito.
    try:
        rows = _wmi_query("SELECT ChassisTypes FROM Win32_SystemEnclosure")
        if not rows:
            return None
        chassis = rows[0].ChassisTypes[0]
        if chassis not in LAPTOP_CHASSIS_CODES and chassis != 13:
            return None
        mon = _wmi_query("SELECT MaxHorizontalImageSize, MaxVerticalImageSize FROM WmiMonitorBasicDisplayParams", "root\\wmi")
        if mon:
            h, v = mon[0].MaxHorizontalImageSize, mon[0].MaxVerticalImageSize
            if h and v:
                diag_cm = (h ** 2 + v ** 2) ** 0.5
                return round(diag_cm / 2.54, 1)
    except Exception:
        pass
    return None


def physical_ram_gb(usable_gb):
    """Redondea al tamano comercial de RAM mas cercano - mismo criterio que
    ya usa el agente Linux (physical_ram_gb)."""
    standards = [1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 32, 48, 64, 96, 128, 192, 256]
    for s in standards:
        if usable_gb <= s + 0.5:
            return s
    return round(usable_gb)


def get_mem_info():
    # GlobalMemoryStatusEx (API nativa de Windows, la misma que usa el
    # Administrador de tareas) en vez de WMI (Win32_OperatingSystem) - visto
    # en produccion: esa consulta WMI puede fallar de forma consistente en un
    # equipo puntual (ciclo tras ciclo, no algo transitorio de un solo
    # arranque) mientras otras consultas WMI en el mismo proceso siguen
    # funcionando bien, y el fallback silencioso a 0 hacia que se reportara
    # "1.0 GB" de RAM total en un equipo con 8GB reales (redondeado hacia
    # arriba por physical_ram_gb al valor comercial mas chico). Esta API no
    # depende del servicio WMI en absoluto.
    try:
        st = win32api.GlobalMemoryStatusEx()
        return {
            "percent":  float(st["MemoryLoad"]),
            "total_gb": physical_ram_gb(st["TotalPhys"] / (1024 ** 3)),
            "used_gb":  round((st["TotalPhys"] - st["AvailPhys"]) / (1024 ** 3), 2),
        }
    except Exception as e:
        write_log(f"WARN: GlobalMemoryStatusEx fallo, usando fallback WMI: {e}")

    rows = _wmi_query("SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem")
    total_mb = round(int(rows[0].TotalVisibleMemorySize) / 1024) if rows else 0
    free_mb  = round(int(rows[0].FreePhysicalMemory) / 1024) if rows else 0
    used_mb  = total_mb - free_mb
    if total_mb:
        return {
            "percent":  round(used_mb / total_mb * 100, 1),
            "total_gb": physical_ram_gb(total_mb / 1024),
            "used_gb":  round(used_mb / 1024, 2),
        }

    # Ambas fuentes fallaron: mejor reportar el total real ya conocido desde
    # el arranque (suma de las memorias fisicas detectadas, ver collect_hw())
    # que un "1.0 GB" absurdo - el % de uso queda sin poder calcularse (0.0,
    # ver nota en send_metrics).
    slot_total = sum(s.get("size_gb", 0) for s in ram.get("detail", []))
    return {"percent": 0.0, "total_gb": slot_total or 0, "used_gb": 0.0}


def _get_disk_info_native_fallback():
    # WMI fallo por completo para Win32_LogicalDisk (misma causa raiz que el
    # bug real de RAM en LAP-ATAFUR - ver get_mem_info) - sin esto,
    # "Almacenamiento" queda vacio en el panel porque physical_disks nunca se
    # llena (el router solo escribe esa tabla si el payload trae algo, ver
    # agents.py). GetLogicalDriveStrings/GetDiskFreeSpaceEx son API nativas,
    # no dependen de WMI. No hay forma de saber el disco fisico real
    # (fabricante/particiones agrupadas) sin WMI, asi que cada letra se
    # reporta como su propio "disco fisico" de 1 particion - mejor que dejarlo
    # vacio.
    disks, physical_disks = [], []
    media_types = _get_disk_media_types()  # probablemente vacio si WMI esta tan roto como para llegar aca, pero no cuesta intentarlo
    try:
        drives = [d for d in win32api.GetLogicalDriveStrings().split("\x00") if d]
        idx = 0
        for drv in drives:
            try:
                if win32file.GetDriveTypeW(drv) != 3:  # DRIVE_FIXED
                    continue
                free_b, total_b, _ = win32api.GetDiskFreeSpaceEx(drv)
            except Exception:
                continue
            total_gb = round(total_b / (1024 ** 3), 1)
            used_gb  = round((total_b - free_b) / (1024 ** 3), 1)
            if total_gb <= 0.1:
                continue
            pct = round(used_gb / total_gb * 100, 1) if total_gb else 0.0
            device = drv.rstrip("\\").rstrip(":")
            disks.append({"device": device, "mountpoint": drv, "total_gb": total_gb,
                           "used_gb": used_gb, "percent": pct, "disk_index": idx})
            # OJO: media_types.get(idx) es un dict ({"type","size_gb","bus_type"}),
            # no un string - un bug real de antes de esta sesion mandaba el
            # dict entero como "media_type" (probablemente la causa de los
            # "HTTP Error 422" vistos en el log de LAP-ATAFUR mientras WMI
            # estuvo roto y esta rama de respaldo se activaba - el backend
            # rechaza el payload si media_type no es str/None). Sin
            # PNPDeviceID en esta rama (no se llego a la consulta WMI de
            # Win32_DiskDrive) no se puede resolver PCIe Gen/lanes, pero
            # SATA/USB si se puede con solo el bus_type.
            extra = media_types.get(idx, {})
            physical_disks.append({"disk_index": idx, "total_gb": total_gb, "used_gb": used_gb,
                                    "percent": pct, "partitions": 1, "media_type": extra.get("type"), "model": None,
                                    "interface": _get_disk_interface(extra.get("bus_type"), None)})
            idx += 1
    except Exception as e:
        write_log(f"WARN: fallback nativo de disco tambien fallo: {e}")
    return {"disks": disks, "physicalDisks": physical_disks}




def _get_disk_media_types():
    """disk_index (mismo indice que Win32_DiskDrive.Index, usado en todo el
    resto de esta funcion) -> {"type": "NVMe SSD"/"SSD"/"HDD"/None,
    "size_gb": tamano real del disco fisico en GB, desde MSFT_PhysicalDisk.
    Size (bytes) - o None}. root\\Microsoft\\Windows\\Storage es un
    namespace WMI aparte (Storage Management API) - MSFT_PhysicalDisk.
    DeviceId coincide con Win32_DiskDrive.Index en la gran mayoria de
    equipos (ambos enumeran los discos fisicos del sistema en el mismo
    orden), pero no hay una asociacion WMI formal entre los dos namespaces
    que lo garantice - es la mejor aproximacion disponible sin agregar una
    dependencia mas pesada (ej. powershell Get-PhysicalDisk). Tambien sirve
    como respaldo del tamano real del disco cuando la cadena de
    ASSOCIATORS Win32_LogicalDiskToPartition/Win32_DiskDriveToDiskPartition
    (unica fuente antes de esto) falla silenciosamente en un equipo puntual
    (visto en produccion: LAP-ATAFUR reportaba el tamano de la particion
    C: -237.4 GB- como si fuera el disco fisico completo -238.46 GB real
    segun Administrador de discos- porque esa cadena de ASSOCIATORS no
    devolvia nada, sin ningun error visible). Si esto falla (namespace no
    disponible en Windows viejo, etc.) no hay dato extra - no se rompe
    nada mas, se usa el metodo viejo."""
    info = {}
    try:
        rows = _wmi_query(
            "SELECT DeviceId, MediaType, BusType, Size FROM MSFT_PhysicalDisk",
            namespace="root\\Microsoft\\Windows\\Storage")
        for r in rows:
            try:
                idx = int(r.DeviceId)
            except Exception:
                continue
            bus_type = getattr(r, "BusType", None)
            media_type = getattr(r, "MediaType", None)
            if bus_type == 17:      # BusTypeNvme
                mtype = "NVMe SSD"
            elif media_type == 4:   # MediaTypeSSD
                mtype = "SSD"
            elif media_type == 3:   # MediaTypeHDD
                mtype = "HDD"
            else:
                mtype = None
            size_raw = getattr(r, "Size", None)
            size_gb = round(int(size_raw) / (1024 ** 3), 1) if size_raw else None
            info[idx] = {"type": mtype, "size_gb": size_gb, "bus_type": bus_type}
    except Exception:
        pass
    return info


def get_disk_info():
    # Solo discos locales (DriveType=3) - excluye unidades de red mapeadas
    # (DriveType=4), que a veces reportan capacidades enormes sin relacion con
    # el almacenamiento real del equipo.
    logical = _wmi_query("SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType=3")
    if not logical:
        return _get_disk_info_native_fallback()

    # Disco fisico real detras de cada letra (dos particiones, ej. C: y D:,
    # pueden estar en el MISMO disco fisico) via las asociaciones WMI
    # estandar Win32_LogicalDiskToPartition / Win32_DiskDriveToDiskPartition.
    disknum_of = {}
    realsize_of = {}
    model_of = {}
    pnpid_of = {}
    for ld in logical:
        device_id = ld.DeviceID
        try:
            partitions = _wmi_query(
                f"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{device_id}'}} "
                f"WHERE AssocClass=Win32_LogicalDiskToPartition")
            for part in partitions:
                drives = _wmi_query(
                    f"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{part.DeviceID}'}} "
                    f"WHERE AssocClass=Win32_DiskDriveToDiskPartition")
                for d in drives:
                    disknum_of[device_id] = d.Index
                    realsize_of[d.Index] = round(int(d.Size) / (1024 ** 3), 1)
                    # .Model (marca/modelo real, ej. "Samsung SSD 980 500GB")
                    # y .PNPDeviceID (para subir al controlador PCI y leer la
                    # interfaz - ver _get_pcie_link_info) vienen gratis en el
                    # mismo objeto ASSOCIATORS, sin consulta aparte. Aislado
                    # en su propio try: en produccion (LAP-ATAFUR) se vio
                    # total_gb correcto pero model siempre None - el fetch de
                    # .Model via COM puede lanzar su propio error (no
                    # AttributeError, asi que getattr(...,"") no lo tapa) y el
                    # except de mas abajo se lo tragaba en silencio junto con
                    # todo lo demas.
                    try:
                        model_of[d.Index] = (getattr(d, "Model", "") or "").strip()
                        pnpid_of[d.Index] = (getattr(d, "PNPDeviceID", "") or "").strip()
                    except Exception as e:
                        write_log(f"WARN: no se pudo leer Model/PNPDeviceID de Win32_DiskDrive #{d.Index}: {e}")
                    break
                break
        except Exception:
            pass

    disks_raw = []
    for ld in logical:
        total_gb = round(int(ld.Size or 0) / (1024 ** 3), 1)
        free_gb  = round(int(ld.FreeSpace or 0) / (1024 ** 3), 1)
        used_gb  = round(total_gb - free_gb, 1)
        if total_gb <= 0.1:
            continue
        pct = round(used_gb / total_gb * 100, 1) if total_gb else 0.0
        disknum = disknum_of.get(ld.DeviceID, -1)
        disks_raw.append({"device": ld.DeviceID.rstrip(":"), "mountpoint": ld.DeviceID + "\\",
                           "total_gb": total_gb, "used_gb": used_gb, "percent": pct, "disknum": disknum})

    disknums = sorted({d["disknum"] for d in disks_raw})
    index_of = {n: i for i, n in enumerate(disknums)}

    disks = [{
        "device": d["device"], "mountpoint": d["mountpoint"], "total_gb": d["total_gb"],
        "used_gb": d["used_gb"], "percent": d["percent"], "disk_index": index_of[d["disknum"]],
    } for d in disks_raw]

    used_by_disk = {}
    for d in disks_raw:
        entry = used_by_disk.setdefault(d["disknum"], {"used": 0.0, "count": 0})
        entry["used"] += d["used_gb"]
        entry["count"] += 1

    wmi_disk_info = _get_disk_media_types()
    physical_disks = []
    for disknum in disknums:
        info = used_by_disk[disknum]
        used_gb = round(info["used"], 1)
        extra = wmi_disk_info.get(disknum, {})
        # MSFT_PhysicalDisk.Size (si esta disponible) es mas confiable que
        # la cadena de ASSOCIATORS de arriba - ver comentario en
        # _get_disk_media_types(). Solo se usa si es MAYOR que lo que ya se
        # tenia (nunca conviene "achicar" el tamano real de un disco por un
        # dato de otra fuente que podria estar mal indexado). Se probo
        # tambien un tamano nativo via IOCTL_DISK_GET_LENGTH_INFO
        # (\\.\PhysicalDriveN, sin depender de WMI) para el caso en que
        # ADEMAS falle esta ruta WMI - se revirtio: en produccion
        # (LAP-ATAFUR) ese IOCTL da "Acceso denegado" incluso corriendo
        # como LocalSystem, casi seguro por la proteccion de acceso a disco
        # crudo de Kaspersky (instalado en ese equipo) - no vale la pena
        # reintentar una llamada de acceso a disco fisico bloqueada cada
        # ciclo de metricas solo por un desajuste de tamano menor al 1%.
        real_total = realsize_of.get(disknum, used_gb)
        if extra.get("size_gb") and extra["size_gb"] > real_total:
            real_total = extra["size_gb"]
        pct = round(used_gb / real_total * 100, 1) if real_total else 0.0
        physical_disks.append({"disk_index": index_of[disknum], "total_gb": real_total,
                                "used_gb": used_gb, "percent": pct, "partitions": info["count"],
                                "media_type": extra.get("type"), "model": model_of.get(disknum) or None,
                                "interface": _get_disk_interface(extra.get("bus_type"), pnpid_of.get(disknum))})

    return {"disks": disks, "physicalDisks": physical_disks}


def _enable_debug_privilege():
    """Habilita SeDebugPrivilege en el token del proceso actual.

    Bug real (agosto 2026): en equipos recien instalados con este agente
    (build que reemplazo la lectura de procesos via WMI por OpenProcess
    nativo, ver _processes_snapshot), la lista de procesos llegaba SIEMPRE
    vacia - "top_processes": [] en cada metrica, sin excepcion visible en
    el log (cada OpenProcess individual esta en su propio try/except que
    solo hace `continue`). En equipos con una instalacion mas vieja (que
    todavia usaba la consulta WMI) la lista si llegaba bien, lo que
    descartaba un problema del equipo en si.

    Causa: el servicio corre como LocalSystem, que SI tiene
    SeDebugPrivilege en su token, pero un privilegio "presente" no es lo
    mismo que "habilitado" - por defecto queda deshabilitado y hace falta
    encenderlo a mano con AdjustTokenPrivileges. Sin él, OpenProcess con
    PROCESS_VM_READ devuelve access denied para practicamente cualquier
    proceso que no pertenezca a la misma sesion/cuenta - en la practica,
    casi todos menos el propio agente - y como _processes_snapshot()
    descarta cada fallo en silencio, el resultado final es una lista vacia
    sin ningun rastro del motivo real."""
    try:
        htoken = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY)
        priv_id = win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME)
        win32security.AdjustTokenPrivileges(htoken, False, [(priv_id, win32security.SE_PRIVILEGE_ENABLED)])
        htoken.Close()
    except Exception as e:
        write_log(f"WARN: no se pudo habilitar SeDebugPrivilege (la lista de procesos puede llegar vacia): {e}")


def _processes_snapshot():
    """PID -> {name, mem, cpu_100ns, disk_bytes, user, creation_epoch} via
    EnumProcesses/OpenProcess + GetProcessMemoryInfo/GetProcessTimes/
    GetProcessIoCounters/OpenProcessToken - las mismas API nativas que usa
    el Administrador de tareas por debajo, sin pasar por WMI ni por PDH.

    Historia: primero se uso Win32_PerfFormattedData_PerfProc_Process (WMI)
    para CPU/RAM por proceso, con un respaldo via win32pdh si esa consulta
    fallaba (puede fallar de forma consistente en un equipo puntual, mismo
    problema ya resuelto para RAM/disco/red - ver get_mem_info/
    _adapter_friendly_names). Ese respaldo de PDH (AddEnglishCounter con
    comodin \\Process(*)\\...) PARECIA funcionar pero en realidad SUBCONTABA
    procesos con varias instancias (ej. svchost, que normalmente tiene
    decenas) - GetFormattedCounterArray devolvia una sola instancia
    "svchost" en vez de "svchost#1", "svchost#2", etc. Confirmado
    comparando contra el uso real: svchost real ~825MB, el respaldo de PDH
    reportaba ~1.2MB - un bug silencioso, mas peligroso que un fallo
    abierto porque parecia datos validos.

    Ademas, ni WMI ni PDH exponen usuario/IO de disco/hora de inicio por
    proceso de forma simple - como de todas formas hacia falta enumerar
    proceso por proceso para esos datos nuevos, esto paso a ser el UNICO
    camino (se elimino el intento de WMI para esta funcion especifica)."""
    data = {}
    try:
        pids = win32process.EnumProcesses()
    except Exception:
        return data
    for pid in pids:
        if pid == 0:
            continue
        try:
            h = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
        except Exception:
            continue
        try:
            try:
                path = win32process.GetModuleFileNameEx(h, 0)
                name = os.path.splitext(os.path.basename(path))[0]
            except Exception:
                continue
            try:
                mem = win32process.GetProcessMemoryInfo(h)
                ws = mem.get("WorkingSetSize", 0)
            except Exception:
                ws = 0
            try:
                t = win32process.GetProcessTimes(h)
                cpu_100ns = t["KernelTime"] + t["UserTime"]
                creation_epoch = t["CreationTime"].timestamp()
            except Exception:
                cpu_100ns = 0
                creation_epoch = None
            try:
                io = win32process.GetProcessIoCounters(h)
                disk_bytes = int(io.get("ReadTransferCount", 0)) + int(io.get("WriteTransferCount", 0))
            except Exception:
                disk_bytes = 0
            user = None
            try:
                tok = win32security.OpenProcessToken(h, win32con.TOKEN_QUERY)
                sid, _ = win32security.GetTokenInformation(tok, win32security.TokenUser)
                user, _domain, _typ = win32security.LookupAccountSid(None, sid)
            except Exception:
                pass
            data[pid] = {"name": name, "mem": ws, "cpu_100ns": cpu_100ns,
                         "disk_bytes": disk_bytes, "user": user, "creation_epoch": creation_epoch}
        finally:
            h.Close()
    return data


def get_top_processes(total_ram_gb):
    """Devuelve (lista de hasta 100 procesos agrupados por nombre ordenados
    por CPU, cantidad total de procesos distintos detectados) - ver
    _processes_snapshot() para de donde sale cada dato. "Red" por proceso
    queda deliberadamente afuera: Windows no tiene una API nativa simple
    para eso (solo ETW/WFP, mucho mas complejo y fragil de meter aca) -
    "Estado" se reporta fijo como en ejecucion, ya que todo lo que aparece
    en esta lista es, por definicion, un proceso vivo en el momento de la
    foto."""
    try:
        s1 = _processes_snapshot()
        time.sleep(0.5)
        s2 = _processes_snapshot()
    except Exception as e:
        write_log(f"WARN: no se pudieron leer los procesos: {e}")
        return [], 0

    now = time.time()
    grouped = {}
    for pid, d2 in s2.items():
        d1 = s1.get(pid)
        cpu_pct = 0.0
        if d1:
            delta = d2["cpu_100ns"] - d1["cpu_100ns"]
            cpu_pct = max(0.0, delta / 5_000_000 * 100.0)  # 0.5s de intervalo, unidades de 100ns
        disk_kb_s = 0.0
        if d1:
            delta_bytes = d2["disk_bytes"] - d1["disk_bytes"]
            disk_kb_s = max(0.0, delta_bytes / 1024 / 0.5)  # 0.5s de intervalo
        name = d2["name"]
        if not name or name in ("_Total", "Idle", "System Idle Process"):
            continue
        g = grouped.setdefault(name, {"cpu": 0.0, "mem_bytes": 0, "disk_kb_s": 0.0,
                                       "user": d2["user"], "uptime_min": None})
        g["cpu"] += cpu_pct
        g["mem_bytes"] += d2["mem"]
        g["disk_kb_s"] += disk_kb_s
        if d2["creation_epoch"] and (g["uptime_min"] is None or d2["creation_epoch"] < g.get("_oldest_epoch", d2["creation_epoch"])):
            g["_oldest_epoch"] = d2["creation_epoch"]
            g["uptime_min"] = round((now - d2["creation_epoch"]) / 60, 1)

    procs = []
    for name, g in grouped.items():
        mem_pct = round(g["mem_bytes"] / (total_ram_gb * 1024 ** 3) * 100, 1) if total_ram_gb else 0.0
        procs.append({
            "name": name, "cpu": round(g["cpu"], 1), "mem": mem_pct,
            "disk_kb_s": round(g["disk_kb_s"], 1), "user": g["user"],
            "uptime_min": g["uptime_min"],
        })
    procs.sort(key=lambda p: -p["cpu"])
    return procs[:100], len(procs)


_net_ignore_keywords = ("loopback", "isatap", "teredo", "tailscale", "tunnel", "pseudo")

def get_system_throughput():
    """Disco (MB/s lectura/escritura) y Red (Mbps bajada/subida) del
    sistema entero, ambos via win32pdh con AddEnglishCounter (no WMI, no
    depende del idioma de Windows - ver get_cpu_percent para el mismo
    patron). Disco usa la instancia unica "_Total" (funciona igual que el
    contador de CPU); Red SI necesita comodin (\\Network Interface(*)\\...)
    porque "_Total" no existe como instancia para ese objeto - a diferencia
    del comodin de \\Process(*)\\... (ver _processes_snapshot para ese bug),
    este SI devuelve una instancia separada por cada adaptador real,
    confirmado con un build real - se suman todas, salvo loopback/tuneles."""
    try:
        query = win32pdh.OpenQuery()
        try:
            h_dr = win32pdh.AddEnglishCounter(query, r"\PhysicalDisk(_Total)\Disk Read Bytes/sec")
            h_dw = win32pdh.AddEnglishCounter(query, r"\PhysicalDisk(_Total)\Disk Write Bytes/sec")
            h_nr = win32pdh.AddEnglishCounter(query, r"\Network Interface(*)\Bytes Received/sec")
            h_ns = win32pdh.AddEnglishCounter(query, r"\Network Interface(*)\Bytes Sent/sec")
            win32pdh.CollectQueryData(query)
            time.sleep(0.5)
            win32pdh.CollectQueryData(query)
            _, dr = win32pdh.GetFormattedCounterValue(h_dr, win32pdh.PDH_FMT_DOUBLE)
            _, dw = win32pdh.GetFormattedCounterValue(h_dw, win32pdh.PDH_FMT_DOUBLE)
            nr_by_if = win32pdh.GetFormattedCounterArray(h_nr, win32pdh.PDH_FMT_DOUBLE)
            ns_by_if = win32pdh.GetFormattedCounterArray(h_ns, win32pdh.PDH_FMT_DOUBLE)
        finally:
            win32pdh.CloseQuery(query)
    except Exception as e:
        write_log(f"WARN: no se pudo leer el throughput de disco/red: {e}")
        return {"disk_read_mb_s": 0.0, "disk_write_mb_s": 0.0, "net_down_mbps": 0.0, "net_up_mbps": 0.0}

    def _sum_real_ifs(by_if):
        total = 0.0
        for iface, val in by_if.items():
            low = (iface or "").lower()
            if any(k in low for k in _net_ignore_keywords):
                continue
            total += float(val or 0)
        return total

    nr = _sum_real_ifs(nr_by_if)
    ns = _sum_real_ifs(ns_by_if)
    return {
        "disk_read_mb_s":  round(dr / (1024 ** 2), 2),
        "disk_write_mb_s": round(dw / (1024 ** 2), 2),
        "net_down_mbps":   round(nr * 8 / (1000 ** 2), 2),
        "net_up_mbps":     round(ns * 8 / (1000 ** 2), 2),
    }


def get_installed_software():
    paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    seen = {}
    for hive, path in paths:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(key)[0]):
            try:
                subkey_name = winreg.EnumKey(key, i)
                subkey = winreg.OpenKey(key, subkey_name)
                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                if not name or not name.strip():
                    continue
                name = name.strip()
                if name in seen:
                    continue
                try:
                    version = winreg.QueryValueEx(subkey, "DisplayVersion")[0].strip()
                except Exception:
                    version = ""
                seen[name] = {"name": name, "version": version}
            except Exception:
                continue
        winreg.CloseKey(key)
    return sorted(seen.values(), key=lambda s: s["name"].lower())


# ── Wifi SSID / bloqueo ──────────────────────────────────────────────────────
def get_wifi_ssid():
    # Importante: Windows suele nombrar el perfil con un sufijo " 2"/" 3" si hay
    # perfiles duplicados, asi que 'Profile' NO es el SSID real. Se prioriza el
    # SSID real y solo se usa el nombre de perfil como ultimo recurso.
    try:
        out = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                              capture_output=True, text=True, timeout=5,
                              creationflags=subprocess.CREATE_NO_WINDOW).stdout
        for line in out.splitlines():
            m = re.match(r"^\s*SSID\s*:\s*(.+)$", line)
            if m and "BSSID" not in line:
                v = m.group(1).strip()
                if v:
                    return v
    except Exception:
        pass
    try:
        rows = _wmi_query("SELECT Ndis80211SsId FROM MSNdis_80211_ServiceSetIdentifier", "root\\wmi")
        for r in rows:
            raw = r.Ndis80211SsId
            if raw and raw.get("SsId"):
                b = bytes(raw["SsId"][:raw.get("SsIdLength", len(raw["SsId"]))])
                s = "".join(chr(c) for c in b if 32 <= c <= 126)
                if s.strip():
                    return s.strip()
    except Exception:
        pass
    try:
        out = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                              capture_output=True, text=True, timeout=5,
                              creationflags=subprocess.CREATE_NO_WINDOW).stdout
        for line in out.splitlines():
            m = re.match(r"^\s*Profile\s*:\s*(.+)$", line)
            if m:
                v = re.sub(r"\s+\d+$", "", m.group(1).strip())
                if v:
                    return v
    except Exception:
        pass
    return None


def get_blocklist():
    """Ya no decide nada del DNS local (eso ahora es fijo, ver
    ensure_local_dns) - se sigue llamando solo como heartbeat que reporta el
    SSID actual, para que el gate de red del lado servidor (resolve_dns_query,
    apply_gate=True) tenga un SSID reciente con el que evaluar."""
    try:
        ssid = get_wifi_ssid()
        ssid_param = urllib.parse.quote(ssid or "")
        serial_param = urllib.parse.quote(hw.get("serial_number", "") or "")
        write_log(f"BLOCKLIST consultando (hostname={HOSTNAME_PC} ssid='{ssid}')")
        url = f"{SERVER}/api/agents/blocklist?hostname={HOSTNAME_PC}&ssid={ssid_param}&serial={serial_param}"
        r = urllib.request.urlopen(url, timeout=5)
        j = json.loads(r.read())
        return {"ShouldBlock": bool(j.get("should_block", True)), "AllDomains": j.get("all_domains", [])}
    except Exception as e:
        write_log(f"BLOCKLIST ERROR consultando: {e}")
        return None


# ── DNS: se fija UNA vez a 127.0.0.1 (cloudflared), nunca se vuelve a tocar ──
def _adapter_friendly_names():
    """Nombres de interfaz (los que usa netsh, ej. 'Wi-Fi') de cada adaptador
    con IP habilitada - "netsh interface ipv4 show interfaces", NO WMI. Bug
    real encontrado (LAP-ATAFUR, Windows 11 en espanol): esto antes cruzaba
    Win32_NetworkAdapterConfiguration con Win32_NetworkAdapter por WMI, que
    puede fallar de forma consistente en un equipo puntual (mismo problema ya
    visto y resuelto para RAM/disco, ver get_mem_info/get_disk_info) - con
    WMI roto esta lista quedaba vacia EN SILENCIO (el unico log posible
    estaba adentro del for de ensure_local_dns(), que con la lista vacia
    nunca llegaba a ejecutarse ni una vez), asi que el DNS del sistema nunca
    se fijaba a 127.0.0.1 y el bloqueo de contenido quedaba sin efecto pese a
    que cloudflared y el certificado CA estaban perfectos - nada en el log
    delataba el problema. Parseo de "netsh ... show interfaces" por
    POSICION de columna (indice numerico al inicio de la fila + todo desde
    la 5ta palabra en adelante es el nombre), nunca por el texto de los
    encabezados (esos si estan en espanol en un Windows en espanol, "Estado"
    en vez de "State" - confirmado en este mismo equipo)."""
    names = []
    try:
        out = subprocess.run(
            ["netsh.exe", "interface", "ipv4", "show", "interfaces"],
            capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW,
            text=True, errors="replace").stdout
        for line in out.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 5 or not parts[0].isdigit():
                continue
            name = parts[4].strip()
            if name and "loopback" not in name.lower():
                names.append(name)
    except Exception as e:
        write_log(f"WARN: no se pudo listar interfaces de red (netsh): {e}")
    return names


def _disable_ipv6_dns(name):
    """netsh (no PowerShell) - fuerza DNS IPv6 estatico vacio en la interfaz.
    Si el adaptador tiene (o aprende por Router Advertisement) un servidor
    DNS IPv6, Windows puede usarlo saltandose por completo
    127.0.0.1/cloudflared, lo que anula el filtrado. Confirmado en un equipo
    real ademas: un DNS IPv6 viejo/colgado tumbaba TODA la resolucion de
    nombres pese a que el IPv4 (127.0.0.1) andaba bien. "source=static
    address=none" pisa lo aprendido por RA - a diferencia de "source=dhcp" o
    borrar la lista, que no lo limpia hasta que esa RA expira/renueva."""
    subprocess.run(
        ["netsh.exe", "interface", "ipv6", "set", "dnsservers",
         f"name={name}", "source=static", "address=none", "validate=no"],
        capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)


def _set_ipv4_dns(name):
    """netsh, no WMI: Win32_NetworkAdapterConfiguration.Get() por SettingID
    (el patron usado antes) falla con "Ruta de acceso del objeto no valida"
    cuando el SettingID es un GUID con llaves (confirmado con un build real
    en una maquina donde el adaptador de red tenia ese formato de
    SettingID - en otras con SettingID numerico simple no pasaba) - netsh
    identifica la interfaz por nombre, no por ese path COM, asi que no
    depende para nada del formato de SettingID."""
    subprocess.run(
        ["netsh.exe", "interface", "ipv4", "set", "dnsservers",
         f"name={name}", "source=static", f"address={LOCAL_DNS_IP}",
         "register=none", "validate=no"],
        capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)


def ensure_local_dns():
    for name in _adapter_friendly_names():
        try:
            _set_ipv4_dns(name)
            _disable_ipv6_dns(name)
        except Exception as e:
            write_log(f"WARN: no se pudo fijar el DNS local en {name}: {e}")


def ensure_hosts_entry(hostname, ip):
    """Mantiene una linea idempotente en el archivo hosts (mismo patron de
    linea-marcada que ya usa el agente Linux en resolv.conf) - le da a
    cloudflared una URL con SNI valido (ver dns_blocker.py/tls_ca.py) hacia la
    IP del tunel WireGuard, que puede cambiar."""
    try:
        lines = []
        if os.path.exists(HOSTS_FILE):
            with open(HOSTS_FILE, encoding="utf-8", errors="ignore") as f:
                lines = [l for l in f.read().splitlines()
                         if HOSTS_MARKER not in l and hostname not in l]
        if ip:
            lines.append(f"{ip} {hostname}  {HOSTS_MARKER}")
        with open(HOSTS_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception as e:
        write_log(f"WARN: no se pudo actualizar el archivo hosts: {e}")


# Se prende cuando el Servicio de Windows recibe SvcStop (ver
# SmartMonitorService abajo) - todos los hilos de fondo (loop principal,
# supervisor de cloudflared, watcher de red) lo consultan en vez de "while
# True" para poder cortar de inmediato y que el Administrador de Servicios no
# tenga que forzar el proceso.
_stop_event = threading.Event()

# ── cloudflared (proxy-dns) como proceso hijo supervisado ───────────────────
_cloudflared_proc = None

def _kill_stray_cloudflared():
    try:
        rows = _wmi_query("SELECT ProcessId, ExecutablePath FROM Win32_Process WHERE Name='cloudflared.exe'")
        for r in rows:
            if r.ExecutablePath and r.ExecutablePath.lower() == CLOUDFLARED_EXE.lower():
                try:
                    _wmi().Get(f"Win32_Process.Handle='{r.ProcessId}'").Terminate()
                except Exception:
                    pass
    except Exception:
        pass


def supervise_cloudflared():
    """Reinicia cloudflared si muere, con backoff - corre en un hilo en
    segundo plano durante toda la vida del agente. La Tarea Programada ya
    reinicia el PROCESO PADRE si muere (red de seguridad de ~1 min); esto
    cubre el caso mas comun de que solo cloudflared se caiga mientras el
    agente sigue vivo, sin esperar ese minuto."""
    global _cloudflared_proc
    # Este hilo tambien hace llamadas WMI (_kill_stray_cloudflared) - necesita
    # su propio CoInitialize(), igual que main() (ver comentario ahi mismo y
    # en _wmi()/_wmi_local mas arriba).
    if pythoncom is not None:
        try:
            pythoncom.CoInitialize()
        except Exception as e:
            write_log(f"WARN: CoInitialize fallo (hilo cloudflared): {e}")
    _kill_stray_cloudflared()
    backoff = 2
    while not _stop_event.is_set():
        try:
            _cloudflared_proc = subprocess.Popen(
                [CLOUDFLARED_EXE, "proxy-dns", "--address", "127.0.0.1", "--port", "53",
                 "--upstream", f"https://{DOH_HOSTNAME}/dns-query",
                 # Respaldo si el tunel WireGuard no es alcanzable (equipo en
                 # otra red, ej. en casa) - --upstream repetido es failover,
                 # NO reparto de trafico: confirmado con una prueba real
                 # (mismo binario, upstream primario roto a proposito) que
                 # cloudflared abre una sola conexion persistente al primero
                 # y solo pasa al siguiente si ese falla del todo. Sin esto,
                 # un tunel caido dejaba el equipo entero sin poder resolver
                 # NINGUN nombre (no solo sin bloqueo) - el server sigue
                 # decidiendo el bloqueo real solo cuando este upstream
                 # responde.
                 "--upstream", "https://cloudflare-dns.com/dns-query"],
                creationflags=subprocess.CREATE_NO_WINDOW)
            write_log(f"cloudflared iniciado (pid={_cloudflared_proc.pid})")
            start_ts = time.time()
            _cloudflared_proc.wait()
            if _stop_event.is_set():
                break
            # Bug real encontrado en produccion (LAP-ATAFUR): el backoff se
            # reseteaba a 2s apenas Popen() arrancaba el proceso, sin
            # importar cuanto duro corriendo - si cloudflared se cae solo al
            # instante en cada intento (ej. mientras el hosts entry/Tailscale
            # todavia no estan listos tras una reconexion), esto nunca
            # llegaba a esperar mas de 2s entre reintentos, generando una
            # rafaga de decenas de procesos en pocos segundos - patron que
            # Kaspersky (System Watcher) termino matando junto con el propio
            # agente. Ahora el backoff solo se resetea si el proceso se
            # mantuvo vivo un tiempo razonable (10s) antes de caer - una
            # caida rapida y repetida ahora si deja que el backoff crezca.
            if time.time() - start_ts >= 10:
                backoff = 2
            write_log(f"cloudflared se cayo (exit={_cloudflared_proc.returncode}), reintentando en {backoff}s")
        except Exception as e:
            write_log(f"WARN: no se pudo iniciar cloudflared: {e}")
        if _stop_event.wait(backoff):
            break
        backoff = min(backoff * 2, 30)


# ── Tailscale / WireGuard ────────────────────────────────────────────────────
def get_tailscale_ip():
    try:
        if not os.path.exists(TAILSCALE_EXE):
            return None
        out = subprocess.run([TAILSCALE_EXE, "ip", "-4"], capture_output=True, text=True,
                              timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return None


def setup_wireguard_tunnel():
    """Registra este equipo en el tunel WireGuard (Headscale) si todavia no
    lo esta. No es indispensable: si falla o Tailscale no esta instalado, el
    endpoint DoH sigue siendo alcanzable por la ruta publica (fallback
    documentado en el plan si cloudflared no confia en la CA propia)."""
    global tailnet_ip, tailnet_server_ip
    try:
        if not os.path.exists(TAILSCALE_EXE):
            write_log("WireGuard: cliente Tailscale no instalado, se omite")
            return
        existing_ip = get_tailscale_ip()
        if existing_ip:
            tailnet_ip = existing_ip
            if not tailnet_server_ip:
                try:
                    tailnet_server_ip = _register_wireguard().get("server_tailnet_ip")
                except Exception:
                    pass
            return

        # Antes de pedir una llave de pre-autenticacion NUEVA (que Headscale
        # trata como una alta/reautenticacion, no como "seguir la sesion que
        # ya tenia"), probar primero un "tailscale up" simple, SIN --authkey.
        # Bug real encontrado en produccion (LAP-ATAFUR): forzar SIEMPRE una
        # llave nueva cada vez que get_tailscale_ip() devolvia vacio (que
        # puede pasar por un blip transitorio de red, no solo por un logout
        # real) terminaba siendo la CAUSA del problema que se suponia
        # arreglar - cada reconexion de mas generaba un logout real del lado
        # de Headscale, entrando en un ciclo de "reconecta un momento, se
        # cae de nuevo" que se repetia solo. Si el nodo ya tiene sesion
        # guardada localmente, este "up" simple alcanza para reconectar sin
        # tocar nada del lado del servidor - la llave nueva queda como
        # ultimo recurso, solo si esto de verdad no alcanza.
        write_log("WireGuard: sin IP, probando reconectar con la sesion existente...")
        try:
            subprocess.run([TAILSCALE_EXE, "up", "--timeout=15s"],
                            capture_output=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            pass
        time.sleep(2)
        existing_ip = get_tailscale_ip()
        if existing_ip:
            tailnet_ip = existing_ip
            write_log(f"WireGuard: reconectado con la sesion existente, IP={tailnet_ip}")
            if not tailnet_server_ip:
                try:
                    tailnet_server_ip = _register_wireguard().get("server_tailnet_ip")
                except Exception:
                    pass
            return

        write_log("WireGuard: sin conectar, pidiendo pre-auth key al servidor...")
        reg = _register_wireguard()
        tailnet_server_ip = reg.get("server_tailnet_ip")
        subprocess.run(
            [TAILSCALE_EXE, "up", f"--login-server={reg['login_server']}",
             f"--authkey={reg['authkey']}", f"--hostname={HOSTNAME_PC}",
             "--accept-dns=false", "--timeout=30s"],
            capture_output=True, timeout=35, creationflags=subprocess.CREATE_NO_WINDOW)
        time.sleep(3)
        tailnet_ip = get_tailscale_ip()
        if tailnet_ip:
            write_log(f"WireGuard: conectado, IP={tailnet_ip} (server={tailnet_server_ip})")
        else:
            write_log("WARN: WireGuard no conecto (reintenta solo)")
    except Exception as e:
        write_log(f"WARN: no se pudo configurar WireGuard: {e}")


def _register_wireguard():
    body = json.dumps({"hostname": HOSTNAME_PC}).encode()
    req = urllib.request.Request(f"{SERVER}/api/agents/wireguard/preauthkey",
                                  data=body, headers={"Content-Type": "application/json"}, method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=10).read())


# ── Hardware (una sola vez al arrancar) ──────────────────────────────────────
def collect_hw():
    try:
        cs  = _wmi_query("SELECT Manufacturer, Model FROM Win32_ComputerSystem")[0]
        cpu = _wmi_query("SELECT Name, NumberOfCores FROM Win32_Processor")[0]
        bio = _wmi_query("SELECT SerialNumber FROM Win32_BIOS")[0]
        os_ = _wmi_query("SELECT Version FROM Win32_OperatingSystem")[0]
        hw_ = {
            "manufacturer": cs.Manufacturer, "model": cs.Model,
            "serial_number": bio.SerialNumber, "cpu_model": (cpu.Name or "").strip(),
            "cpu_cores": int(cpu.NumberOfCores or 0), "os_version": os_.Version,
        }
        arrays = _wmi_query("SELECT MemoryDevices, MaxCapacity, MaxCapacityEx FROM Win32_PhysicalMemoryArray")
        total_slots = int(arrays[0].MemoryDevices) if arrays else 0
        # MaxCapacityEx (KB, 64-bit) cubre el caso de placas con mas de 2TB
        # soportados donde MaxCapacity (32-bit) queda truncado/0xFFFFFFFF -
        # se prefiere si esta presente. Ambos vienen en KB.
        max_capacity_gb = None
        if arrays:
            max_cap_kb = getattr(arrays[0], "MaxCapacityEx", None) or getattr(arrays[0], "MaxCapacity", None)
            if max_cap_kb:
                max_capacity_gb = round(int(max_cap_kb) / (1024 ** 2))
        # FormFactor (DIMM de escritorio vs SODIMM de portatil/compacto) SI
        # esta en Win32_PhysicalMemory - a diferencia de la latencia CAS,
        # que no esta expuesta por WMI en ningun lado (requeriria leer el
        # SPD crudo por SMBus, fuera de alcance - mismo tipo de operacion
        # de bajo nivel que la lectura de disco fisico via IOCTL que se
        # probo y se descarto por bloqueo del antivirus).
        form_factor_map = {8: "DIMM", 12: "SODIMM", 11: "RIMM", 13: "SRIMM"}
        ddr_map = {20: "DDR", 21: "DDR2", 24: "DDR3", 26: "DDR4", 34: "DDR5"}
        slots = []
        for m in _wmi_query("SELECT DeviceLocator, Capacity, SMBIOSMemoryType, MemoryType, "
                             "Speed, Manufacturer, PartNumber, FormFactor FROM Win32_PhysicalMemory"):
            t = ddr_map.get(int(m.SMBIOSMemoryType or 0)) or ddr_map.get(int(m.MemoryType or 0)) or "DDR"
            slots.append({
                "slot": m.DeviceLocator, "size_gb": round(int(m.Capacity or 0) / (1024 ** 3)),
                "type": t, "speed": f"{m.Speed} MT/s" if m.Speed else "",
                "manufacturer": (m.Manufacturer or "").strip(),
                "part_number": (m.PartNumber or "").strip(), "installed": True,
                "form_factor": form_factor_map.get(int(m.FormFactor or 0)),
            })
        ram_ = {"used": len(slots), "total": total_slots or len(slots), "detail": slots,
                "max_capacity_gb": max_capacity_gb}
        write_log(f"Hardware OK - {hw_['cpu_model']}")
        return hw_, ram_
    except Exception as e:
        write_log(f"ERROR recopilando hardware: {e}")
        return ({"manufacturer": "", "model": "", "serial_number": "", "cpu_model": "",
                  "cpu_cores": 0, "os_version": ""},
                 {"used": 0, "total": 0, "detail": [], "max_capacity_gb": None})


hw, ram = collect_hw()


# ── Envio de metricas ─────────────────────────────────────────────────────────
def send_metrics(sw_to_send):
    mem = get_mem_info()
    cpu = get_cpu_percent()
    disk_info = get_disk_info()
    disks, physical_disks = disk_info["disks"], disk_info["physicalDisks"]
    procs, process_count = get_top_processes(mem["total_gb"])
    throughput = get_system_throughput()

    # % de disco reportado para el dashboard/inventario: la unidad de sistema
    # (normalmente C:) es la referencia mas simple y confiable, ya viene de
    # Win32_LogicalDisk sin pasar por las ASSOCIATORS de disco fisico (que en
    # algunas maquinas fallan por completo - visto en produccion: physical_disks
    # queda vacio aunque "disks" si tenga datos correctos). Antes esto dependia
    # de encontrar el disco fisico via physical_disks y caia a 0% si esa
    # asociacion fallaba, aunque el propio C: tuviera datos validos.
    sys_drive = os.environ.get("SystemDrive", "C:").rstrip(":")
    sys_disk = next((d for d in disks if d["device"] == sys_drive), None)
    if sys_disk is not None:
        disk_pct = sys_disk["percent"]
    elif physical_disks:
        disk_pct = max(physical_disks, key=lambda p: p["total_gb"])["percent"]
    elif disks:
        # Sin drive de sistema identificado y sin physical_disks: usar el disco
        # logico mas grande, descartando unidades de red mapeadas con
        # capacidades absurdas (mismo umbral de sanidad que ya usa el panel).
        sane = [d for d in disks if d["total_gb"] <= 5000]
        disk_pct = max((sane or disks), key=lambda d: d["total_gb"])["percent"]
    else:
        # WMI (Win32_LogicalDisk) fallo por completo esta vez - mismo caso
        # real que el de RAM en get_mem_info(): GetDiskFreeSpaceEx es la API
        # nativa de Windows, no depende de WMI, ultimo respaldo antes de
        # reportar un 0% enganoso.
        try:
            free_b, total_b, _ = win32api.GetDiskFreeSpaceEx(sys_drive + ":\\")
            disk_pct = round((total_b - free_b) / total_b * 100, 1) if total_b else 0
        except Exception as e:
            write_log(f"WARN: GetDiskFreeSpaceEx fallo: {e}")
            disk_pct = 0

    payload = {
        "hostname": HOSTNAME_PC, "os": "windows", "os_version": hw.get("os_version"),
        "manufacturer": hw.get("manufacturer"), "model": hw.get("model"),
        "serial_number": hw.get("serial_number"), "cpu_model": hw.get("cpu_model"),
        "cpu_cores": hw.get("cpu_cores"), "ram_slots_total": ram.get("total"),
        "ram_slots_used": ram.get("used"), "ram_total_gb": mem["total_gb"],
        "cpu_percent": cpu, "ram_percent": mem["percent"], "ram_used_gb": mem["used_gb"],
        "disk_percent": disk_pct, "net_rx_mb": 0, "net_tx_mb": 0, "cpu_temp": get_cpu_temp(),
        "latency_ms": last_latency_ms, "disks": disks, "physical_disks": physical_disks,
        "top_processes": procs, "process_count": process_count,
        "ram_slots_detail": ram.get("detail", []),
        "ram_max_capacity_gb": ram.get("max_capacity_gb"),
        "installed_software": sw_to_send, "screen_size_in": get_screen_size_in(),
        "tailnet_ip": tailnet_ip,
        "disk_read_mb_s": throughput["disk_read_mb_s"], "disk_write_mb_s": throughput["disk_write_mb_s"],
        "net_down_mbps": throughput["net_down_mbps"], "net_up_mbps": throughput["net_up_mbps"],
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(f"{SERVER}/api/agents/metrics", data=data,
                                  headers={"Content-Type": "application/json; charset=utf-8"}, method="POST")
    urllib.request.urlopen(req, timeout=10)


def get_interval():
    global last_latency_ms
    try:
        t0 = time.time()
        r = urllib.request.urlopen(f"{SERVER}/api/config/interval", timeout=3)
        last_latency_ms = round((time.time() - t0) * 1000, 1)
        cfg = json.loads(r.read())
        interval = max(3, int(cfg.get("interval", 60)))
        blocklist_poll = max(60, int(cfg.get("blocklist_interval", 60)))
        return interval, blocklist_poll
    except Exception:
        return 60, 60


# ── Deteccion de cambio de red (SSID/gateway) ────────────────────────────────
_network_changed = threading.Event()

def _default_gateway():
    # route.exe, NO WMI - mismo motivo que _adapter_friendly_names(): esta
    # consulta WMI (Win32_NetworkAdapterConfiguration) puede fallar de forma
    # consistente en un equipo puntual: bug real encontrado en produccion,
    # llenaba agent.log con un WARN cada ~2 segundos sin parar (llamado desde
    # _watch_network_changes(), que corre en un loop de 2s) sin aportar nada.
    # Se busca la fila de la ruta por defecto por su CONTENIDO ("0.0.0.0
    # 0.0.0.0" en las primeras dos columnas), nunca por el texto de los
    # encabezados - esos si cambian con el idioma de Windows ("Puerta de
    # enlace" vs "Gateway"), pero el contenido de la ruta por defecto no.
    try:
        out = subprocess.run(
            ["route.exe", "print", "-4"],
            capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW,
            text=True, errors="replace").stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2]
    except Exception:
        pass
    return None

def _network_fingerprint():
    return f"{get_wifi_ssid() or ''}|{_default_gateway() or ''}"

def _watch_network_changes():
    last = _network_fingerprint()
    while not _stop_event.wait(2):
        try:
            cur = _network_fingerprint()
            if cur != last:
                last = cur
                _network_changed.set()
        except Exception:
            pass


def _clear_reboot_pause():
    """Si la ultima pausa activa fue pedida como 'hasta reiniciar' (ver tray
    /pause-code/validate con until_reboot=true), la termina aca - el Servicio
    arranca en cada boot (start=auto), asi que este es el punto natural para
    devolver el bloqueo a su estado normal. Si no habia ninguna pausa de ese
    tipo, el server no hace nada (ver clear_reboot_pause en
    agent_uninstall_codes.py) - se llama siempre, sin condicion previa."""
    try:
        url = f"{SERVER}/api/agents/clear-reboot-pause"
        body = json.dumps({"hostname": HOSTNAME_PC, "serial": hw.get("serial_number", "")}).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        write_log(f"WARN: no se pudo confirmar el fin de pausa 'hasta reiniciar': {e}")


def main():
    global tailnet_ip
    # CoInitialize() del hilo: main() corre en el hilo que la SCM crea para
    # SvcDoRun (no el hilo "principal" del proceso que win32com podria haber
    # inicializado implicitamente en otro contexto) - sin esto, TODAS las
    # llamadas WMI/COM desde este hilo (root\cimv2 incluido) quedan en riesgo
    # de fallar. Bug real visto en produccion (LAP-ATAFUR): las consultas a
    # root\Microsoft\Windows\Storage, root\wmi y Win32_SystemEnclosure
    # fallaban SIEMPRE con "No se ha llamado a CoInitialize" (mensaje
    # explicito), y ademas Win32_LogicalDisk (root\cimv2) fallaba con un
    # error distinto pero relacionado ("SWbemServicesEx") de forma
    # intermitente al principio y despues en CADA ciclo - mismo origen:
    # apartment COM del hilo nunca inicializado. Esto tambien explica por que
    # "model" (disco) siempre llegaba vacio: al fallar Win32_LogicalDisk,
    # get_disk_info() caia siempre al fallback nativo, que no tiene forma de
    # leer el modelo del disco.
    if pythoncom is not None:
        try:
            pythoncom.CoInitialize()
        except Exception as e:
            write_log(f"WARN: CoInitialize fallo: {e}")
    # Ver _enable_debug_privilege(): sin esto la lista de procesos llega
    # vacia en equipos con este agente (aunque el resto de las metricas
    # -CPU/RAM/disco- reporten bien), sin ningun error visible en el log.
    _enable_debug_privilege()
    # Adentro de main(), no a nivel de modulo: main() corre DESPUES de que el
    # Servicio ya reporto RUNNING (ver SvcDoRun) - el Administrador de
    # Servicios de Windows exige una actualizacion de estado dentro de los
    # primeros ~30 segundos desde que arranca el proceso, y esta espera puede
    # tardar hasta 60s. Antes vivia a nivel de modulo (se ejecutaba durante el
    # import, antes de que el Servicio pudiera reportar nada) y eso hacia que
    # el arranque fallara con "El servicio no respondio a tiempo a la
    # solicitud de inicio" cada vez que la red no contestaba de inmediato -
    # confirmado con un build real.
    _wait_for_network()
    threading.Thread(target=_watch_network_changes, daemon=True).start()
    threading.Thread(target=supervise_cloudflared, daemon=True).start()

    _clear_reboot_pause()
    setup_wireguard_tunnel()
    ensure_hosts_entry(DOH_HOSTNAME, tailnet_ip and tailnet_server_ip)
    # Dar tiempo a que cloudflared arranque antes de apuntarle el DNS del
    # sistema - si no hay nada escuchando en 127.0.0.1:53 todavia, Windows
    # simplemente reintenta solo hasta que cloudflared este listo.
    time.sleep(3)
    ensure_local_dns()

    interval, blocklist_poll_sec = get_interval()
    prev_sw_hash = ""
    if os.path.exists(SW_HASH_FILE):
        try:
            prev_sw_hash = open(SW_HASH_FILE, encoding="utf-8").read().strip()
        except Exception:
            pass
    loop_count = 0
    last_metrics = 0.0
    last_wireguard_retry = time.time()
    last_hosts_ip = tailnet_ip and tailnet_server_ip

    write_log(f"Loop iniciado - metricas cada {interval}s, bloqueo cada {blocklist_poll_sec}s")

    while not _stop_event.is_set():
        try:
            if time.time() - last_metrics >= interval:
                sw_to_send = []
                if loop_count % max(1, int(300 / interval)) == 0:
                    sw_list = get_installed_software()
                    sw_hash = hashlib.md5(json.dumps(sw_list, sort_keys=True).encode()).hexdigest()
                    if sw_hash != prev_sw_hash:
                        sw_to_send = sw_list
                        prev_sw_hash = sw_hash
                        try:
                            with open(SW_HASH_FILE, "w", encoding="utf-8") as f:
                                f.write(sw_hash)
                        except Exception:
                            pass

                send_metrics(sw_to_send)
                interval, blocklist_poll_sec = get_interval()
                last_metrics = time.time()
                loop_count += 1

            # Se revalida en CADA ciclo si el tunel sigue realmente vivo - si
            # Tailscale se cae despues de haber estado conectado, tailnet_ip
            # quedaba en un valor viejo para siempre.
            tailnet_ip = get_tailscale_ip()

            # 15s, no 60s: bug real visto en produccion (LAP-ATAFUR) - el
            # servicio de WLAN de Windows puede reiniciarse solo cada pocos
            # minutos (driver de red inestable), lo que desloguea Tailscale
            # por completo. Mientras el tunel esta caido, cloudflared pasa
            # automaticamente a un DNS publico de respaldo para no dejar el
            # equipo sin poder navegar - pero eso tambien salta el bloqueo de
            # contenido mientras dura. Reintentar cada 60s dejaba esa ventana
            # de "bloqueo salteado" mas larga de lo necesario; 15s la acorta
            # sin ser agresivo (Tailscale ya reconecta solo en unos segundos
            # una vez que WLAN vuelve, lo que faltaba era que ESTE agente se
            # enterara y volviera a pedir un pre-auth key mas rapido).
            if (not tailnet_ip or not tailnet_server_ip) and time.time() - last_wireguard_retry >= 15:
                setup_wireguard_tunnel()
                last_wireguard_retry = time.time()

            current_hosts_ip = tailnet_ip and tailnet_server_ip
            if current_hosts_ip != last_hosts_ip:
                ensure_hosts_entry(DOH_HOSTNAME, current_hosts_ip)
                last_hosts_ip = current_hosts_ip

            # get_blocklist() ya no decide nada del DNS local (fijo a
            # 127.0.0.1 desde el arranque) - solo reporta el SSID actual, que
            # el gate del lado servidor usa para el camino DoH.
            block_result = get_blocklist()
            if block_result is not None:
                write_log(f"BLOCKLIST should_block={block_result['ShouldBlock']} "
                          f"all_domains={len(block_result['AllDomains'])}")
            else:
                write_log("BLOCKLIST sin respuesta del servidor (None)")

            write_log(f"OK - siguiente revision de red en {blocklist_poll_sec}s")
        except Exception as e:
            write_log(f"ERROR: {e}")

        waited = 0
        while waited < blocklist_poll_sec:
            if _stop_event.wait(2):
                return
            if _network_changed.is_set():
                _network_changed.clear()
                write_log("Cambio de red detectado - revisando de inmediato")
                # Bug real reportado por un usuario: en una red el equipo
                # navegaba bien, al cambiar a otra red dejaba de poder
                # navegar del todo (no solo se saltaba el bloqueo, se
                # rompia la resolucion DNS entera). Causa: cloudflared
                # mantiene una conexion HTTPS persistente al upstream DoH -
                # ese cambio de red (nueva puerta de enlace/interfaz) puede
                # dejarla en un estado roto/colgado sin que el PROCESO en
                # si llegue a caerse, asi que supervise_cloudflared() (que
                # solo reinicia si el proceso MUERE) nunca se enteraba.
                # Como el DNS de Windows queda fijo a 127.0.0.1 (ver
                # ensure_local_dns()), sin cloudflared respondiendo ahi
                # NINGUN nombre resuelve - no es un problema del sitio
                # bloqueado, es que no hay DNS en absoluto. Forzar el
                # reinicio aca asegura que abra una conexion nueva ya
                # sobre la red actual en vez de esperar a que el usuario
                # reinicie el equipo o el servicio a mano.
                if _cloudflared_proc is not None and _cloudflared_proc.poll() is None:
                    write_log("Reiniciando cloudflared por el cambio de red (conexion vieja puede haber quedado colgada)")
                    try:
                        _cloudflared_proc.terminate()
                    except Exception as e:
                        write_log(f"WARN: no se pudo reiniciar cloudflared tras cambio de red: {e}")
                # ensure_local_dns() solo corria una vez, al arrancar main() -
                # un adaptador que no existia todavia en ese momento (ej. un
                # Ethernet por USB/dock que se conecta despues) se quedaba
                # sin el DNS fijo a 127.0.0.1 para siempre. Reaplicarlo aca
                # es idempotente (no hace nada distinto en un adaptador que
                # ya esta bien configurado) y cubre ese caso sin tener que
                # reiniciar el servicio a mano.
                ensure_local_dns()
                _stop_event.wait(3)  # debounce: dar tiempo a que la SSID/IP se asienten
                break
            waited += 2

    write_log("Loop principal detenido (SvcStop)")


# ── Servicio nativo de Windows (pywin32) ─────────────────────────────────────
# Reemplaza la Tarea Programada: registrado con "sc.exe create" (ver
# cmd_register_service en smartmonitor_installer_helper.py) y con acciones de
# recuperacion (sc.exe failure) para que el Administrador de Servicios lo
# reinicie solo casi al instante si el proceso muere o lo terminan a mano -
# antes (Tarea Programada) el reinicio dependia de un intervalo de ~1 minuto.
# NO es NSSM ni ningun binario de terceros (eso fue lo que en su momento
# disparo la heuristica de "dropper" de Kaspersky) - es nuestro propio .exe
# actuando como servicio via la API nativa de Windows (win32serviceutil).
try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
except ImportError:
    win32serviceutil = None


if win32serviceutil is not None:
    class SmartMonitorService(win32serviceutil.ServiceFramework):
        _svc_name_ = "SmartMonitorAgent"
        _svc_display_name_ = "SmartMonitor Agent"
        _svc_description_ = ("Agente de monitoreo y bloqueo de contenido de SmartMonitor. "
                              "No detener manualmente - se reinicia solo; pausar desde el panel.")

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            _stop_event.set()
            try:
                if _cloudflared_proc is not None and _cloudflared_proc.poll() is None:
                    _cloudflared_proc.terminate()  # desbloquea el .wait() del supervisor
            except Exception:
                pass
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self):
            # Reportar RUNNING de inmediato, antes de main() - el Administrador
            # de Servicios espera una actualizacion de estado dentro de los
            # primeros ~30 segundos desde que arranca el proceso; si nada la
            # reporta, lo da por colgado y falla el arranque
            # ("El servicio no respondio a tiempo a la solicitud de inicio"),
            # sin importar que main() este funcionando bien - confirmado con
            # un build real.
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                                   servicemanager.PYS_SERVICE_STARTED,
                                   (self._svc_name_, ""))
            main()


def _run_as_service_or_cli():
    if win32serviceutil is None:
        main()  # smoke-test fuera de Windows (sin pywin32) - ver import de arriba
        return
    if len(sys.argv) == 1:
        # Sin argumentos = asi es como el Administrador de Servicios arranca
        # el .exe - cualquier otra invocacion (instalar/quitar/depurar) trae
        # argumentos y la maneja win32serviceutil.HandleCommandLine.
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SmartMonitorService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(SmartMonitorService)


if __name__ == "__main__":
    _run_as_service_or_cli()

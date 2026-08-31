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
CLOUDFLARED_EXE = os.path.join(getattr(sys, "_MEIPASS", AGENT_DIR), "cloudflared.exe")
TAILSCALE_EXE   = r"C:\Program Files\Tailscale\tailscale.exe"
HOSTS_FILE      = r"C:\Windows\System32\drivers\etc\hosts"

DOH_HOSTNAME  = "dns.smartmonitor.local"
HOSTS_MARKER  = "# SmartMonitor DoH upstream"
LOCAL_DNS_IP  = "127.0.0.1"

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
write_log(f"Servidor configurado: {SERVER} | Hostname: {HOSTNAME_PC}")


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
        write_log(f"WARN: WMI query fallo ({namespace}): {wql[:80]} - {e}")
        return []


try:
    import ctypes as _ctypes
    from ctypes import wintypes as _wintypes

    class _GUID(_ctypes.Structure):
        _fields_ = [("Data1", _wintypes.DWORD), ("Data2", _wintypes.WORD), ("Data3", _wintypes.WORD),
                    ("Data4", _ctypes.c_ubyte * 8)]

    class _DEVPROPKEY(_ctypes.Structure):
        _fields_ = [("fmtid", _GUID), ("pid", _wintypes.ULONG)]

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
    if not _cfgmgr32 or not pnp_device_id:
        return None
    try:
        devinst = _wintypes.DWORD()
        if _cfgmgr32.CM_Locate_DevNodeW(_ctypes.byref(devinst), _ctypes.c_wchar_p(pnp_device_id), 0) != 0:
            return None
        cur = devinst.value
        for _ in range(6):
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
    if bus_type == 17:  # BusTypeNvme
        link = _get_pcie_link_info(pnp_device_id)
        return f"PCIe Gen{link[0]} x{link[1]}" if link else None
    if bus_type == 11:  # BusTypeSata
        return "SATA"
    if bus_type == 7:   # BusTypeUsb
        return "USB"
    return None


_cpu_query = None
_cpu_counter = None

def get_cpu_percent():
    global _cpu_query, _cpu_counter
    try:
        if _cpu_query is None:
            try:
                _cpu_query = win32pdh.OpenQuery()
                _cpu_counter = win32pdh.AddEnglishCounter(_cpu_query, r"\Processor(_Total)\% Processor Time")
                win32pdh.CollectQueryData(_cpu_query)
                time.sleep(0.2)
            except Exception:
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
    standards = [1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 32, 48, 64, 96, 128, 192, 256]
    for s in standards:
        if usable_gb <= s + 0.5:
            return s
    return round(usable_gb)


def get_mem_info():
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

    slot_total = sum(s.get("size_gb", 0) for s in ram.get("detail", []))
    return {"percent": 0.0, "total_gb": slot_total or 0, "used_gb": 0.0}


def _get_disk_info_native_fallback():
    disks, physical_disks = [], []
    media_types = _get_disk_media_types()
    try:
        drives = [d for d in win32api.GetLogicalDriveStrings().split("\x00") if d]
        idx = 0
        for drv in drives:
            try:
                if win32file.GetDriveTypeW(drv) != 3:
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
            extra = media_types.get(idx, {})
            physical_disks.append({"disk_index": idx, "total_gb": total_gb, "used_gb": used_gb,
                                    "percent": pct, "partitions": 1, "media_type": extra.get("type"), "model": None,
                                    "interface": _get_disk_interface(extra.get("bus_type"), None)})
            idx += 1
    except Exception as e:
        write_log(f"WARN: fallback nativo de disco tambien fallo: {e}")
    return {"disks": disks, "physicalDisks": physical_disks}


def _get_disk_media_types():
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
    logical = _wmi_query("SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType=3")
    if not logical:
        return _get_disk_info_native_fallback()

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
            cpu_pct = max(0.0, delta / 5_000_000 * 100.0)
        disk_kb_s = 0.0
        if d1:
            delta_bytes = d2["disk_bytes"] - d1["disk_bytes"]
            disk_kb_s = max(0.0, delta_bytes / 1024 / 0.5)
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
    subprocess.run(
        ["netsh.exe", "interface", "ipv6", "set", "dnsservers",
         f"name={name}", "source=static", "address=none", "validate=no"],
        capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)


def _set_ipv4_dns(name):
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


def restore_dhcp_dns():
    """Restaura el DNS de los adaptadores de red a DHCP automatico.
    Se ejecuta de forma automatica cuando el agente detecta que la red actual
    no tiene conectividad con el servidor central de SmartMonitor (red externa/bloqueada),
    impidiendo que el equipo pierda acceso a Internet o sufra desconexiones de Wi-Fi."""
    for name in _adapter_friendly_names():
        try:
            subprocess.run(
                ["netsh.exe", "interface", "ipv4", "set", "dnsservers",
                 f"name={name}", "source=dhcp"],
                capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(
                ["netsh.exe", "interface", "ipv6", "set", "dnsservers",
                 f"name={name}", "source=dhcp"],
                capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
            write_log(f"DNS DHCP restaurado en adaptador: {name}")
        except Exception as e:
            write_log(f"WARN: no se pudo restaurar DNS DHCP en {name}: {e}")


def ensure_hosts_entry(hostname, ip):
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


_stop_event = threading.Event()
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
    global _cloudflared_proc
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
                 "--upstream", "https://cloudflare-dns.com/dns-query"],
                creationflags=subprocess.CREATE_NO_WINDOW)
            write_log(f"cloudflared iniciado (pid={_cloudflared_proc.pid})")
            start_ts = time.time()
            _cloudflared_proc.wait()
            if _stop_event.is_set():
                break
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
        max_capacity_gb = None
        if arrays:
            max_cap_kb = getattr(arrays[0], "MaxCapacityEx", None) or getattr(arrays[0], "MaxCapacity", None)
            if max_cap_kb:
                max_capacity_gb = round(int(max_cap_kb) / (1024 ** 2))
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

    sys_drive = os.environ.get("SystemDrive", "C:").rstrip(":")
    sys_disk = next((d for d in disks if d["device"] == sys_drive), None)
    if sys_disk is not None:
        disk_pct = sys_disk["percent"]
    elif physical_disks:
        disk_pct = max(physical_disks, key=lambda p: p["total_gb"])["percent"]
    elif disks:
        sane = [d for d in disks if d["total_gb"] <= 5000]
        disk_pct = max((sane or disks), key=lambda d: d["total_gb"])["percent"]
    else:
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
    try:
        url = f"{SERVER}/api/agents/clear-reboot-pause"
        body = json.dumps({"hostname": HOSTNAME_PC, "serial": hw.get("serial_number", "")}).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        write_log(f"WARN: no se pudo confirmar el fin de pausa 'hasta reiniciar': {e}")


def main():
    global tailnet_ip
    if pythoncom is not None:
        try:
            pythoncom.CoInitialize()
        except Exception as e:
            write_log(f"WARN: CoInitialize fallo: {e}")
    _enable_debug_privilege()
    _wait_for_network()
    threading.Thread(target=_watch_network_changes, daemon=True).start()
    threading.Thread(target=supervise_cloudflared, daemon=True).start()

    _clear_reboot_pause()
    setup_wireguard_tunnel()
    ensure_hosts_entry(DOH_HOSTNAME, tailnet_ip and tailnet_server_ip)
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

    _in_dhcp_fallback = False
    _consecutive_server_failures = 0

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

            tailnet_ip = get_tailscale_ip()

            if (not tailnet_ip or not tailnet_server_ip) and time.time() - last_wireguard_retry >= 15:
                setup_wireguard_tunnel()
                last_wireguard_retry = time.time()

            current_hosts_ip = tailnet_ip and tailnet_server_ip
            if current_hosts_ip != last_hosts_ip:
                ensure_hosts_entry(DOH_HOSTNAME, current_hosts_ip)
                last_hosts_ip = current_hosts_ip

            block_result = get_blocklist()
            if block_result is not None:
                write_log(f"BLOCKLIST should_block={block_result['ShouldBlock']} "
                          f"all_domains={len(block_result['AllDomains'])}")
                _consecutive_server_failures = 0
                if _in_dhcp_fallback:
                    write_log("Conectividad con servidor restablecida. Reaplicando DNS local 127.0.0.1 y protecciones.")
                    ensure_local_dns()
                    _in_dhcp_fallback = False
            else:
                _consecutive_server_failures += 1
                write_log(f"BLOCKLIST sin respuesta del servidor (intento fallido {_consecutive_server_failures})")
                if _consecutive_server_failures >= 2 and not _in_dhcp_fallback:
                    write_log("WARN: Servidor no alcanzable en la red actual. Activando fallback automatico de DNS a DHCP para evitar desconexion de Wi-Fi...")
                    restore_dhcp_dns()
                    _in_dhcp_fallback = True

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
                if _cloudflared_proc is not None and _cloudflared_proc.poll() is None:
                    write_log("Reiniciando cloudflared por el cambio de red (conexion vieja puede haber quedado colgada)")
                    try:
                        _cloudflared_proc.terminate()
                    except Exception as e:
                        write_log(f"WARN: no se pudo reiniciar cloudflared tras cambio de red: {e}")
                
                _stop_event.wait(3)
                test_block = get_blocklist()
                if test_block is None:
                    write_log("Nueva red sin conectividad directa al servidor central. Aplicando fallback a DHCP.")
                    restore_dhcp_dns()
                    _in_dhcp_fallback = True
                    _consecutive_server_failures = 1
                else:
                    write_log("Nueva red con conectividad al servidor central. Aplicando DNS local 127.0.0.1.")
                    ensure_local_dns()
                    _in_dhcp_fallback = False
                    _consecutive_server_failures = 0
                break
            waited += 2

    write_log("Loop principal detenido (SvcStop)")


# ── Servicio nativo de Windows (pywin32) ─────────────────────────────────────
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
                    _cloudflared_proc.terminate()
            except Exception:
                pass
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self):
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                                   servicemanager.PYS_SERVICE_STARTED,
                                   (self._svc_name_, ""))
            main()


def _run_as_service_or_cli():
    if win32serviceutil is None:
        main()
        return
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SmartMonitorService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(SmartMonitorService)


if __name__ == "__main__":
    _run_as_service_or_cli()

#!/usr/bin/env python3
"""SmartMonitor v3 - Helper de instalacion/desinstalacion (Python, compilado a
smartmonitor-installer-helper.exe con PyInstaller).

Reemplaza TODO lo que antes corria via powershell.exe desde
smartmonitor-agent.iss (los pasos de instalacion con RunPS) y los dos scripts
sueltos uninstall-cleanup.ps1 / validate-uninstall-code.ps1 - a pedido
explicito del usuario, cero PowerShell en todo el flujo de instalar/
desinstalar. Inno Setup (Pascal Script) solo invoca este .exe con un
subcomando via Exec(), igual que ya invoca netsh.exe/icacls.exe/schtasks.exe
nativos - ninguno de esos es PowerShell tampoco.

Subcomandos (uno por accion, cada uno hace una sola cosa e imprime OK/ERROR):
    cleanup-previous
    write-config       --server <url>
    install-tailscale
    install-ca-cert    --server <ip-o-dominio>
    register-service   --app-dir <dir>
    register-tray      --app-dir <dir>
    validate-uninstall-code --code <codigo>
    uninstall-cleanup

Exit 0 = OK. Exit != 0 = fallo (Inno Setup ya lo maneja mostrando un MsgBox).
"""
import sys; sys.dont_write_bytecode = True
import os, json, socket, subprocess, argparse, ctypes
import urllib.request, urllib.error, ssl

try:
    import win32com.client
    import winreg
    import win32ts
except ImportError:
    win32com = None
    winreg = None
    win32ts = None

AGENT_DIR   = r"C:\SmartMonitor"
CONFIG_FILE = os.path.join(AGENT_DIR, "config.json")
CA_CERT_FILE = os.path.join(AGENT_DIR, "smartmonitor-ca.crt")
TASK_NAME   = "SmartMonitor"      # Tarea Programada vieja - solo se limpia, ya no se crea
SERVICE_NAME = "SmartMonitorAgent"  # debe matchear _svc_name_ en smartmonitor_agent.py
TAILSCALE_EXE = r"C:\Program Files\Tailscale\tailscale.exe"

DOH_IPS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"]
BROWSER_POLICY_PATHS = ["Google\\Chrome", "Microsoft\\Edge", "BraveSoftware\\Brave"]


def log(msg):
    print(msg, flush=True)


# ── WMI (mismo patron que smartmonitor_agent.py) ─────────────────────────────
_wmi_conn = None

def _wmi():
    global _wmi_conn
    if _wmi_conn is None:
        locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        _wmi_conn = locator.ConnectServer(".", "root\\cimv2")
    return _wmi_conn

def _wmi_query(wql):
    try:
        return list(_wmi().ExecQuery(wql))
    except Exception:
        return []


def _run(cmd, timeout=30):
    """Corre un comando nativo (nunca PowerShell) y no lanza si falla - los
    pasos de limpieza deben seguir aunque uno puntual no aplique."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception as e:
        log(f"WARN: no se pudo correr {cmd[0]}: {e}")
        return None


# ── cleanup-previous: limpia rastros de una instalacion anterior (.ps1 vieja
# o una corrida previa de este mismo .exe) antes de instalar de nuevo ───────
def cmd_cleanup_previous(args):
    log("Deteniendo Tarea Programada previa (si habia - versiones viejas usaban eso en vez del Servicio actual)...")
    _run(["schtasks.exe", "/end", "/tn", TASK_NAME])
    _run(["schtasks.exe", "/delete", "/tn", TASK_NAME, "/f"])

    log("Deteniendo y eliminando el Servicio de Windows previo (propio o NSSM heredado de una version muy vieja)...")
    services = _wmi_query(f"SELECT Name FROM Win32_Service WHERE Name='{SERVICE_NAME}'")
    if services:
        _run(["sc.exe", "stop", SERVICE_NAME])
        nssm = os.path.join(AGENT_DIR, "nssm.exe")
        if os.path.exists(nssm):
            _run([nssm, "remove", SERVICE_NAME, "confirm"])
        else:
            _run(["sc.exe", "delete", SERVICE_NAME])

    log("Quitando autoinicio en el registro (agente viejo y/o tray)...")
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                              r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                              0, winreg.KEY_SET_VALUE)
        for value_name in ("SmartMonitor", "SmartMonitorTray"):
            try:
                winreg.DeleteValue(key, value_name)
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
    except Exception:
        pass

    log("Deteniendo procesos previos del agente y del tray...")
    # taskkill /F, no WMI Terminate(): el agente corre como SYSTEM (Tarea
    # Programada) pero este helper corre como Administrador durante la
    # desinstalacion/reinstalacion - WMI Terminate() necesita SeDebugPrivilege
    # habilitado explicitamente para matar un proceso de otra cuenta y falla
    # en silencio sin eso (confirmado: el proceso quedaba vivo tras
    # "desinstalar", con el .exe bloqueado - por eso Inno avisaba "algunos
    # elementos no se pudieron eliminar"). taskkill.exe si habilita ese
    # privilegio internamente. El tray corre con el usuario logueado (no
    # SYSTEM), pero taskkill /F funciona igual para ese caso.
    rows = _wmi_query("SELECT ProcessId, Name, CommandLine FROM Win32_Process")
    for r in rows:
        cmdline = r.CommandLine or ""
        name = (r.Name or "").lower()
        if "smartmonitor-push.ps1" in cmdline or name in (
                "smartmonitor-agent.exe", "cloudflared.exe", "smartmonitor-tray.exe"):
            _run(["taskkill.exe", "/F", "/PID", str(r.ProcessId)])

    log("Restaurando DNS automatico...")
    _reset_dns()

    log("Quitando politicas de DNS-over-HTTPS de navegadores...")
    _remove_browser_doh_policies()

    log("Quitando reglas de firewall de bloqueo de DoH previas...")
    _remove_doh_firewall_rules()

    # Bug real encontrado (LAP-ATAFUR, actualizacion 2026.08.04-3 ->
    # 2026.08.07-1): .sw_hash no esta en [Files] del .iss, asi que una
    # reinstalacion/actualizacion NO lo toca y sobrevive con el hash
    # calculado contra el software instalado ANTES de actualizar. El agente
    # nuevo arranca, recalcula el hash sobre el software actual (que ya
    # incluye la version nueva de "SmartMonitor Agent" en el registro) y en
    # teoria deberia diferir del guardado - pero en la practica, en ese
    # equipo real, el panel siguio mostrando la version vieja indefinidamente
    # hasta borrar este archivo a mano y reiniciar el servicio. Sin este
    # borrado en cada instalacion, es imposible para un administrador saber
    # desde el panel que build tiene realmente cada equipo tras actualizarlo
    # - justo el problema que la version de smartmonitor-agent.iss existe
    # para resolver. Se borra aca (no en el agente) porque cleanup-previous
    # ya corre en cada instalacion/actualizacion, antes de que el servicio
    # nuevo arranque.
    sw_hash_path = os.path.join(AGENT_DIR, ".sw_hash")
    try:
        if os.path.exists(sw_hash_path):
            os.remove(sw_hash_path)
            log("Cache de inventario de software (.sw_hash) eliminada - se reenviara completo en el proximo reporte")
    except Exception as e:
        log(f"WARN: no se pudo borrar .sw_hash: {e}")

    log("OK: limpieza de instalacion previa completada")
    return 0


def _adapter_friendly_names():
    """Mismo cruce Win32_NetworkAdapterConfiguration <-> Win32_NetworkAdapter
    que usa el agente (ver _adapter_friendly_names en smartmonitor_agent.py)
    para conseguir el nombre que entiende netsh (ej. 'Ethernet')."""
    names = []
    try:
        idxs = {a.Index for a in _wmi_query(
            "SELECT Index FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True")}
        for a in _wmi_query("SELECT Index, NetConnectionID FROM Win32_NetworkAdapter"):
            if a.Index in idxs and a.NetConnectionID:
                names.append(a.NetConnectionID)
    except Exception:
        pass
    return names


def _reset_dns():
    # netsh, no WMI Get()-por-SettingID: ese patron (usado antes tanto aca
    # como en el agente) falla con "Ruta de acceso del objeto no valida"
    # cuando el SettingID del adaptador es un GUID con llaves (confirmado
    # con un build real) - netsh identifica la interfaz por nombre, no
    # depende del formato de SettingID. Mismo cambio que
    # ensure_local_dns()/_set_ipv4_dns() en smartmonitor_agent.py.
    try:
        for name in _adapter_friendly_names():
            _run(["netsh.exe", "interface", "ipv4", "set", "dnsservers",
                  f"name={name}", "source=dhcp"])
            _run(["netsh.exe", "interface", "ipv6", "set", "dnsservers",
                  f"name={name}", "source=dhcp"])
        _run(["ipconfig", "/flushdns"])
    except Exception as e:
        log(f"WARN: no se pudo restaurar el DNS automatico: {e}")


def _remove_browser_doh_policies():
    for p in BROWSER_POLICY_PATHS:
        try:
            _delete_registry_tree(winreg.HKEY_LOCAL_MACHINE, "Software\\Policies\\" + p)
        except Exception:
            pass
    try:
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        pol = os.path.join(program_files, "Mozilla Firefox", "distribution", "policies.json")
        if os.path.exists(pol):
            os.remove(pol)
    except Exception:
        pass


def _delete_registry_tree(hive, path):
    """winreg no tiene un 'borrar recursivo' nativo - hay que vaciar las
    subclaves primero (de adentro hacia afuera) antes de poder borrar la
    clave misma, igual que Remove-Item -Recurse en PowerShell hacia adentro."""
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS)
    except FileNotFoundError:
        return
    try:
        while True:
            try:
                sub = winreg.EnumKey(key, 0)
            except OSError:
                break
            _delete_registry_tree(hive, path + "\\" + sub)
    finally:
        winreg.CloseKey(key)
    try:
        winreg.DeleteKey(hive, path)
    except Exception:
        pass


def _remove_doh_firewall_rules():
    for ip in DOH_IPS:
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=SM_BlockDoH_{ip}"])


# ── write-config: sidecar que lee smartmonitor_agent.py al arrancar ─────────
def cmd_write_config(args):
    os.makedirs(AGENT_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump({"server": args.server}, f)
    log(f"OK: config.json escrito (server={args.server})")
    return 0


# ── install-tailscale ────────────────────────────────────────────────────────
def cmd_install_tailscale(args):
    if os.path.exists(TAILSCALE_EXE):
        log("OK: Tailscale ya estaba instalado")
        return 0
    try:
        msi_path = os.path.join(AGENT_DIR, "tailscale-setup.msi")
        log("Descargando instalador de Tailscale...")
        urllib.request.urlretrieve(
            "https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi", msi_path)
        log("Instalando Tailscale (silencioso)...")
        _run(["msiexec.exe", "/i", msi_path, "/quiet", "/norestart"], timeout=120)
        try:
            os.remove(msi_path)
        except Exception:
            pass
    except Exception as e:
        log(f"WARN: no se pudo instalar Tailscale: {e}")
        return 0  # no fatal - el agente sigue funcionando por IP publica sin tunel

    # No se necesita el icono de bandeja ni el arranque automatico propio de
    # Tailscale - lo maneja la Tarea Programada de SmartMonitor.
    try:
        startup_lnk = os.path.join(
            os.environ.get("ProgramData", r"C:\ProgramData"),
            "Microsoft", "Windows", "Start Menu", "Programs", "StartUp", "Tailscale.lnk")
        if os.path.exists(startup_lnk):
            os.remove(startup_lnk)
        rows = _wmi_query("SELECT ProcessId FROM Win32_Process WHERE Name='tailscale-ipn.exe'")
        for r in rows:
            try:
                _wmi().Get(f"Win32_Process.Handle='{r.ProcessId}'").Terminate()
            except Exception:
                pass
        pf_dir = os.path.dirname(TAILSCALE_EXE)
        ipn = os.path.join(pf_dir, "tailscale-ipn.exe")
        if os.path.exists(ipn):
            os.replace(ipn, ipn + ".disabled")
    except Exception:
        pass

    log("OK: Tailscale instalado")
    return 0


# ── install-ca-cert ──────────────────────────────────────────────────────────
def cmd_install_ca_cert(args):
    # Se prueba primero por HTTPS (mismo certificado que sirve la app
    # principal detras del dominio real - ver GET /smartmonitor-ca.crt en
    # main.py) en vez de HTTP plano al puerto 80: descargar un .crt por HTTP
    # directo a una IP (sin dominio, sin cifrar) es un patron que la
    # heuristica de varios antivirus (Kaspersky confirmado en pruebas) marca
    # como sitio malintencionado. Se ignora la validacion del certificado TLS
    # en este paso puntual porque, si "servidor" es la IP en vez del dominio
    # real, el nombre nunca va a coincidir - igual se gana cifrado en
    # transito. Si HTTPS falla del todo (ej. puerto 443 no expuesto), cae al
    # viejo HTTP:80 como respaldo.
    server = args.server
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    data = None
    try:
        with urllib.request.urlopen(f"https://{server}/smartmonitor-ca.crt", timeout=8, context=ctx) as r:
            data = r.read()
    except Exception:
        try:
            with urllib.request.urlopen(f"http://{server}/smartmonitor-ca.crt", timeout=8) as r:
                data = r.read()
        except Exception as e:
            log(f"WARN: no se pudo descargar el certificado de la CA: {e}")
            return 0  # no fatal - el bloqueo por HTTPS mostrara advertencia de certificado, pero el agente sigue funcionando

    os.makedirs(AGENT_DIR, exist_ok=True)
    with open(CA_CERT_FILE, "wb") as f:
        f.write(data)

    # certutil.exe (nativo de Windows desde XP, NO PowerShell) importa el
    # certificado al almacen de la maquina - "Root" = Trusted Root
    # Certification Authorities, el mismo almacen que Import-Certificate
    # -CertStoreLocation Cert:\LocalMachine\Root usaba antes.
    r = _run(["certutil.exe", "-addstore", "Root", CA_CERT_FILE], timeout=15)
    if r and r.returncode == 0:
        log("OK: certificado de la CA instalado")
    else:
        log("WARN: certutil no confirmo la instalacion del certificado")
    return 0


# ── register-service: Servicio nativo de Windows (reemplaza la Tarea
# Programada de antes) ──────────────────────────────────────────────────────
# NO es NSSM ni ningun binario de terceros (ver Notas de diseno en BUILD.md
# sobre por que Kaspersky bloqueo NSSM) - smartmonitor-agent.exe ES el
# servicio (win32serviceutil.ServiceFramework, ver smartmonitor_agent.py);
# "sc.exe create" solo lo registra ante el Administrador de Servicios, igual
# que con cualquier otro servicio nativo (Windows Update, etc.).
#
# Ventaja sobre la Tarea Programada: "sc.exe failure" hace que el
# Administrador de Servicios reinicie el proceso a los pocos segundos si
# muere o si lo terminan a mano (antes, con Tarea Programada, el reintento
# mas rapido era ~1 minuto). Ademas, un Servicio con dueno LocalSystem ya
# rechaza por defecto que un usuario sin permisos de administrador lo
# detenga/deshabilite/borre (Windows aplica esto solo via el Security
# Descriptor del servicio) - no hace falta el icacls que si necesitaba el
# archivo .job de la Tarea Programada.
def cmd_register_service(args):
    exe_path = os.path.join(args.app_dir, "smartmonitor-agent.exe")

    _run(["sc.exe", "stop", SERVICE_NAME])
    _run(["sc.exe", "delete", SERVICE_NAME])

    # OJO con sc.exe: cada "clave=" necesita llegar como argumento SEPARADO
    # de su valor (dos items de lista, ej. "binPath=", exe_path) - no como un
    # solo string "binPath= valor". Python arma la linea de comandos de
    # Windows con list2cmdline(), que entrecomilla cualquier argumento con
    # espacios ("start= auto" -> "\"start= auto\""); sc.exe recibe eso como
    # UN solo token entrecomillado en vez de dos separados por espacio (como
    # pasa cuando un humano lo tipea a mano en cmd.exe, sin comillas) y el
    # comando falla en silencio. Confirmado con un build real: "create"
    # fallaba justo por esto.
    r = _run(["sc.exe", "create", SERVICE_NAME,
              "binPath=", exe_path,
              "start=", "auto",
              "obj=", "LocalSystem",
              "DisplayName=", "SmartMonitor Agent"], timeout=30)
    if not r or r.returncode != 0:
        log(f"ERROR: no se pudo crear el servicio: {(r.stdout or r.stderr) if r else '?'}")
        return 1

    _run(["sc.exe", "description", SERVICE_NAME,
          "Agente de monitoreo y bloqueo de contenido de SmartMonitor."])

    # reset= 0: el contador de fallos NUNCA se reinicia solo - todas las
    # veces que el proceso muera se intenta reiniciar, no solo las primeras
    # (el default de Windows sin esto es resetear el contador tras 24hs sin
    # fallos, lo cual en la practica ya cubre casi cualquier escenario real,
    # pero reset=0 lo deja explicito e infalible).
    _run(["sc.exe", "failure", SERVICE_NAME,
          "reset=", "0",
          "actions=", "restart/2000/restart/5000/restart/10000"])
    # failureflag=1: tambien dispara las acciones de arriba si el proceso
    # termina "limpio" (exit code 0) - por defecto sc.exe solo reinicia ante
    # una falla real; nuestro proceso nunca deberia salir solo, asi que
    # cualquier salida (limpia o no) debe disparar el reinicio.
    _run(["sc.exe", "failureflag", SERVICE_NAME, "1"])

    r2 = _run(["sc.exe", "start", SERVICE_NAME], timeout=30)
    if not r2 or r2.returncode != 0:
        log(f"ERROR: no se pudo iniciar el servicio: {(r2.stdout or r2.stderr) if r2 else '?'}")
        return 1
    log("OK: servicio registrado e iniciado")
    return 0


def _launch_in_active_session(exe_path):
    """Lanza exe_path en la sesion interactiva activa (consola), NO en la
    sesion 0 elevada donde corre este instalador. Sin esto, el icono de la
    bandeja recien aparece en el PROXIMO inicio de sesion - HKLM\\...\\Run
    solo se evalua al loguearse, no de forma retroactiva sobre una sesion ya
    abierta - dejando al usuario sin forma de pausar el bloqueo hasta que
    cierre sesion o reinicie (bug real reportado). Si no hay nadie logueado
    en la consola en el momento de instalar (ej. instalacion desatendida),
    se omite en silencio - el Run key ya registrado igual lo cubre en el
    proximo login.

    Primer intento real: WTSQueryUserToken + CreateProcessAsUser (la forma
    "de libro" de hacer esto). Confirmado con un build real que FALLA siempre
    desde este instalador: WTSQueryUserToken exige el privilegio SE_TCB_NAME
    ("Actuar como parte del sistema operativo"), que un proceso elevado como
    Administrador (que es como corre este instalador, PrivilegesRequired=
    admin en el .iss) simplemente NO TIENE en su token - a diferencia de un
    Servicio de Windows corriendo como SYSTEM, que si lo tiene. No hay forma
    de "activarlo" con AdjustTokenPrivileges porque ni siquiera esta presente
    en el token, deshabilitado - directamente no esta.

    Fix real, tambien confirmado con un build: usar el Programador de tareas
    (schtasks.exe, nativo, no PowerShell) como intermediario. El Programador
    de tareas SI corre como SYSTEM internamente, asi que un Administrador
    puede pedirle -sin tener SE_TCB_NAME el mismo- que lance un proceso en la
    sesion de OTRO usuario logueado, usando una tarea "solo interactiva"
    (/it, sin contraseña guardada) apuntada al usuario de la sesion activa:
    crear la tarea, correrla ya (/run, ignora el horario programado),
    borrarla - todo en segundos."""
    try:
        session_id = win32ts.WTSGetActiveConsoleSessionId()
        if session_id in (0xFFFFFFFF, -1):
            return False
        username = win32ts.WTSQuerySessionInformation(None, session_id, win32ts.WTSUserName)
        domain   = win32ts.WTSQuerySessionInformation(None, session_id, win32ts.WTSDomainName)
        if not username:
            return False
        full_user = f"{domain}\\{username}" if domain else username
        task_name = "SmartMonitorTrayLaunch"
        _run(["schtasks", "/create", "/tn", task_name, "/tr", f'"{exe_path}"',
              "/sc", "once", "/st", "00:00", "/ru", full_user, "/it", "/f"], timeout=15)
        _run(["schtasks", "/run", "/tn", task_name], timeout=15)
        _run(["schtasks", "/delete", "/tn", task_name, "/f"], timeout=15)
        return True
    except Exception as e:
        log(f"WARN: no se pudo lanzar el tray de inmediato en la sesion activa: {e}")
        return False


# ── register-tray: icono de bandeja para pausar con codigo (tipo Kaspersky) ──
# HKLM (no HKCU) a proposito: corre para CUALQUIER usuario que inicie sesion
# en el equipo, con los permisos de esa cuenta (nunca como SYSTEM ni
# administrador) - ver el docstring de smartmonitor_tray.py, la pausa la
# puede pedir cualquiera, lo que la protege es el CODIGO, no el nivel de
# permisos de Windows.
def cmd_register_tray(args):
    # smartmonitor-tray.exe paso de --onefile a --onedir (ver BUILD.md) -
    # ahora vive en su propia subcarpeta, no directo en app_dir.
    exe_path = os.path.join(args.app_dir, "smartmonitor-tray", "smartmonitor-tray.exe")
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                              r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                              0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "SmartMonitorTray", 0, winreg.REG_SZ, f'"{exe_path}"')
        winreg.CloseKey(key)
    except Exception as e:
        log(f"ERROR: no se pudo registrar el autoarranque del tray: {e}")
        return 1
    if _launch_in_active_session(exe_path):
        log("OK: tray registrado y lanzado de inmediato en la sesion activa")
    else:
        log("OK: tray registrado (arranca en el proximo inicio de sesion de cada usuario)")
    return 0


FILE_ATTRIBUTE_HIDDEN = 0x02

# ── hide-folder: oculta C:\SmartMonitor del Explorador ───────────────────────
# No es un rootkit - el usuario sigue pudiendo verla activando "Elementos
# ocultos" en el Explorador, esto solo evita que aparezca sin mas al navegar
# C:\ como cualquier otra carpeta - antes quedaba visible, a diferencia de
# otras herramientas de monitoreo/control parental que si ocultan la suya.
# Solo HIDDEN, sin sumar FILE_ATTRIBUTE_SYSTEM a proposito: marcar una
# carpeta comun como "de sistema" es justo el patron que la heuristica de
# varios antivirus asocia con tecnicas de ocultamiento de malware (visto de
# cerca en esta misma migracion con Kaspersky) - HIDDEN solo ya cumple el
# objetivo (no aparece por defecto) sin ese riesgo extra.
def cmd_hide_folder(args):
    try:
        ok = ctypes.windll.kernel32.SetFileAttributesW(
            args.app_dir, FILE_ATTRIBUTE_HIDDEN)
        if not ok:
            log(f"WARN: no se pudo ocultar la carpeta (codigo {ctypes.GetLastError()})")
            return 1
    except Exception as e:
        log(f"ERROR ocultando la carpeta: {e}")
        return 1
    log("OK: carpeta ocultada")
    return 0


# ── validate-uninstall-code ──────────────────────────────────────────────────
def _load_server_url():
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f).get("server")
    except Exception:
        return None

def cmd_validate_uninstall_code(args):
    server = _load_server_url() or "http://52.73.185.45:8000"
    serial = None
    try:
        rows = _wmi_query("SELECT SerialNumber FROM Win32_BIOS")
        if rows:
            serial = rows[0].SerialNumber
    except Exception:
        pass
    hostname = os.environ.get("COMPUTERNAME") or socket.gethostname()

    body = json.dumps({"hostname": hostname, "serial": serial, "code": args.code}).encode()
    req = urllib.request.Request(f"{server}/api/agents/uninstall-code/validate",
                                  data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        resp = json.loads(urllib.request.urlopen(req, timeout=10).read())
        if resp.get("valid"):
            log("OK: codigo valido")
            return 0
        log("ERROR: codigo invalido")
        return 1
    except urllib.error.HTTPError as e:
        # El servidor manda el detalle real (ej. "Codigo incorrecto", "El
        # codigo expiro") en el body del error, no en la excepcion misma.
        detail = ""
        try:
            detail = json.loads(e.read()).get("detail", "")
        except Exception:
            pass
        log(f"ERROR: no se pudo validar el codigo: {detail or e}")
        return 1
    except Exception as e:
        log(f"ERROR: no se pudo contactar al servidor: {e}")
        return 1  # sin bypass: si no se puede validar, no se desinstala


# ── uninstall-cleanup: teardown completo, invocado por [UninstallRun] ──────
def cmd_uninstall_cleanup(args):
    log("SmartMonitor - limpiando instalacion...")
    cmd_cleanup_previous(args)  # cubre tarea/servicio/registro/procesos/DNS/politicas/firewall

    log("Desconectando y desinstalando Tailscale (si lo instalo este agente)...")
    if os.path.exists(TAILSCALE_EXE):
        _run([TAILSCALE_EXE, "logout"], timeout=10)
        rows = [r for r in _wmi_query(
            "SELECT IdentifyingNumber FROM Win32_Product WHERE Name='Tailscale'")]
        for r in rows:
            _run(["msiexec.exe", "/x", r.IdentifyingNumber, "/quiet", "/norestart"], timeout=60)

    log("Quitando el certificado de la CA de SmartMonitor...")
    _run(["certutil.exe", "-delstore", "Root", "SmartMonitor Root CA"])

    log("SmartMonitor - limpieza completada.")
    return 0


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("cleanup-previous")

    p = sub.add_parser("write-config")
    p.add_argument("--server", required=True)

    sub.add_parser("install-tailscale")

    p = sub.add_parser("install-ca-cert")
    p.add_argument("--server", required=True)

    p = sub.add_parser("register-service")
    p.add_argument("--app-dir", required=True)

    p = sub.add_parser("register-tray")
    p.add_argument("--app-dir", required=True)

    p = sub.add_parser("hide-folder")
    p.add_argument("--app-dir", required=True)

    p = sub.add_parser("validate-uninstall-code")
    p.add_argument("--code", required=True)

    sub.add_parser("uninstall-cleanup")

    args = parser.parse_args()
    handlers = {
        "cleanup-previous": cmd_cleanup_previous,
        "write-config": cmd_write_config,
        "install-tailscale": cmd_install_tailscale,
        "install-ca-cert": cmd_install_ca_cert,
        "register-service": cmd_register_service,
        "register-tray": cmd_register_tray,
        "hide-folder": cmd_hide_folder,
        "validate-uninstall-code": cmd_validate_uninstall_code,
        "uninstall-cleanup": cmd_uninstall_cleanup,
    }
    sys.exit(handlers[args.cmd](args))


if __name__ == "__main__":
    main()

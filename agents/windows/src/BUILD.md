# Compilar el agente (PyInstaller) + el instalador gráfico (Inno Setup)

Se necesita una máquina Windows real para compilar y correr los `.exe`
finales - eso no cambia. Pero **sí se puede hacer sin tener una PC Windows a
mano**: todo este flujo se compiló y probó de punta a punta (instalar,
reinstalar encima, desinstalar, Servicio, DNS, cloudflared) conectándose por
SSH a una máquina Windows real, y también levantando un Windows real dentro
de una VM QEMU/KVM en Docker (`dockurr/windows`) en una maquina Linux - en
ambos casos, todo el trabajo (subir código, compilar con PyInstaller, correr
Inno Setup, instalar/desinstalar, revisar logs) se hizo por línea de
comandos via SSH, sin necesitar ver la pantalla de Windows directamente.

Esta carpeta (`agents/windows/src/`) contiene **solo código
fuente en Python** (`.py`) más el `.iss` de Inno Setup — nada de PowerShell,
a pedido explícito. Hay tres programas Python, cada uno se compila por
separado con **PyInstaller** en su propio `.exe` (sin Python instalado por
separado en la máquina destino — misma propiedad de "un solo binario, sin
dependencias de runtime" que ya tiene `cloudflared.exe`):

- **`smartmonitor_agent.py`** → `smartmonitor-agent.exe`: el agente en sí
  (métricas, inventario, Tailscale, y el bloqueo vía `cloudflared`), corriendo
  como **Servicio nativo de Windows** (no Tarea Programada, no NSSM - ver
  "Notas de diseño"). Reemplaza al viejo `smartmonitor-push.ps1` (que se
  mantiene intacto en `agents/windows/legacy/antiguos/` como respaldo por-equipo
  durante la transición).
- **`smartmonitor_installer_helper.py`** → `smartmonitor-installer-helper.exe`:
  todo lo que el instalador necesita ejecutar (limpieza de una instalación
  previa, Tailscale, certificado CA, Servicio de Windows, tray) y todo lo que
  antes vivía en `uninstall-cleanup.ps1`/`validate-uninstall-code.ps1` — un
  solo binario con subcomandos (`cleanup-previous`, `write-config`,
  `install-tailscale`, `install-ca-cert`, `register-service`, `register-tray`,
  `validate-uninstall-code`, `uninstall-cleanup`), invocado por
  `smartmonitor-agent.iss` vía `Exec()`. El propio `.iss` sigue en Pascal
  Script (el lenguaje propio de Inno Setup) — eso no es PowerShell, no
  cambia.
- **`smartmonitor_tray.py`** → `smartmonitor-tray.exe`: ícono de bandeja para
  que el usuario del equipo pause el bloqueo el mismo con un código (tipo
  Kaspersky) - corre en la sesión del usuario logueado (el Servicio corre en
  Session 0, sin escritorio, así que no puede mostrar nada visual el mismo).

## 0) Descargar cloudflared

Se **embebe dentro del `.exe`** (PyInstaller `--add-data`), no se descarga en
tiempo de ejecución. Guardarlo como `agents/windows/src/cloudflared.exe`.

## 1) Instalar Python + PyInstaller + pywin32

```cmd
pip install pyinstaller pywin32
```

## 2) Compilar el agente

Desde una consola en `agents/windows/src/`:

```cmd
pyinstaller --onedir --noconsole --name smartmonitor-agent ^
    --icon icon.ico ^
    --add-data "cloudflared.exe;." ^
    --hidden-import win32timezone ^
    --hidden-import win32serviceutil ^
    --hidden-import win32service ^
    --hidden-import win32event ^
    --hidden-import servicemanager ^
    --collect-submodules win32com ^
    smartmonitor_agent.py
```

## 2.1) Compilar el helper de instalación/desinstalación

```cmd
pyinstaller --onedir --name smartmonitor-installer-helper ^
    --icon icon.ico ^
    --hidden-import win32timezone ^
    --collect-submodules win32com ^
    smartmonitor_installer_helper.py
```

## 2.2) Compilar el icono de bandeja

```cmd
pyinstaller --onedir --noconsole --name smartmonitor-tray ^
    --icon icon.ico ^
    --hidden-import win32timezone ^
    --collect-submodules win32com ^
    smartmonitor_tray.py
```

## 3) Compilar con Inno Setup

```cmd
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" smartmonitor-agent.iss
```

El instalador queda generado en `dist/SmartMonitor-Agent-Setup.exe`.

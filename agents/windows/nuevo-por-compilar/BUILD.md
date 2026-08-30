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

Esta carpeta (`agents/windows/nuevo-por-compilar/`) contiene **solo código
fuente en Python** (`.py`) más el `.iss` de Inno Setup — nada de PowerShell,
a pedido explícito. Hay tres programas Python, cada uno se compila por
separado con **PyInstaller** en su propio `.exe` (sin Python instalado por
separado en la máquina destino — misma propiedad de "un solo binario, sin
dependencias de runtime" que ya tiene `cloudflared.exe`):

- **`smartmonitor_agent.py`** → `smartmonitor-agent.exe`: el agente en sí
  (métricas, inventario, Tailscale, y el bloqueo vía `cloudflared`), corriendo
  como **Servicio nativo de Windows** (no Tarea Programada, no NSSM - ver
  "Notas de diseño"). Reemplaza al viejo `smartmonitor-push.ps1` (que se
  mantiene intacto en `agents/windows/antiguos/` como respaldo por-equipo
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

## 0) Descargar cloudflared (una vez, y cada vez que se actualice el pin)

Se **embebe dentro del `.exe`** (PyInstaller `--add-data`), no se descarga en
tiempo de ejecución — descargar y ejecutar un binario de terceros al vuelo es
justo el patrón que ya hizo que Kaspersky bloqueara NSSM (ver "Notas de
diseño"); empaquetarlo dentro del artefacto firmado/instalado es una postura
distinta y ya aceptada.

Descargar el binario oficial (pin de versión, no "latest", para que el build
sea reproducible) desde
[github.com/cloudflare/cloudflared/releases](https://github.com/cloudflare/cloudflared/releases)
— `cloudflared-windows-amd64.exe`, y guardarlo como `agents/windows/cloudflared.exe`.

**Versión pineada actual: registrar aquí el tag exacto (ej. `2026.x.y`) y el
SHA256 del binario cada vez que se actualice**, para poder auditar qué build
se distribuyó:

```
# cloudflared version: 2026.1.2
# SHA256: 6304f5e1c017c038fb74a02c0157b2b63d4bc1f15709c639fcc08cb6dbe4c126
#
# OJO: no usar una version mas nueva que esta sin verificar antes - Cloudflare
# elimino el subcomando "proxy-dns" (justo el que usa este agente, ver
# supervise_cloudflared() en smartmonitor_agent.py) a partir de la version
# 2026.2.0. Confirmado corriendo el binario real: 2026.7.3 tira
# "dns-proxy feature is no longer supported"; 2026.1.2 es la ultima release
# anterior al cambio y si lo soporta. Si en el futuro hace falta actualizar
# cloudflared (por una CVE, por ejemplo), primero correr
# "cloudflared.exe proxy-dns --address 127.0.0.1 --port 53 --upstream https://dns.smartmonitor.local/dns-query"
# a mano con la version nueva y confirmar que no tira ese error antes de
# pinear la version y recompilar.
```

## 1) Instalar Python + PyInstaller + pywin32

```
pip install pyinstaller pywin32
```

## 2) Compilar el agente

`icon.ico` (icono de la app: instalador, .exe's y bandeja) ya está en esta
misma carpeta - lo usan los tres `pyinstaller --icon` de abajo y el
`SetupIconFile` del .iss. Si falta, regenerarlo desde el PNG original:
`python3 -c "from PIL import Image; Image.open('Icono.png').convert('RGBA').save('icon.ico', sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])"`.

Desde una consola, parado en `agents/windows/nuevo-por-compilar/`:

```
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

**`--onedir`, NO `--onefile`, es obligatorio para este .exe especifico**
(confirmado con un build real - ver "Notas de diseño" mas abajo para el
detalle completo): un Servicio de Windows tiene que ser el MISMO proceso
que arranca el Administrador de Servicios. El bootloader `--onefile` en
realidad arranca un "lanzador" que extrae todo a una carpeta temporal y
lanza un proceso HIJO separado - el Administrador de Servicios rechaza eso
("El Administrador de control de servicios inicio el proceso X pero el
proceso Y se conecto en su lugar", visible en el Visor de Eventos) y el
servicio nunca termina de arrancar (falla con "El servicio no respondio a
tiempo a la solicitud de inicio", timeout de 30 segundos). `--onedir` no
tiene ese problema - el `.exe` final ES el proceso, sin relanzar nada - a
cambio de quedar como una CARPETA (`dist/smartmonitor-agent/`, con el `.exe`
mas una subcarpeta `_internal/`) en vez de un solo archivo.

Los 4 `--hidden-import` de servicio son necesarios ademas de
`win32timezone`/`win32com` - PyInstaller no los detecta solo porque se
importan dentro de un `try/except ImportError` (para poder importar el
modulo fuera de Windows, ver el inicio del archivo).

El agente corre como **Servicio nativo de Windows** (no NSSM, no Tarea
Programada - ver `SmartMonitorService`/`_run_as_service_or_cli()` en
`smartmonitor_agent.py` y "Notas de diseño" mas abajo).

La carpeta completa `dist/smartmonitor-agent/` queda en esta misma carpeta
(junto al `.iss`, que ya la referencia como tal en `[Files]` con
`recursesubdirs`) antes del paso 4.

**Antes de compilar, correr una sola vez en la maquina de build** (no hace
falta repetirlo en cada compilacion, solo si la maquina es nueva):

```
python Scripts\pywin32_postinstall.py -install
```

Sin esto, el `.exe` compila bien pero el Servicio puede fallar al arrancar
(`servicemanager` necesita una DLL de recursos - `pythonserviceXX.dll` - que
este paso copia a `System32`; sin ella, `sc start SmartMonitorAgent` puede
devolver un error generico sin mensaje util). Esto es un problema conocido de
empaquetar servicios pywin32 con PyInstaller, documentado aca preventivamente
- pendiente de confirmar con un build real (ver checklist de prueba manual
mas abajo) si en la practica hace falta o si `--collect-submodules win32com`
ya alcanza.

## 2.1) Compilar el helper de instalación/desinstalación

Mismo `pip install` del paso 1, misma carpeta. A diferencia del agente, se
compila **con consola** (sin `--noconsole`) — Inno Setup igual lo invoca
oculto (`SW_HIDE`), pero mantener la consola disponible ayuda si alguna vez
hay que correr un subcomando a mano para diagnosticar una instalación que
falló:

```
pyinstaller --onedir --name smartmonitor-installer-helper ^
    --icon icon.ico ^
    --hidden-import win32timezone ^
    --collect-submodules win32com ^
    smartmonitor_installer_helper.py
```

**`--onedir`, no `--onefile`** (cambiado después de un incidente real - ver
"Notas de diseño" más abajo): Kaspersky detectó y mató
`smartmonitor-installer-helper.exe` como "Malicious object" durante una
instalación de verdad. El bootloader `--onefile` se auto-extrae a una
carpeta temporal cada vez que arranca, patrón que coincide con el de muchos
droppers de malware y dispara la heurística de comportamiento de varios
antivirus (no solo Kaspersky), sin importar si el `.exe` está firmado.

La carpeta completa `dist/smartmonitor-installer-helper/` queda en esta
misma carpeta (junto al `.iss`) — copiarla junto al paso anterior.

Se puede probar cada subcomando a mano antes de empaquetar el instalador
completo, por ejemplo:

```
dist\smartmonitor-installer-helper\smartmonitor-installer-helper.exe write-config --server "http://192.168.1.50:8000"
dist\smartmonitor-installer-helper\smartmonitor-installer-helper.exe install-ca-cert --server "192.168.1.50"
dist\smartmonitor-installer-helper\smartmonitor-installer-helper.exe register-service --app-dir "C:\SmartMonitor"
```

## 2.2) Compilar el icono de bandeja (pausar con código, tipo Kaspersky)

Mismo `pip install` del paso 1, misma carpeta. Se compila **sin consola**
(corre en la sesión del usuario logueado, con ícono en la bandeja - una
ventana de consola detrás se vería rara). Necesita `tkinter` para el
diálogo de "ingresar código" - viene con cualquier instalación estándar de
Python en Windows, PyInstaller lo detecta solo:

```
pyinstaller --onedir --noconsole --name smartmonitor-tray ^
    --icon icon.ico ^
    --hidden-import win32timezone ^
    --collect-submodules win32com ^
    smartmonitor_tray.py
```

**`--onedir`, no `--onefile`** — mismo motivo que el helper de arriba
(bootloader `--onefile` disparando heurística de antivirus).

La carpeta completa `dist/smartmonitor-tray/` queda en esta misma carpeta —
copiarla junto a las dos anteriores.

## 3) Instalar Inno Setup

Descargar e instalar Inno Setup 6 (gratuito): https://jrsoftware.org/isdl.php

## 4) Compilar el instalador

Desde una consola, parado en `agents/windows/nuevo-por-compilar/` (con las
carpetas completas `smartmonitor-agent/`, `smartmonitor-installer-helper/` y
`smartmonitor-tray/` de los pasos 2, 2.1 y 2.2, ya presentes en esta
carpeta):

```
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" smartmonitor-agent.iss
```

El instalador queda en `dist/SmartMonitor-Agent-Setup.exe`.

Cada vez que cambie `smartmonitor_agent.py`, `smartmonitor_installer_helper.py`
o `smartmonitor_tray.py`, hay que **recompilar todo de nuevo** (PyInstaller de
lo que cambió, después siempre Inno Setup) — a diferencia del `.bat` viejo,
este instalador es un `.exe` cerrado, no recoge cambios de archivos sueltos.
Sube el número de `MyAppVersion` en `smartmonitor-agent.iss` en cada
recompilación para poder identificar qué build es cada `.exe`.

## 5) Firma digital (opcional, pero recomendado)

Sin firmar, Windows SmartScreen va a avisar "Editor desconocido" la primera
vez que se ejecute en cada equipo (ver más abajo). Si se compra un
certificado de code-signing, firmarlo después de compilar con:

```
signtool sign /f certificado.pfx /p <contraseña> /fd sha256 /tr http://timestamp.digicert.com /td sha256 dist\SmartMonitor-Agent-Setup.exe
```

## 6) Checklist de prueba manual

Correr en una máquina Windows de prueba (no en un equipo de producción):

**Básico (igual que con el `.ps1` viejo):**

- [ ] **Instalación limpia**: correr el `.exe` en un equipo sin el agente.
  Confirmar que aparece el equipo en el panel en unos segundos.
- [ ] **Reinstalación sobre una instalación existente (agente corriendo)**:
  volver a correr el `.exe` con el agente ya instalado y el servicio activo.
  Confirmar que `PrepareToInstall` frena el servicio antes de copiar
  archivos (si no, Setup aborta con "Setup was unable to automatically
  close all applications" - visto en pruebas reales) y que no queda
  duplicado (ni Servicio ni proceso viejo, ni `cloudflared.exe` huérfano).
- [ ] **Auto-reinicio del servicio**: con el agente instalado, abrir el
  Administrador de tareas, matar el proceso `smartmonitor-agent.exe`.
  Confirmar que reaparece solo en pocos segundos (revisar
  `sc query SmartMonitorAgent` o el Administrador de tareas - mucho más
  rápido que el ~1 minuto de la Tarea Programada que reemplaza).
- [ ] **Permisos del servicio**: como usuario SIN permisos de administrador,
  intentar `sc stop SmartMonitorAgent` / detenerlo desde
  `services.msc` — debe fallar ("Acceso denegado"). Como administrador, sí
  debe poder gestionarse (límite esperado — nada impide a un administrador
  local de verdad).
- [ ] **Desinstalar con código correcto**: generar un código desde el panel
  (botón "🔑 Código de desinstalación" en el detalle del equipo), correr el
  desinstalador (desde "Agregar o quitar programas" o `unins000.exe`),
  ingresar el código — debe completarse sin problema.
- [ ] **Desinstalar con código incorrecto**: repetir, pero escribiendo un
  código inválido — debe cancelarse sin tocar nada.
- [ ] **Desinstalar con código expirado**: generar un código, esperar 30+
  minutos (o ajustar `_EXPIRY_MINUTES` temporalmente en
  `server/app/routers/agent_uninstall_codes.py` para probar más rápido),
  confirmar que se rechaza.
- [ ] **Desinstalar sin poder llegar al servidor**: desconectar la red del
  equipo antes de desinstalar — debe cancelarse (sin bypass, por diseño).
- [ ] **Confirmar limpieza completa tras desinstalar**: `smartmonitor-agent.exe`
  y `cloudflared.exe` ya NO estan corriendo (antes de esto era un bug: el
  desinstalador borraba el registro pero dejaba el proceso vivo, bloqueando
  el `.exe` - "algunos elementos no se pudieron eliminar"), el servicio
  `SmartMonitorAgent` ya no existe (`sc query SmartMonitorAgent` -> "no
  existe el servicio"), DNS IPv4 Y IPv6 vuelven a automático (`nslookup`
  responde bien de nuevo), `C:\SmartMonitor` se borra.

**Específico de cloudflared / DoH (nuevo, no existía con el `.ps1`):**

- [ ] `cloudflared.exe` se extrae correctamente desde el `.exe` embebido y
  arranca como proceso hijo; confirmar que `127.0.0.1:53` queda escuchando
  (`netstat -an | findstr :53`).
- [ ] La línea en `C:\Windows\System32\drivers\etc\hosts` para
  `dns.smartmonitor.local` aparece una sola vez, apunta a la IP tailnet
  correcta, y se actualiza (no se duplica) si Tailscale se reconecta con
  otra IP.
- [ ] El DNS del sistema queda fijo en `127.0.0.1` **una sola vez** al
  arrancar y **nunca se vuelve a tocar** en ciclos posteriores — monitorear
  varios minutos (Visor de eventos o simplemente `Get-DnsClientServerAddress`
  repetido) y confirmar que no cambia.
- [ ] **La prueba que de verdad importa**: dejar el agente corriendo varias
  horas con Kaspersky (u otro antivirus disponible) activo y confirmar que
  **no vuelve a aparecer** la alerta de System Watcher/"Object deleted" que
  motivó este rediseño.
- [ ] Un dominio bloqueado para ese equipo se bloquea de verdad en el
  navegador (Chrome/Edge/Firefox/Brave, HTTP y HTTPS) **sin ningún cambio de
  política de navegador** — confirma que desactivar el "Secure DNS" del
  navegador ya no hace falta con este diseño.
- [ ] Cambiar de una red permitida a una no permitida (y viceversa, ver
  Configuración → Red permitida en el panel): confirmar que el bloqueo
  reacciona dentro de un ciclo de sondeo.
- [ ] Pausar el bloqueo del equipo desde el panel (botón "⏸ Pausar bloqueo")
  y confirmar que deja de bloquear de punta a punta a través del camino DoH
  nuevo (sin reiniciar el agente).
- [ ] Matar `cloudflared.exe` a mano (Administrador de tareas) con el agente
  vivo: confirmar que se reinicia solo en segundos (no hay que esperar el
  minuto de la Tarea Programada — ver `supervise_cloudflared()` en
  `smartmonitor_agent.py`).
- [ ] **Riesgo marcado como incierto en el plan, validar aquí**: confirmar
  que `cloudflared` confía en la CA propia de SmartMonitor (ya importada al
  almacén de Windows) sin flags adicionales. Si el handshake TLS falla,
  aplicar el fallback documentado (apuntar `--upstream` al dominio público
  en vez del hostname interno) y volver a probar.

## Notas de diseño (por qué quedó así)

- **Cero PowerShell en todo el flujo** (a pedido explícito, ampliando una
  decisión anterior que ya evitaba un `.ps1` *auxiliar* pero seguía usando
  PowerShell internamente vía scripts temporales `RunPS`): todo lo que antes
  corría como `powershell.exe -File ...` (los pasos de instalación, y los dos
  scripts `uninstall-cleanup.ps1`/`validate-uninstall-code.ps1`) se reescribió
  en Python (`smartmonitor_installer_helper.py`) y se compila a un único
  `.exe` que el `.iss` invoca por subcomando vía `Exec()` — exactamente igual
  a como ya invocaba `netsh.exe`/`icacls.exe`/`schtasks.exe` nativos
  directamente, ninguno de esos es PowerShell tampoco. El `.iss` en sí sigue
  en Pascal Script (el lenguaje propio de Inno Setup para el asistente
  gráfico) — eso no es PowerShell y no cambia.
- **`agents/windows/antiguos/`** contiene el agente viejo en PowerShell
  (`smartmonitor-push.ps1`) y su instalador `.bat`, intactos, como respaldo
  por-equipo durante la transición: si el `.exe` nuevo falla en una máquina
  puntual, reinstalar con el instalador viejo restaura el comportamiento
  conocido sin tocar el servidor (el contrato HTTP de
  `/api/agents/blocklist` no cambió, así que ambos agentes pueden convivir
  en la misma flota mientras dure la migración). Ese `.bat` viejo tiene su
  **propia copia** de `validate-uninstall-code.ps1`/`uninstall-cleanup.ps1`
  (duplicadas a propósito en vez de compartidas con el flujo nuevo — si se
  edita una lógica de limpieza compartida entre ambos caminos, hay que
  replicar el cambio a mano en las dos carpetas).
- **Por qué se reescribió el agente y se sumó `cloudflared`**: el `.ps1`
  bloqueaba DNS-over-HTTPS apuntando/desapuntando el DNS del sistema y
  creando/borrando 6 reglas de firewall + políticas de registro en cada
  ciclo (~60s) — ese patrón de creación/borrado repetido, corriendo como
  SYSTEM, disparaba la heurística de comportamiento de Kaspersky (System
  Watcher, "Object deleted", `PDM:Trojan.Win32.Generic`). Ahora el DNS del
  sistema se fija UNA sola vez a `127.0.0.1`, donde `cloudflared.exe`
  (binario oficial de Cloudflare, open source) reenvía todo a un endpoint
  DoH nuevo del servidor (`/dns-query` en `dns_blocker.py`) que aplica el
  mismo filtrado de siempre — sin volver a tocar DNS/firewall/registro
  nunca más. `cloudflared` corre como proceso hijo supervisado por el propio
  agente (no como servicio nativo de Windows vía `cloudflared service
  install` — esa vía tiene fricción documentada para el modo `proxy-dns`,
  ver conversación de diseño), y Tailscale se mantiene como el camino de red
  que le da a `cloudflared` una URL con SNI válido hacia el servidor
  (`dns.smartmonitor.local` vía una línea en el archivo `hosts`), preservando
  la identificación por equipo detrás de un NAT de oficina compartido.
- **El `.bat` viejo se mantiene en paralelo**, no se borra — vía manual/
  ligera para quien la prefiera, en `agents/windows/antiguos/`. Instala/
  gestiona el agente viejo en `.ps1`, no el `.exe` nuevo — no se actualizó
  como parte de este cambio (usar el instalador gráfico para el agente
  nuevo).
- **Historial - por que primero se eligio Tarea Programada en vez de un
  Servicio, y por que ahora si es un Servicio**: se probó primero envolver
  el agente con NSSM como Servicio de Windows (reinicio casi instantáneo),
  pero Kaspersky (y probablemente otros antivirus) bloqueó la
  descarga/ejecución del `.exe` de NSSM — el patrón "un script descarga y
  ejecuta un binario de terceros que se instala con privilegios" es justo
  lo que la heurística de varios antivirus marca como sospechoso/tipo
  "dropper", sin importar si se empaqueta en vez de descargarse en el
  momento. En ese momento se volvió a la Tarea Programada (100% nativa,
  firmada por Microsoft) como alternativa mas segura frente a esa
  heurística, con el archivo de la tarea bloqueado por ACL (`icacls`) para
  que un usuario sin permisos de administrador no pudiera
  detenerla/deshabilitarla, a cambio de un reinicio mas lento (~1 minuto).
  A pedido explícito de que el reinicio sea mas rapido y confiable, ahora
  el agente ES el Servicio directamente (`win32serviceutil.ServiceFramework`,
  registrado con `sc.exe create` — ver `cmd_register_service` en
  `smartmonitor_installer_helper.py`) — un patrón distinto al de NSSM: no
  hay ningun binario de terceros de por medio, es nuestro propio `.exe`
  actuando como servicio via la API nativa de Windows, la misma que usa
  cualquier servicio legitimo (Windows Update, etc.). `sc.exe failure`
  reinicia el proceso a los pocos segundos si muere o si lo terminan a
  mano, y el Security Descriptor por defecto de un servicio LocalSystem ya
  rechaza que un usuario sin permisos de administrador lo
  detenga/deshabilite/borre — no hace falta un ACL aparte como con la Tarea
  Programada. **Confirmado con un build real**: el Servicio arranca solo al
  bootear la maquina, y si se mata el proceso a mano (`taskkill /F`), el
  Administrador de Servicios lo reinicia con un PID nuevo en unos pocos
  segundos (no el ~1 minuto de la Tarea Programada). Pendiente todavia
  probarlo con Kaspersky activo (ver checklist mas arriba) - a diferencia de
  NSSM, no hay descarga+ejecución de un binario de terceros con privilegios,
  pero de todas formas conviene confirmarlo antes de desplegarlo a toda la
  flota.
- **Dos bugs reales encontrados armando y probando el Servicio por primera
  vez** (ambos con build real, no solo lectura de código - ver commits/notas
  de esta sesión):
  1. **`--onefile` rompe el Servicio** (ver nota extensa en el paso 2 de
     arriba) - el bootloader relanza un proceso hijo, y el Administrador de
     Servicios rechaza que un proceso distinto al que el arranco se conecte.
     Fix: compilar el agente con `--onedir`.
  2. **La espera de red bloqueaba el arranque del Servicio**: `_wait_for_network()`
     (heredada del diseño con Tarea Programada, donde no importaba cuanto
     tardara) se llamaba a NIVEL DE MODULO - se ejecutaba durante el
     `import`, antes de que el codigo del Servicio pudiera reportar
     `SERVICE_RUNNING`. Como puede tardar hasta 60 segundos y el
     Administrador de Servicios de Windows exige una actualización de
     estado dentro de los primeros ~30 segundos, el arranque fallaba
     ("El servicio no respondió a tiempo a la solicitud de inicio")
     cada vez que la red no contestaba de inmediato - intermitente, no
     siempre reproducible. Fix: la espera de red se movió adentro de
     `main()` (que corre despues de reportar `SERVICE_RUNNING` en
     `SvcDoRun`), y `SvcDoRun` ahora llama
     `self.ReportServiceStatus(win32service.SERVICE_RUNNING)`
     explícitamente antes de hacer cualquier otra cosa.
- **Límite explícito, conocido y aceptado**: nada de esto impide a un
  administrador local de verdad detener el servicio (puede matar el proceso
  con más privilegios, deshabilitar el servicio, o arrancar en Modo Seguro)
  — no existe forma de evitar eso sin un driver de kernel, que no se
  construye aquí (cruza a territorio de rootkit). La mitigación real es la
  detección: el equipo aparece "offline" en el panel casi de inmediato si
  el agente deja de correr, con notificación automática ya existente para
  ese evento.
- **`smartmonitor-installer-helper.exe` también pasó de `--onefile` a
  `--onedir`** (agosto 2026): en una instalación real sobre un equipo con
  Kaspersky, el registro de eventos mostró `Malicious object detected` +
  `Process terminated` para `smartmonitor-installer-helper.exe`, matando el
  proceso a mitad de la instalación (visible después como "No se puede
  ejecutar esta aplicación en este equipo" al reintentar, porque el archivo
  quedaba en cuarentena/corrupto). Mismo motivo raíz que ya se había resuelto
  para el agente: el bootloader `--onefile` se auto-extrae a una carpeta
  temporal en cada arranque, un patrón de comportamiento que System Watcher
  (y heurísticas equivalentes de otros antivirus) asocia con droppers de
  malware, independientemente de que el binario esté firmado o no. Se aplicó
  el mismo fix (`--onedir`) también a `smartmonitor-tray.exe` de forma
  preventiva, ya que comparte el mismo patrón de empaquetado. Cada uno queda
  en su propia subcarpeta bajo `{app}` (`smartmonitor-installer-helper\` y
  `smartmonitor-tray\`) en vez de aplanarse junto al agente, para que sus
  respectivas carpetas `_internal` no choquen entre sí — ver `[Files]` en
  `smartmonitor-agent.iss`. Nota aparte, no resuelta acá: el helper también
  instala un certificado de CA raíz propio vía `certutil.exe -addstore Root`
  (paso `install-ca-cert`), que es en sí mismo un patrón de comportamiento
  asociado a intercepción TLS/MITM y probablemente una causa tan o más fuerte
  de la detección que el empaquetado — pendiente evaluar si hay forma de
  lograr el mismo objetivo (que `cloudflared` confíe en el certificado del
  servidor) sin tocar el almacén de confianza raíz de Windows.

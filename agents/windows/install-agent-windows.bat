@echo off
REM Este archivo debe guardarse con fin de linea CRLF (no LF). Con LF puro,
REM el bloque con continuacion de linea "^" (instalacion del certificado CA,
REM mas abajo) rompe el parser de cmd.exe y ejecuta fragmentos sueltos como
REM comandos ("IP", "M", "9009" no reconocidos) en vez de instalar. Si un
REM editor/herramienta vuelve a guardarlo en LF, reconvertir a CRLF antes
REM de distribuirlo.
chcp 65001 >nul 2>&1
title SmartMonitor v3 - Instalador Windows (instalacion limpia)

REM IP del servidor SmartMonitor por defecto — UNICO lugar a tocar si el
REM server se muda de IP. Se usa mas abajo solo si no se pasa un argumento
REM (install-agent-windows.bat <IP_SERVIDOR>).
set "SMARTMONITOR_DEFAULT_SERVER_IP=52.73.185.45"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Ejecuta este archivo como Administrador.
    echo Clic derecho - "Ejecutar como administrador"
    pause
    exit /b 1
)

set "INSTALL_DIR=C:\SmartMonitor"
set "PS_SRC=%~dp0smartmonitor-push.ps1"
set "PS_DEST=%INSTALL_DIR%\smartmonitor-push.ps1"

REM IP o dominio del servidor SmartMonitor: uso "install-agent-windows.bat <IP_SERVIDOR>"
REM Si no se pasa nada, usa la constante de arriba (SMARTMONITOR_DEFAULT_SERVER_IP).
set "SERVER_IP=%~1"
if "%SERVER_IP%"=="" set "SERVER_IP=%SMARTMONITOR_DEFAULT_SERVER_IP%"

if not exist "%PS_SRC%" (
    echo [ERROR] No se encuentra smartmonitor-push.ps1 en la misma carpeta.
    pause
    exit /b 1
)

REM Detecta si hay algo de una instalacion anterior para limpiar (tarea
REM programada o la carpeta de instalacion) - si no hay nada, se avisa
REM claramente en vez de imprimir "[OK]" de pasos que no hicieron nada.
set "HAD_PREVIOUS=0"
schtasks /query /tn "SmartMonitor" >nul 2>&1
if %errorlevel% equ 0 set "HAD_PREVIOUS=1"
if exist "%INSTALL_DIR%" set "HAD_PREVIOUS=1"

echo.
if "%HAD_PREVIOUS%"=="1" (
    echo  SmartMonitor v3 - Desinstalando instalacion previa...
) else (
    echo  SmartMonitor v3 - Sin instalaciones previas, instalando de cero...
)
echo.

if "%HAD_PREVIOUS%"=="1" (
    REM 1) Detener y eliminar la tarea programada
    schtasks /end /tn "SmartMonitor" >nul 2>&1
    powershell -ExecutionPolicy Bypass -Command "Unregister-ScheduledTask -TaskName 'SmartMonitor' -Confirm:$false -ErrorAction SilentlyContinue" >nul 2>&1
    echo [OK] Tarea programada eliminada

    REM 2) Quitar autoinicio en el registro
    powershell -ExecutionPolicy Bypass -Command "Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'SmartMonitor' -ErrorAction SilentlyContinue" >nul 2>&1
    echo [OK] Clave de autoinicio eliminada

    REM 3) Matar cualquier proceso del agente que quede vivo (libera el .ps1)
    powershell -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*smartmonitor-push.ps1*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1
    echo [OK] Procesos previos detenidos

    REM 4) Restaurar el DNS a automatico en todas las interfaces activas -
    REM antes esto buscaba especificamente 127.0.0.1 (de una arquitectura
    REM vieja de sinkhole local), pero el agente actual apunta el DNS al
    REM servidor publico o al tunel WireGuard, nunca a localhost, asi que
    REM ese filtro nunca coincidia con nada real. Se resetea todo sin
    REM condicionar a que IP tenga puesta ahora - mismo criterio que ya usa
    REM el desinstalador.
    powershell -ExecutionPolicy Bypass -Command "$adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }; foreach ($a in $adapters) { try { Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue } catch {} }; ipconfig /flushdns | Out-Null" >nul 2>&1
    echo [OK] DNS del sistema restaurado a automatico

    REM 5) Borrar el directorio de instalacion anterior
    if exist "%INSTALL_DIR%" (
        rd /s /q "%INSTALL_DIR%" >nul 2>&1
    )
    echo [OK] Directorio anterior eliminado
)

echo.
echo  SmartMonitor v3 - Instalando agente Windows...
echo.

if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
)

copy /Y "%PS_SRC%" "%PS_DEST%" >nul
echo [OK] Agente copiado a %PS_DEST%

REM Inyectar la IP/dominio del servidor en el script copiado (igual que el
REM instalador de Linux hace con sed). El .ps1 fuente trae un placeholder
REM fijo (__SMARTMONITOR_SERVER_IP__, no una IP real) que se reemplaza aca
REM por el SERVER_IP recibido — asi este reemplazo no se vuelve a romper el
REM dia que cambie el default (como paso antes: buscaba la IP vieja
REM 172.27.142.107, que dejo de existir en el archivo cuando se hardcodeo
REM una IP real, y el reemplazo pasaba a no hacer nada silenciosamente).
powershell -ExecutionPolicy Bypass -Command "(Get-Content -Raw '%PS_DEST%').Replace('__SMARTMONITOR_SERVER_IP__', '%SERVER_IP%') | Set-Content -Path '%PS_DEST%' -Encoding UTF8"
findstr /C:"__SMARTMONITOR_SERVER_IP__" "%PS_DEST%" >nul 2>&1
if %errorlevel% equ 0 (
    echo [ERROR] El reemplazo del servidor NO se aplico - %PS_DEST% todavia tiene el placeholder sin resolver.
) else (
    echo [OK] Servidor configurado: http://%SERVER_IP%:8000
)

REM Ocultar carpeta
attrib +H "%INSTALL_DIR%" >nul 2>&1

powershell -Command "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force" >nul 2>&1
echo [OK] Politica de ejecucion configurada

echo.
echo Probando conexion con el servidor...
powershell -ExecutionPolicy Bypass -Command "try{Invoke-WebRequest 'http://%SERVER_IP%:8000' -TimeoutSec 5 -UseBasicParsing | Out-Null; Write-Host '[OK] Servidor accesible'}catch{Write-Host '[WARN] No se pudo conectar al servidor.'}"

echo.
echo Instalando cliente Tailscale (tunel WireGuard para identificar el equipo sin ambiguedad de IP compartida)...
if exist "%ProgramFiles%\Tailscale\tailscale.exe" (
    echo [OK] Tailscale ya estaba instalado
) else (
    powershell -ExecutionPolicy Bypass -Command "try { Invoke-WebRequest 'https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi' -OutFile 'C:\SmartMonitor\tailscale-setup.msi' -TimeoutSec 60 -UseBasicParsing; Write-Host '[OK] Tailscale descargado' } catch { Write-Host '[WARN] No se pudo descargar Tailscale (reintenta luego re-ejecutando este instalador; el agente sigue bloqueando por IP publica mientras tanto)' }"
    if exist "C:\SmartMonitor\tailscale-setup.msi" (
        msiexec /i "C:\SmartMonitor\tailscale-setup.msi" /quiet /norestart
        del /f /q "C:\SmartMonitor\tailscale-setup.msi" >nul 2>&1
        echo [OK] Tailscale instalado
    )
)

REM El agente solo necesita el servicio de Tailscale (usa la CLI para
REM conectarse), no la app grafica de bandeja - ademas de quitar su acceso
REM directo de inicio, se renombra el ejecutable de la interfaz grafica para
REM que nadie pueda abrirla a mano (desde el menu de inicio, buscador, etc.)
REM y desconectar el tunel por accidente o a proposito. El servicio sigue
REM funcionando igual - no depende de este ejecutable para nada.
del /f /q "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Tailscale.lnk" >nul 2>&1
taskkill /IM tailscale-ipn.exe /F >nul 2>&1
if exist "%ProgramFiles%\Tailscale\tailscale-ipn.exe" (
    move /y "%ProgramFiles%\Tailscale\tailscale-ipn.exe" "%ProgramFiles%\Tailscale\tailscale-ipn.exe.disabled" >nul 2>&1
)

echo.
echo Instalando certificado de la CA del servidor (para que la pagina de bloqueo se vea tambien en sitios HTTPS)...
powershell -ExecutionPolicy Bypass -Command ^
    "try { $r = Invoke-WebRequest 'http://%SERVER_IP%/smartmonitor-ca.crt' -TimeoutSec 5 -UseBasicParsing;" ^
    " $path = 'C:\SmartMonitor\smartmonitor-ca.crt'; [IO.File]::WriteAllBytes($path, $r.Content);" ^
    " Import-Certificate -FilePath $path -CertStoreLocation Cert:\LocalMachine\Root | Out-Null;" ^
    " Write-Host '[OK] CA instalada en el almacen de confianza (Chrome/Edge la heredan)' }" ^
    " catch { Write-Host '[WARN] No se pudo instalar la CA (reintenta luego re-ejecutando este instalador)' }"

echo.
echo Creando tarea programada (corre sin login, como SYSTEM)...
powershell -ExecutionPolicy Bypass -Command "Unregister-ScheduledTask -TaskName 'SmartMonitor' -Confirm:$false -ErrorAction SilentlyContinue; $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -NonInteractive -File C:\SmartMonitor\smartmonitor-push.ps1'; $t1 = New-ScheduledTaskTrigger -AtStartup; $t2 = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5); $s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; Register-ScheduledTask -TaskName 'SmartMonitor' -Action $a -Trigger @($t1,$t2) -Settings $s -Principal $p -Force | Out-Null; Start-ScheduledTask -TaskName 'SmartMonitor'"

if %errorlevel% equ 0 (
    echo [OK] Tarea creada (SYSTEM) - corre sin login, se reinicia cada 5 min si falla
) else (
    echo [ERROR] No se pudo crear la tarea programada.
    pause
    exit /b 1
)

schtasks /run /tn "SmartMonitor" >nul 2>&1
echo [OK] Agente iniciado

echo.
echo  Instalacion completada.
echo  El equipo aparecera en SmartMonitor en unos segundos.
echo  Revisa C:\SmartMonitor\agent.log para ver el estado del bloqueo.
echo.
pause
exit /b 0

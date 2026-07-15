@echo off
chcp 65001 >nul 2>&1
title SmartMonitor v3 - Desinstalador Windows (limpieza completa)

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Ejecuta este archivo como Administrador.
    echo Clic derecho - "Ejecutar como administrador"
    pause
    exit /b 1
)

echo.
echo  SmartMonitor v3 - Desinstalando y revirtiendo todos los cambios...
echo.

REM 1) Detener y eliminar la tarea programada
schtasks /end /tn "SmartMonitor" >nul 2>&1
powershell -ExecutionPolicy Bypass -Command "Unregister-ScheduledTask -TaskName 'SmartMonitor' -Confirm:$false -ErrorAction SilentlyContinue"
echo [OK] Tarea programada eliminada

REM 2) Quitar autoinicio en el registro (por si quedo de una version vieja)
powershell -ExecutionPolicy Bypass -Command "Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'SmartMonitor' -ErrorAction SilentlyContinue"
echo [OK] Clave de autoinicio eliminada

REM 3) Matar cualquier proceso del agente que quede vivo (reintenta 3 veces)
powershell -ExecutionPolicy Bypass -Command "for ($i = 0; $i -lt 3; $i++) { $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*smartmonitor-push.ps1*' }; if (-not $procs) { break }; $procs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }; Start-Sleep -Milliseconds 500 }; $left = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*smartmonitor-push.ps1*' }; if ($left) { Write-Host '[WARN] Sigue vivo un proceso del agente (PID' $left.ProcessId ') - revisa manualmente' } else { Write-Host '[OK] Procesos del agente detenidos' }"

REM 4) Restaurar el DNS automatico (DHCP) y reactivar IPv6 (si el agente lo habia deshabilitado para bloquear) en todos los adaptadores activos
powershell -ExecutionPolicy Bypass -Command "$adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }; foreach ($a in $adapters) { try { Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue } catch {}; try { $b = Get-NetAdapterBinding -InterfaceIndex $a.InterfaceIndex -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue; if ($b -and -not $b.Enabled) { Enable-NetAdapterBinding -InterfaceIndex $a.InterfaceIndex -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue } } catch {} }; ipconfig /flushdns | Out-Null"
echo [OK] DNS de los adaptadores de red restaurado a automatico (DHCP)

REM 5) Quitar el certificado de la CA de SmartMonitor del almacen de confianza
powershell -ExecutionPolicy Bypass -Command "Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like '*SmartMonitor Root CA*' } | Remove-Item -Force -ErrorAction SilentlyContinue"
echo [OK] Certificado de la CA eliminado del almacen de confianza

REM 6) Revertir las politicas de DoH ("Secure DNS") en Chrome/Edge/Brave
powershell -ExecutionPolicy Bypass -Command "foreach ($p in @('Google\Chrome','Microsoft\Edge','BraveSoftware\Brave')) { Remove-Item -Path ('HKLM:\Software\Policies\' + $p) -Recurse -Force -ErrorAction SilentlyContinue }"
echo [OK] Politicas de DNS-over-HTTPS de Chrome/Edge/Brave revertidas

REM 7) Quitar la politica de DoH de Firefox (policies.json)
powershell -ExecutionPolicy Bypass -Command "$ff = Join-Path ${env:ProgramFiles} 'Mozilla Firefox'; $pol = Join-Path $ff 'distribution\policies.json'; if (Test-Path $pol) { Remove-Item -Path $pol -Force -ErrorAction SilentlyContinue }"
echo [OK] Politica de DNS-over-HTTPS de Firefox eliminada (si existia)

REM 8) Quitar las reglas de firewall que bloqueaban los endpoints de DoH publicos
REM (sin comillas en name= : el valor no tiene espacios, asi se evita anidar
REM comillas de PowerShell dentro del argumento -Command de cmd.exe)
powershell -ExecutionPolicy Bypass -Command "foreach ($ep in @('1.1.1.1','1.0.0.1','8.8.8.8','8.8.4.4','9.9.9.9','149.112.112.112')) { netsh advfirewall firewall delete rule name=SM_BlockDoH_$ep | Out-Null }"
echo [OK] Reglas de firewall de bloqueo de DoH eliminadas

REM 9) Restaurar la politica de ejecucion de PowerShell al valor por defecto de Windows
powershell -Command "Set-ExecutionPolicy Restricted -Scope LocalMachine -Force" >nul 2>&1
echo [OK] Politica de ejecucion de PowerShell restaurada (Restricted)

REM 10) Borrar la carpeta de instalacion (script, log, cache de software, cert descargado)
attrib -H "C:\SmartMonitor" >nul 2>&1
if exist "C:\SmartMonitor" (
    rd /s /q "C:\SmartMonitor" >nul 2>&1
)
if exist "C:\SmartMonitor" (
    echo [WARN] No se pudo borrar C:\SmartMonitor por completo - revisa manualmente si algun archivo sigue en uso
) else (
    echo [OK] Carpeta C:\SmartMonitor eliminada
)

echo.
echo  Desinstalacion completada. El equipo deberia quedar como antes de instalar el agente.
echo  Si segundos despues sigues viendo el equipo en el panel de SmartMonitor, es normal:
echo  el servidor lo marcara offline solo tras dejar de recibir reportes (no hace falta
echo  borrarlo ahi tambien, salvo que quieras limpiar el historial manualmente).
echo.
pause
exit /b 0

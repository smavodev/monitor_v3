# SmartMonitor v3 - Agente Windows (loop continuo, modo DNS centralizado)
$SERVER       = "http://__SMARTMONITOR_SERVER_IP__:8000"
$HOSTNAME_PC  = $env:COMPUTERNAME
$SW_HASH_FILE = "C:\SmartMonitor\.sw_hash"
$LOG_FILE     = "C:\SmartMonitor\agent.log"
$INTERVAL     = 60
$TAILSCALE_EXE = "C:\Program Files\Tailscale\tailscale.exe"
# IP unica del equipo dentro del tunel WireGuard (Headscale), si esta
# conectado. Null hasta que Setup-WireguardTunnel lo resuelva. Se manda en
# cada Send-Metrics para que dns_blocker.py identifique a este equipo sin
# depender de la IP publica compartida de la oficina.
$script:TailnetIp       = $null
$script:TailnetServerIp = $null

function Write-Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg"
    Write-Host $line
    try {
        $dir = Split-Path $LOG_FILE -Parent
        if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LOG_FILE -Value $line -Encoding UTF8 -Force
    } catch {}
}

Write-Log "=== SmartMonitor iniciando (usuario: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)) ==="
# Server y hostname bien visibles en la primera linea del log: si el agente
# alguna vez queda apuntando al servidor equivocado (ej. una reinstalacion que
# no reemplazo el archivo de verdad, como paso una vez), esto lo delata de
# inmediato sin tener que diagnosticar por SSH cuanto trafico llega a cada server.
Write-Log "Servidor configurado: $SERVER | Hostname: $HOSTNAME_PC"

# Esperar a que la red este lista al arrancar como servicio. Se prueba con
# una conexion TCP real al puerto del server (no ping/ICMP): el security
# group de EC2 no tiene abierto ICMP, asi que un ping siempre falla y esta
# espera se comia los 60s completos en CADA arranque sin aportar nada.
$maxWait   = 60
$waited    = 0
$serverIp  = ($SERVER -replace '^https?://' -replace ':.*$', '')
Write-Log "Esperando red..."
while ($waited -lt $maxWait) {
    $ok = $false
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($serverIp, 8000, $null, $null)
        $ok  = $iar.AsyncWaitHandle.WaitOne(2000) -and $tcp.Connected
        $tcp.Close()
    } catch { $ok = $false }
    if ($ok) {
        Write-Log "Red lista tras ${waited}s"
        break
    }
    Start-Sleep -Seconds 5
    $waited += 5
}
if ($waited -ge $maxWait) { Write-Log "WARN: Red no disponible tras ${maxWait}s - continuando" }

function Get-CpuPercent {
    try {
        $load = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
        return [math]::Round($load, 1)
    } catch { return 0.0 }
}

function Get-MemInfo {
    $os      = Get-CimInstance Win32_OperatingSystem
    $totalMB = [math]::Round($os.TotalVisibleMemorySize / 1024, 0)
    $freeMB  = [math]::Round($os.FreePhysicalMemory / 1024, 0)
    $usedMB  = $totalMB - $freeMB
    return @{
        percent  = [math]::Round($usedMB / $totalMB * 100, 1)
        total_gb = [math]::Round($totalMB / 1024, 1)
        used_gb  = [math]::Round($usedMB / 1024, 2)
    }
}

function Get-DiskInfo {
    $disks = @()
    Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null } | ForEach-Object {
        $total = [math]::Round(($_.Used + $_.Free) / 1GB, 1)
        $used  = [math]::Round($_.Used / 1GB, 1)
        $pct   = if ($total -gt 0) { [math]::Round($used / $total * 100, 1) } else { 0 }
        if ($total -gt 0.1) {
            $disks += @{ device=$_.Name; mountpoint=$_.Root; total_gb=$total; used_gb=$used; percent=$pct }
        }
    }
    return $disks
}

function Get-TopProcesses($totalRamGB) {
    return @(Get-Process |
        Where-Object { $_.CPU -ne $null } |
        Group-Object Name |
        ForEach-Object {
            $cpu = [math]::Round(($_.Group | Measure-Object CPU -Sum).Sum, 1)
            $mem = [math]::Round(($_.Group | Measure-Object WorkingSet64 -Sum).Sum / 1MB, 0)
            $memPct = if ($totalRamGB -gt 0) { [math]::Round($mem / ($totalRamGB * 1024) * 100, 1) } else { 0 }
            @{ name=$_.Name; cpu=$cpu; mem=$memPct }
        } |
        Sort-Object { -$_.cpu } |
        Select-Object -First 100)
}

function Get-InstalledSoftware {
    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $seen = @{}; $sw = @()
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Get-ItemProperty $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and $_.DisplayName -notmatch '^\s*$' } |
                ForEach-Object {
                    $key = $_.DisplayName.Trim()
                    if (-not $seen[$key]) {
                        $seen[$key] = $true
                        $sw += @{ name=$key; version=($_.DisplayVersion -replace '^\s+|\s+$','') }
                    }
                }
        }
    }
    return $sw | Sort-Object { $_.name.ToLower() }
}

# ── Bloqueo centralizado (Fase 1 + 2) ────────────────────────────────────────
# El agente NO hace sinkhole/hosts local: apunta el DNS de TODAS las interfaces
# activas al server, que aplica la blocklist centralmente (dns_blocker.py) y
# redirige los dominios bloqueados a la pagina de bloqueo. Para vencer DoH se
# desactiva el "Secure DNS" del navegador y se bloquean los endpoints DoH.

function Get-WifiSSID {
    # Importante: Windows suele nombrar el perfil de conexion con un sufijo
    # " 2"/" 3" cuando hay perfiles duplicados, asi que el campo 'Profile' NO es
    # el SSID real (este equipo lo reportaba como "Nuzzle 2" siendo "Nuzzle").
    # Por eso priorizamos el SSID real y solo usamos el nombre de perfil como
    # ultimo recurso, quitandole el sufijo numerico.
    # 1) netsh: campo 'SSID' (SSID real; puede venir vacio en W11 sin ubicacion)
    try {
        $out = netsh wlan show interfaces 2>$null
        foreach ($line in $out) {
            if ($line -match '^\s*SSID\s*:\s*(.+)$' -and $line -notmatch 'BSSID') {
                $v = $matches[1].Trim()
                if ($v) { return $v }
            }
        }
    } catch {}
    # 2) WMI NDIS: SSID real leido directamente del driver (sin ubicacion)
    try {
        $wmi = Get-CimInstance -Namespace 'root/wmi' -ClassName 'MSNdis_80211_ServiceSetIdentifier' -ErrorAction SilentlyContinue
        foreach ($w in $wmi) {
            $bytes = $w.Ndis80211SsId
            if ($bytes -and $bytes.Count -gt 0) {
                $s = -join ($bytes | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } })
                if ($s.Trim()) { return $s.Trim() }
            }
        }
    } catch {}
    # 3) netsh: campo 'Profile' (nombre del perfil; quitar sufijo " 2"/" 3")
    try {
        $out = netsh wlan show interfaces 2>$null
        foreach ($line in $out) {
            if ($line -match '^\s*Profile\s*:\s*(.+)$') {
                $v = $matches[1].Trim() -replace '\s+\d+$', ''
                if ($v) { return $v }
            }
        }
    } catch {}
    # 4) Perfil de conexion (ultimo recurso; tambien quitar sufijo)
    try {
        $cp = Get-NetConnectionProfile -ErrorAction SilentlyContinue
        $wifi = @($cp | Where-Object { $_.InterfaceAlias -match 'wi' })
        foreach ($p in @($wifi + $cp)) {
            if ($p.Name -and $p.Name.Trim()) { return $p.Name.Trim() -replace '\s+\d+$', '' }
        }
    } catch {}
    return $null
}

function Get-BlockList {
    try {
        $ssid = Get-WifiSSID
        $ssidParam = if ($ssid) { [uri]::EscapeDataString($ssid) } else { "" }
        # El hostname de Windows puede repetirse entre equipos distintos
        # (clonación, error humano); mandar el serial deja que el server
        # identifique a este equipo sin ambigüedad si hay otro con el mismo
        # nombre (ver receive_metrics/get_blocklist en el server).
        $serialParam = if ($hw -and $hw.serial_number) { [uri]::EscapeDataString($hw.serial_number) } else { "" }
        Write-Log "BLOCKLIST consultando (hostname=$HOSTNAME_PC ssid='$ssid')"
        $r = Invoke-RestMethod -Uri "$SERVER/api/agents/blocklist?hostname=$HOSTNAME_PC&ssid=$ssidParam&serial=$serialParam" -Method GET -TimeoutSec 5
        $allDomains = @($r.all_domains)
        $shouldBlock = [bool]($r.should_block -ne $false)
        return @{ AllDomains = $allDomains; ShouldBlock = $shouldBlock }
    } catch { Write-Log "BLOCKLIST ERROR consultando: $_"; return $null }
}

function Get-ServerDnsIp {
    # Si el tunel WireGuard esta activo, el DNS se apunta a la IP del server
    # DENTRO del tunel (unica de verdad) en vez de la IP publica compartida
    # de la oficina - asi dns_blocker.py identifica a este equipo sin
    # ambiguedad. Si el tunel no esta disponible, se cae al comportamiento
    # de siempre (IP publica) sin que el bloqueo deje de funcionar.
    if ($script:TailnetIp -and $script:TailnetServerIp) {
        return $script:TailnetServerIp
    }
    try {
        return ($SERVER -replace '^https?://' -replace ':.*$', '')
    } catch { return $SERVER }
}

function Get-TailscaleIp {
    try {
        if (-not (Test-Path $TAILSCALE_EXE)) { return $null }
        $ip = & $TAILSCALE_EXE ip -4 2>$null
        if ($LASTEXITCODE -eq 0 -and $ip) { return $ip.Trim() }
    } catch {}
    return $null
}

function Setup-WireguardTunnel {
    # Registra este equipo en el tunel WireGuard (Headscale) si todavia no lo
    # esta. No es indispensable para que el agente funcione: si esto falla o
    # el cliente Tailscale no esta instalado, el bloqueo sigue funcionando
    # igual que siempre por la IP publica (ver Get-ServerDnsIp).
    try {
        if (-not (Test-Path $TAILSCALE_EXE)) {
            Write-Log "WireGuard: cliente Tailscale no instalado, se omite"
            return
        }
        $existingIp = Get-TailscaleIp
        if ($existingIp) {
            $script:TailnetIp = $existingIp
            if (-not $script:TailnetServerIp) {
                try {
                    $reg = Invoke-RestMethod -Uri "$SERVER/api/agents/wireguard/preauthkey" -Method POST -Body (@{ hostname = $HOSTNAME_PC } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 10
                    $script:TailnetServerIp = $reg.server_tailnet_ip
                } catch {}
            }
            return
        }
        Write-Log "WireGuard: sin conectar, pidiendo pre-auth key al servidor..."
        $reg = Invoke-RestMethod -Uri "$SERVER/api/agents/wireguard/preauthkey" -Method POST -Body (@{ hostname = $HOSTNAME_PC } | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 10
        $script:TailnetServerIp = $reg.server_tailnet_ip
        & $TAILSCALE_EXE up --login-server=$($reg.login_server) --authkey=$($reg.authkey) --hostname=$HOSTNAME_PC --accept-dns=false --timeout=30s 2>&1 | Out-Null
        Start-Sleep -Seconds 3
        $script:TailnetIp = Get-TailscaleIp
        if ($script:TailnetIp) {
            Write-Log "WireGuard: conectado, IP=$($script:TailnetIp) (server=$($script:TailnetServerIp))"
        } else {
            Write-Log "WARN: WireGuard no conecto (reintenta solo)"
        }
    } catch {
        Write-Log "WARN: no se pudo configurar WireGuard: $_"
    }
}

function Set-CentralDns {
    try {
        $ip = Get-ServerDnsIp
        # Aplicar el DNS del server a TODAS las interfaces activas, igual que
        # 'resolvectl dns *' en Linux. Si solo lo ponemos en la interfaz de la
        # ruta por defecto, Windows (resolucion multi-homed) manda consultas por
        # otra interfaz con su DNS de DHCP y esquiva el filtro -> no bloquea.
        $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
        if ($adapters.Count -eq 0) {
            # Fallback a la ruta por defecto si no hay ninguna 'Up' detectable
            $idx = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
                     Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex
            if ($idx) { Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $ip }
        } else {
            foreach ($a in $adapters) {
                try { Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ServerAddresses $ip -ErrorAction SilentlyContinue } catch {}
            }
        }
        & ipconfig /flushdns | Out-Null
    } catch { Write-Log "WARN: no se pudo apuntar el DNS al server: $_" }
}

function Restore-Dns {
    try {
        $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
        if ($adapters.Count -eq 0) {
            $idx = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
                     Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex
            if ($idx) { Set-DnsClientServerAddress -InterfaceIndex $idx -ResetServerAddresses }
        } else {
            foreach ($a in $adapters) {
                try { Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue } catch {}
            }
        }
        & ipconfig /flushdns | Out-Null
    } catch {}
}

# Fase 2: cerrar la via de DoH para que el DNS central sea efectivo
$DoHEndpoints = @("1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4","9.9.9.9","149.112.112.112")

function Disable-BrowserDoH {
    try {
        foreach ($p in @("Google\Chrome","Microsoft\Edge","BraveSoftware\Brave")) {
            $k = "HKLM:\Software\Policies\$p"
            if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
            Set-ItemProperty -Path $k -Name "DnsOverHttpsMode" -Value "off" -Type String -Force
        }
        $ff = Join-Path ${env:ProgramFiles} "Mozilla Firefox"
        if (Test-Path $ff) {
            $pol = Join-Path $ff "distribution\policies.json"
            New-Item -Path (Split-Path $pol) -Force | Out-Null
            # ImportEnterpriseRoots: Firefox usa su propio almacen de certificados
            # (NSS) y por defecto ignora el de Windows. Sin esto, aunque la CA de
            # SmartMonitor este instalada en Cert:\LocalMachine\Root, Firefox
            # seguiria mostrando advertencia de certificado en la pagina de bloqueo.
            Set-Content -Path $pol -Value '{"policies":{"DNSOverHTTPS":{"Enabled":false,"Locked":true},"ImportEnterpriseRoots":true}}' -Force
        }
    } catch { Write-Log "WARN: no se pudo desactivar DoH del navegador: $_" }
}

function Block-DoHEndpoints {
    try {
        foreach ($ep in $DoHEndpoints) {
            $name = "SM_BlockDoH_$ep"
            netsh advfirewall firewall delete rule name="$name" | Out-Null
            netsh advfirewall firewall add rule name="$name" dir=out action=block remoteip="$ep" | Out-Null
        }
    } catch { Write-Log "WARN: no se pudo bloquear endpoints DoH: $_" }
}

function Send-Metrics($hw, $ram, $swToSend) {
    $mem      = Get-MemInfo
    $cpu      = Get-CpuPercent
    $disks    = Get-DiskInfo
    $procs    = Get-TopProcesses $mem.total_gb
    $mainDisk = $disks | Sort-Object { -$_.total_gb } | Select-Object -First 1
    $diskPct  = if ($mainDisk) { $mainDisk.percent } else { 0 }

    $payload = [ordered]@{
        hostname           = $HOSTNAME_PC
        os                 = "windows"
        os_version         = $hw.os_version
        manufacturer       = $hw.manufacturer
        model              = $hw.model
        serial_number      = $hw.serial_number
        cpu_model          = $hw.cpu_model
        cpu_cores          = $hw.cpu_cores
        ram_slots_total    = $ram.total
        ram_slots_used     = $ram.used
        ram_total_gb       = $mem.total_gb
        cpu_percent        = $cpu
        ram_percent        = $mem.percent
        ram_used_gb        = $mem.used_gb
        disk_percent       = $diskPct
        net_rx_mb          = 0
        net_tx_mb          = 0
        cpu_temp           = $null
        latency_ms         = $null
        disks              = @($disks)
        top_processes      = @($procs)
        ram_slots_detail   = @($ram.detail)
        installed_software = @($swToSend)
        tailnet_ip         = $script:TailnetIp
    }

    $body = $payload | ConvertTo-Json -Depth 5 -Compress
    # Invoke-RestMethod con -Body como string usa la codificacion por defecto
    # del sistema (no UTF-8) para pasar a bytes, sin importar el -ContentType
    # declarado — si algun nombre de software instalado (u otro campo) trae
    # tildes/simbolos, el body llega corrupto y el server responde 400 "There
    # was an error parsing the body". Se fuerza UTF-8 explicitamente.
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    Invoke-RestMethod -Uri "$SERVER/api/agents/metrics" `
        -Method POST -Body $bodyBytes -ContentType "application/json; charset=utf-8" | Out-Null
}

# Recopilar hardware una sola vez (con proteccion ante errores de arranque)
Write-Log "Recopilando hardware..."
try {
    $cs  = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $bio = Get-CimInstance Win32_BIOS
    $os  = Get-CimInstance Win32_OperatingSystem
    $hw  = @{
        manufacturer  = $cs.Manufacturer
        model         = $cs.Model
        serial_number = $bio.SerialNumber
        cpu_model     = $cpu.Name.Trim()
        cpu_cores     = [int]$cpu.NumberOfCores
        os_version    = $os.Version
    }
    $array = Get-CimInstance Win32_PhysicalMemoryArray -ErrorAction SilentlyContinue | Select-Object -First 1
    $total = if ($array) { [int]$array.MemoryDevices } else { 0 }
    $slots = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | ForEach-Object {
        $t = switch ([int]$_.MemoryType) { 24{"DDR3"} 26{"DDR4"} 34{"DDR5"} default{"DDR"} }
        @{ slot=$_.DeviceLocator; size_gb=[math]::Round($_.Capacity/1GB,0); type=$t
           speed=if($_.Speed){"$($_.Speed) MT/s"}else{""}
           manufacturer=($_.Manufacturer -replace '^\s+|\s+$','')
           part_number=($_.PartNumber -replace '^\s+|\s+$',''); installed=$true }
    })
    $ram = @{ used=$slots.Count; total=if($total -gt 0){$total}else{$slots.Count}; detail=$slots }
    Write-Log "Hardware OK - $($hw.cpu_model)"
} catch {
    Write-Log "ERROR recopilando hardware: $_"
    $hw  = @{ manufacturer=""; model=""; serial_number=""; cpu_model=""; cpu_cores=0; os_version="" }
    $ram = @{ used=0; total=0; detail=@() }
}

# Fase 2: cerrar la via de DoH para que el DNS central sea efectivo
Disable-BrowserDoH
Block-DoHEndpoints

# Intento inicial de conectar el tunel WireGuard (no bloqueante: si falla,
# el agente sigue funcionando por IP publica igual que siempre)
Setup-WireguardTunnel

# Loop principal
# El bloqueo (dominios/excepciones/horario/red) se revisa cada BLOCKLIST_POLL_SEC,
# independiente del intervalo de métricas — así una excepción que agregas o
# quitas no depende del intervalo de métricas (que puede ser mucho más largo).
# Configurable desde el servidor (Configuración -> "Bloqueo cada"), con piso
# de 1 minuto pensado para producción a escala (cientos de equipos). El valor
# de aca abajo es solo el respaldo por si el servidor no responde todavia -
# se pide el real de inmediato despues, sin esperar al primer ciclo del loop.
$BLOCKLIST_POLL_SEC = 60

# Pide los intervalos reales al servidor ya desde el arranque, en vez de
# esperar al primer ciclo del loop para corregir los valores de respaldo
# ($INTERVAL de la linea 6, $BLOCKLIST_POLL_SEC de arriba) - si el server no
# responde todavia (red lenta al iniciar), se quedan esos respaldos hasta el
# primer ciclo exitoso, sin romper nada.
try {
    $cfg = Invoke-RestMethod -Uri "$SERVER/api/config/interval" -Method GET -TimeoutSec 5
    $INTERVAL = [math]::Max(3, [int]$cfg.interval)
    if ($cfg.blocklist_interval) { $BLOCKLIST_POLL_SEC = [math]::Max(60, [int]$cfg.blocklist_interval) }
} catch {}
$prevSwHash = if (Test-Path $SW_HASH_FILE) { (Get-Content $SW_HASH_FILE -Raw).Trim() } else { "" }
$loopCount   = 0
$lastMetrics = [DateTime]::MinValue
$lastWireguardRetry = Get-Date

Write-Log "Loop iniciado - metricas cada ${INTERVAL}s, bloqueo cada ${BLOCKLIST_POLL_SEC}s"

while ($true) {
    try {
        if (((Get-Date) - $lastMetrics).TotalSeconds -ge $INTERVAL) {
            $swToSend      = @()
            $pendingSwHash = $null
            if ($loopCount % [math]::Max(1, [math]::Floor(300 / $INTERVAL)) -eq 0) {
                $swList = Get-InstalledSoftware
                $swJson = if ($swList.Count -gt 0) { $swList | ConvertTo-Json -Depth 3 -Compress } else { '[]' }
                $swHash = ([System.BitConverter]::ToString(
                    [System.Security.Cryptography.MD5]::Create().ComputeHash(
                        [System.Text.Encoding]::UTF8.GetBytes($swJson)
                    ))).Replace('-','').ToLower()
                if ($swHash -ne $prevSwHash) {
                    $swToSend      = $swList
                    $pendingSwHash = $swHash
                }
            }

            Send-Metrics $hw $ram $swToSend

            if ($pendingSwHash) {
                $prevSwHash = $pendingSwHash
                Set-Content $SW_HASH_FILE $pendingSwHash
            }

            try {
                $cfg      = Invoke-RestMethod -Uri "$SERVER/api/config/interval" -Method GET -TimeoutSec 3
                $INTERVAL = [math]::Max(3, [int]$cfg.interval)
                # El intervalo de revision de bloqueo tambien lo maneja el
                # server (Configuracion -> "Bloqueo cada") - se refresca con
                # la misma cadencia que el de metricas, sin llamada aparte.
                if ($cfg.blocklist_interval) {
                    $BLOCKLIST_POLL_SEC = [math]::Max(60, [int]$cfg.blocklist_interval)
                }
            } catch {}

            $lastMetrics = Get-Date
            $loopCount++
        }

        # Se revalida en CADA ciclo si el tunel sigue realmente vivo (no solo
        # una vez al conectar): si Tailscale se cae despues de haber estado
        # conectado, $script:TailnetIp quedaba en un valor viejo para
        # siempre, y el agente seguia apuntando el DNS a una IP del tunel que
        # ya no respondia -> Windows terminaba usando otro DNS sin filtrar
        # (resolucion multi-homed) y el bloqueo se saltaba por completo.
        $script:TailnetIp = Get-TailscaleIp

        # Reintenta conectar el tunel WireGuard cada ~60s si todavia no lo
        # logro (ej. el servicio de Tailscale tardo en arrancar, se cayo, o
        # el server no tenia Headscale configurado en ese momento).
        if (-not $script:TailnetIp -and ((Get-Date) - $lastWireguardRetry).TotalSeconds -ge 60) {
            Setup-WireguardTunnel
            $lastWireguardRetry = Get-Date
        }

        $blockResult = Get-BlockList
        if ($null -ne $blockResult) {
            $shouldBlock = [bool]($blockResult.ShouldBlock -ne $false)
            $allDomains  = @($blockResult.AllDomains)
            Write-Log "BLOCKLIST should_block=$shouldBlock all_domains=$($allDomains.Count)"
            if ($shouldBlock -and $allDomains.Count -gt 0) {
                Set-CentralDns
                Write-Log "BLOCKLIST modo=DNS-central (el server filtra)"
            } else {
                Restore-Dns
                Write-Log "BLOCKLIST modo=off"
            }
        } else {
            Write-Log "BLOCKLIST sin respuesta del servidor (null)"
        }

        Write-Log "OK - siguiente revision de bloqueo en ${BLOCKLIST_POLL_SEC}s"
    } catch {
        Write-Log "ERROR: $_"
    }

    Start-Sleep -Seconds $BLOCKLIST_POLL_SEC
}

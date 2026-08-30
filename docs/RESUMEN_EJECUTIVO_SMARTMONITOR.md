# Resumen Ejecutivo: SmartMonitor v3 — Plataforma de Monitoreo, ITAM y Seguridad

**Cliente / Sistema:** SmartBoleta  
**Proyecto:** SmartMonitor v3  
**Fecha de Análisis:** Agosto 2026  
**Documento:** Resumen Técnico Ejecutivo y Diagnóstico de Arquitectura  

---

## 1. Visión General y Propósito del Sistema

**SmartMonitor v3** es una solución integral de **gestión de activos de TI (ITAM), monitoreo centralizado de infraestructura y control de seguridad web por DNS/TLS** diseñada específicamente para la infraestructura tecnológica de **SmartBoleta**.

La plataforma permite al departamento de TI controlar, auditar y proteger estaciones de trabajo (Windows) y servidores/equipos (Linux) desde un panel centralizado, garantizando la continuidad operativa, el inventariado de hardware y el cumplimiento de políticas de seguridad.

---

## 2. Pilares Arquitectónicos del Sistema

```
                         ┌─────────────────────────────────────────┐
                         │       Dashboard Web (Frontend SPA)      │
                         └────────────────────┬────────────────────┘
                                              │
                         ┌────────────────────▼────────────────────┐
                         │       Servidor Backend (FastAPI)        │
                         │    PostgreSQL + Docker + Headscale      │
                         └───────┬─────────────────────────┬───────┘
                                 │                         │
            ┌────────────────────▼────┐       ┌────────────▼────────────┐
            │  Servidor DNS / TLS     │       │  API REST / Telemetría  │
            │  (dns_blocker.py)       │       │  (routers / models)     │
            └────────────┬────────────┘       └────────────┬────────────┘
                         │                                 │
     ┌───────────────────┴─────────────────────────────────┴───────────────────┐
     │                                                                         │
┌────▼───────────────────────────────────┐   ┌─────────────────────────────────▼───┐
│     Agentes Cliente (Windows)          │   │      Agentes Cliente (Linux)        │
│  - smartmonitor_agent.py (Service)     │   │  - smartmonitor-push.py (Cron)      │
│  - smartmonitor_tray.py (Tray Icon)    │   │  - install-agent-linux.sh           │
│  - cloudflared.exe (DNS Local 127.0.0.1)│   │                                     │
└────────────────────────────────────────┘   └─────────────────────────────────────┘
```

### 2.1 Backend y Servidor Central (`/server/app`)

- **Tecnologías:** Python (FastAPI), SQLAlchemy ORM, PostgreSQL, Docker & Docker Compose.
- **Monitoreo & Telemetría:** Recepción periódica de métricas de CPU, RAM, almacenamiento (discos físicos y particiones), batería, red, software instalado, parches del SO, números de serie e IP pública/privada.
- **Filtro DNS y Proxy SNI/TLS (`dns_blocker.py` / `tls_ca.py`):** Servidor DNS integrado que filtra peticiones por categorías (redes sociales, ocio, contenido no permitido), por horarios (`block_schedules`) y por sedes/equipos.
- **Excepciones de Seguridad:** Gestión de códigos de pausa temporal (`AgentPauseCode`) y códigos de desinstalación segura (`AgentUninstallCode`).
- **Conectividad VPN (Headscale / Tailscale):** Integración con servidor Headscale (WireGuard) para mantener la comunicación segura con equipos fuera de la red local (`tailnet_ip`).
- **Gestión de Identidad y Accesos (IAM):** Autenticación JWT, control de acceso basado en roles por sección (`RolePermission`), políticas avanzadas de contraseñas y registro de auditoría de logins (`LoginAttempt`).

### 2.2 Agentes de Monitoreo (`/agents`)

- **Agente Windows (`smartmonitor_agent.py` + `smartmonitor_tray.py`):**
  - Proceso de servicio en segundo plano con icono en la bandeja del sistema.
  - Recolección profunda de hardware vía WMI y `psutil` (Slots de RAM, discos físicos, estado de batería, software instalado).
  - Enrutamiento de peticiones DNS a `127.0.0.1:53` mediante `cloudflared.exe`.
- **Agente Linux (`smartmonitor-push.py` + `install-agent-linux.sh`):**
  - Script optimizado para ejecución periódica en servidores o computadoras Linux mediante `cron` o `systemd`.

### 2.3 Despliegue Automatizado (`setup.sh`)

- Script de instalación de un solo comando en Linux con verificaciones automáticas:
  1. Limpieza de instalaciones previas.
  2. Verificación e instalación de Docker y Docker Compose.
  3. Despliegue de contenedores (Servidor Web en puerto 8000 / PostgreSQL).
  4. Registro automático del equipo local en el dashboard.

---

## 3. Diagnóstico Técnico: Inestabilidad y Desconexión de Wi-Fi en Redes Externas

### 3.1 Descripción del Problema

Al trasladar un equipo a una red Wi-Fi secundaria (hogar, hotspot móvil, cliente), la conexión Wi-Fi sufre desconexiones o pierde acceso a Internet, requiriendo múltiples reinicios del equipo.

### 3.2 Causas Raíz Identificadas en el Código Fuente

1. **Forzado de DNS a `127.0.0.1` (`ensure_local_dns`):**
   - El agente ejecuta comandos `netsh` asignando el DNS de la interfaz IPv4 de Windows a `127.0.0.1` (`cloudflared.exe`) y desactivando el DNS IPv6 (`address=none`).
   - Al cambiar de red Wi-Fi, la red asigna nueva IP por DHCP, pero el DNS se mantiene fijo en `127.0.0.1`. Si `cloudflared` no logra conectarse con el servidor en esa nueva red, **Windows pierde la capacidad de resolver dominios DNS**, marcando la red como "Sin Internet".

2. **Ráfaga de reconexiones VPN (Tailscale / Headscale):**
   - Al cambiar de red Wi-Fi, la IP pública cambia y la conexión con el servidor VPN se interrumpe momentáneamente.
   - En situaciones donde la reconexión entra en bucle, `cloudflared.exe` se reinicia decenas de veces por segundo. Antivirus corporativos (como Defender o Kaspersky System Watcher) interpretan esta ráfaga de subprocesos como actividad maliciosa y **deshabilitan el adaptador de red Wi-Fi por seguridad**, obligando a reiniciar el sistema.

3. **Mapeo Fijo en el Archivo `hosts` (`ensure_hosts_entry`):**
   - El agente modifica `C:\Windows\System32\drivers\etc\hosts` para forzar la IP del servidor hacia la dirección interna de la VPN WireGuard. Si los puertos UDP de la VPN están bloqueados en la red Wi-Fi externa, el tráfico queda completamente colgado.

4. **Conflicto con Router Advertisements (RA) en IPv6:**
   - En redes con IPv6 activo, los routers envían paquetes RA para asignar DNS IPv6 automáticamente. La lucha constante entre el router y el agente desactivando IPv6 provoca microdesconexiones en la pila de red NDIS/Winsock de Windows.

---

## 4. Plan de Acción y Soluciones

### 4.1 Solución Inmediata para Usuarios (Sin reiniciar el equipo)

Restablecer la configuración DNS automática del adaptador Wi-Fi vía CMD (como Administrador):

```cmd
netsh interface ipv4 set dnsservers name="Wi-Fi" source=dhcp
netsh interface ipv6 set dnsservers name="Wi-Fi" source=dhcp
ipconfig /flushdns
```

### 4.2 Solución con Códigos de Pausa

Solicitar un **Código de Pausa Temporal** desde la consola del administrador e ingresarlo en el agente tray para suspender temporalmente la redirección DNS y la VPN mientras se está en redes externas.

### 4.3 Recomendaciones de Desarrollo (Mejoras en el Agente)

1. **Implementar Fallback Automático a DHCP:** Si el agente no detecta conectividad con el servidor central tras 30 segundos de cambiar de red, restaurar temporalmente la interfaz a `source=dhcp` para garantizar la navegabilidad.
2. **Suavizar la frecuencia de supervisión de `cloudflared`:** Ajustar el tiempo de backoff exponencial en reintentos para evitar que antivirus corporativos bloqueen la tarjeta de red.
3. **Validar alcance de la VPN antes de forzar `hosts`:** Verificar la conectividad antes de sobrescribir el archivo `hosts` del sistema.

---

## 5. Resumen de Archivos Clave del Proyecto

| Archivo | Ruta | Función Principal |
| :--- | :--- | :--- |
| **`main.py`** | [server/app/main.py](../server/app/main.py) | Entrypoint del servidor FastAPI, migraciones y API REST. |
| **`dns_blocker.py`** | [server/app/dns_blocker.py](../server/app/dns_blocker.py) | Servidor DNS asíncrono y motor de filtrado web por categorías/horarios. |
| **`models.py`** | [server/app/models/models.py](../server/app/models/models.py) | Esquemas de base de datos (Agentes, Activos ITAM, Roles, Historiales). |
| **`smartmonitor_agent.py`** | [agents/windows/nuevo-por-compilar/smartmonitor_agent.py](../agents/windows/nuevo-por-compilar/smartmonitor_agent.py) | Agente Windows, telemetría WMI/psutil, gestión de `cloudflared` y DNS. |
| **`smartmonitor_tray.py`** | [agents/windows/nuevo-por-compilar/smartmonitor_tray.py](../agents/windows/nuevo-por-compilar/smartmonitor_tray.py) | Interface de usuario en la bandeja del sistema (System Tray). |
| **`smartmonitor-push.py`** | [agents/linux/smartmonitor-push.py](../agents/linux/smartmonitor-push.py) | Agente de reporte de métricas para Linux. |
| **`setup.sh`** | [setup.sh](../setup.sh) | Script de instalación y despliegue automatizado del servidor. |

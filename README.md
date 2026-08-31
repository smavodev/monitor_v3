# SmartMonitor v3 — Plataforma de Monitoreo TI, ITAM y Seguridad Web

**SmartMonitor v3** es una plataforma centralizada de **gestión de activos de TI (ITAM), monitoreo en tiempo real de infraestructura y control de seguridad web por DNS/TLS** desarrollada para la infraestructura corporativa de **SmartBoleta**.

Permite al departamento de TI supervisar estaciones de trabajo (Windows) y servidores/equipos (Linux), administrar licencias e insumos, aplicar reglas de filtrado web por categorías y horarios, y mantener conectividad VPN segura con todos los dispositivos.

---

## 🚀 Características Principales

- 📊 **Monitoreo en Tiempo Real:** Telemetría continua de uso de CPU, memoria RAM, discos físicos y particiones, salud de discos, temperatura, parches del SO y software instalado.
- 🛡️ **Seguridad y Filtro Web DNS/TLS:** Servidor DNS integrado (`dns_blocker.py`) y proxy SNI/TLS para bloqueo de contenido no permitido por categorías, horarios y sedes.
- 🔄 **Resiliencia de Red y Auto-Healing (Novedad v3):** Los agentes detectan automáticamente la conectividad con la red corporativa. Si un portátil entra a una red Wi-Fi externa (hogar/cliente), el DNS conmuta automáticamente a **DHCP** sin perder señal Wi-Fi ni requerir reinicios. Al volver a la empresa, las protecciones se reactivan solas.
- 📦 **Gestión de Inventario (ITAM):** Control de equipos monitoreados y activos no monitoreados (monitores, periféricos, licencias) con historial de entregas/devoluciones (`assignment_log`).
- 🔑 **IAM y Control de Acceso:** Roles con permisos granulares por sección, políticas de contraseñas de nivel empresarial y registro de auditoría de intentos de acceso.
- 🌐 **Integración VPN (Headscale / WireGuard):** Permite monitorear y gestionar de forma segura dispositivos fuera de la red local.

---

## 🏛️ Estructura del Proyecto (Clean Enterprise Architecture)

```text
smartmonitor3/
├── README.md                      # Documentación principal de entrada al proyecto
├── setup.sh                       # Script de despliegue automatizado del servidor Linux
├── .gitignore                     # Exclusiones globales de Git
│
├── config/                        # Configuraciones de Infraestructura
│   └── headscale/
│       └── config.yaml            # Configuración del Servidor VPN Headscale WireGuard
│
├── docs/                          # Centro de Documentación Técnica Centralizada
│   ├── README.md                  # Índice general de documentación
│   ├── GUIA_DESPLIEGUE.md         # Guía oficial de despliegue e instalación
│   ├── RESUMEN_EJECUTIVO.md       # Resumen ejecutivo de la solución
│   ├── ARQUITECTURA_RED.md        # Documentación de resiliencia Wi-Fi/DHCP & Auto-Healing
│   ├── INFORME_CAMBIOS.md         # Informe ejecutivo de la solución de desconexiones
│   └── PROPUESTA_AGENTE_V4.md     # Hoja de ruta para el agente propietario v4
│
├── server/                        # Servidor Central Backend (FastAPI) & Frontend (SPA)
│   ├── docker-compose.yml         # Orquestación de servicios (App + DB + Headscale)
│   └── app/
│       ├── Dockerfile
│       ├── main.py                # Aplicación FastAPI y ejecutor de migraciones
│       ├── dns_blocker.py         # Engine de servidor DNS asíncrono y filtrado web
│       ├── tls_ca.py              # Generador de Certificados CA para interceptación TLS
│       ├── models/                # Modelos de Base de Datos SQLAlchemy
│       ├── routers/               # Endpoints REST API (agentes, auth, assets, etc.)
│       └── static/                # Dashboard Web (Single Page Application HTML/JS)
│
└── agents/                        # Agentes Clientes por Sistema Operativo
    ├── windows/                   # Agente nativo de Windows (Python + PyInstaller + Inno Setup)
    │   ├── src/                   # Código fuente activo del Agente Windows (.exe / Servicio)
    │   │   ├── smartmonitor_agent.py          # Servicio de telemetría y resiliencia DHCP
    │   │   ├── smartmonitor_tray.py           # Icono de bandeja del sistema (System Tray)
    │   │   ├── smartmonitor_installer_helper.py# Helper de instalación y comandos
    │   │   ├── smartmonitor-agent.iss         # Script de compilación Inno Setup
    │   │   └── BUILD.md                       # Instrucciones de compilación Windows
    │   └── legacy/                # Versiones anteriores de respaldo
    └── linux/                     # Agente para Linux (Ubuntu / Debian / Distros)
        └── src/                   # Código fuente activo del Agente Linux
            ├── smartmonitor-push.py
            ├── install-agent-linux.sh
            └── uninstall-agent-linux.sh
```

---

## 🛠️ Instalación y Despliegue del Servidor

### Requisitos Previos

- Servidor Linux (Ubuntu 20.04 / 22.04 LTS recomendado) o entorno con Docker.
- Privilegios de root (`sudo`).

### Instalación Rápida (Un solo comando)

Ejecuta el script de instalación en el servidor central:

```bash
sudo bash setup.sh
```

El script instalará automáticamente Docker (si no está instalado), construirá los contenedores e iniciará los servicios.

### Acceso Inicial al Dashboard

- **URL Dashboard:** `http://<IP_DEL_SERVIDOR>:8000`
- **Usuario Admin:** `admin@smartmonitor.local`
- **Contraseña:** `Admin2024!` *(Se recomienda cambiarla tras el primer inicio)*

---

## 🖥️ Instalación de Agentes Cliente

### En Estaciones de Trabajo Windows

1. Compilar el ejecutable o copiar el instalador generado `SmartMonitor-Agent-Setup.exe` desde `agents/windows/src/dist/`.
2. Ejecutar el instalador en el equipo del usuario e ingresar la IP o Dominio del Servidor de SmartMonitor.
3. El servicio `SmartMonitorAgent` se registrará e iniciará automáticamente en Windows.

### En Equipos / Servidores Linux

Ejecuta el siguiente comando en la máquina Linux a monitorear:

```bash
sudo bash agents/linux/src/install-agent-linux.sh <IP_DEL_SERVIDOR> "NombreDelEquipo"
```

---

## ✅ Lista de Chequeo para Funcionamiento Correcto en Producción

Antes de pasar el servidor a producción, verifica los siguientes puntos clave:

- [ ] **Ajuste de Variables de Entorno en `server/docker-compose.yml`:**
  - Cambiar `SECRET_KEY` por una clave secreta aleatoria segura.
  - Asegurar que `DNS_BLOCK_REDIRECT_IP` contenga la IP pública/LAN real del servidor SmartMonitor.
  - Asegurar que `HEADSCALE_PUBLIC_URL` apunte a la IP/dominio real del puerto 8090.
- [ ] **Generación de API Key para Headscale (Si se usa la VPN):**
  - Generar una clave de API ejecutando en el servidor:

    ```bash
    docker exec -it smartmonitor-headscale headscale apikeys create
    ```

  - Copiar la clave generada a la variable `HEADSCALE_API_KEY` en `server/docker-compose.yml` y reiniciar el contenedor `docker compose restart app`.
- [ ] **Puertos del Firewall del Servidor:**
  Asegurar que los siguientes puertos estén abiertos en el firewall (UFW/iptables/Router):
  - `8000 TCP`: Dashboard Web / API REST de Agentes.
  - `53 UDP/TCP`: Servidor DNS de Filtrado Web.
  - `8090 TCP`: Servidor Headscale (VPN WireGuard).
  - `41641 UDP`: Puerto de comunicación STUN/WireGuard para la VPN.
- [ ] **Certificados SSL (Opcional pero Recomendado):**
  Para acceder al panel por HTTPS, se puede colocar un certificado Let's Encrypt en `/data/tls/fullchain.pem` y `/data/tls/privkey.pem`. El servidor habilitará automáticamente el puerto `:8443`.

---

## 📖 Documentación Técnica Adicional

Para más detalles sobre la arquitectura y funcionamiento técnico, consulta los documentos en la carpeta [`docs/`](./docs/):

- 📘 **[Guía Oficial de Despliegue e Instalación Paso a Paso](./docs/GUIA_DESPLIEGUE.md)**
- 📄 **[Resumen Ejecutivo General](./docs/RESUMEN_EJECUTIVO.md)**
- 🛡️ **[Documentación Técnica de Red, DHCP y Auto-Healing](./docs/ARQUITECTURA_RED.md)**
- 📊 **[Informe Ejecutivo de Cambios y Resiliencia](./docs/INFORME_CAMBIOS.md)**
- 💡 **[Propuesta de Arquitectura Futura: Agente Propietario v4.0](./docs/PROPUESTA_AGENTE_V4.md)**

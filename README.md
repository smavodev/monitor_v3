# SmartMonitor v3 — Plataforma de Monitoreo TI, ITAM y Seguridad Web

**SmartMonitor v3** es una plataforma centralizada de **gestión de activos de TI (ITAM), monitoreo en tiempo real de infraestructura y control de seguridad web por DNS/TLS** desarrollada para la infraestructura de **SmartBoleta**.

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

## 📁 Estructura del Proyecto

```text
smartmonitor3/
├── server/                    # Servidor Central Backend & Base de Datos
│   ├── docker-compose.yml     # Orquestación Docker (FastAPI + PostgreSQL + Headscale)
│   ├── headscale-config/      # Configuración del servidor VPN WireGuard (Headscale)
│   └── app/                   # Aplicación FastAPI
│       ├── main.py            # Entrypoint principal y ejecutor de migraciones
│       ├── dns_blocker.py     # Servidor DNS asíncrono y motor de filtrado web
│       ├── tls_ca.py          # Certificados CA dinámicos para interceptación TLS
│       ├── models/            # Esquemas de Base de Datos SQLAlchemy
│       ├── routers/           # Endpoints de API REST (agentes, auth, assets, sedes)
│       └── static/            # Dashboard Web (Single Page Application HTML/JS)
├── agents/                    # Agentes de Monitoreo Cliente
│   ├── windows/               # Agente nativo de Windows (Python + PyInstaller + Inno Setup)
│   │   └── nuevo-por-compilar/
│   │       ├── smartmonitor_agent.py   # Servicio background con Fallback a DHCP & Auto-Healing
│   │       ├── smartmonitor_tray.py    # Icono en la bandeja del sistema (System Tray)
│   │       └── smartmonitor-agent.iss  # Script de compilación del instalador .exe
│   └── linux/                 # Agente para Linux (Daemon + Bash + Python push)
│       ├── smartmonitor-push.py
│       └── install-agent-linux.sh
├── docs/                      # Documentación Técnica Oficial
│   ├── RESUMEN_EJECUTIVO_SMARTMONITOR.md
│   ├── INFORME_EJECUTIVO_CAMBIOS_OPCION_C.md
│   └── DOC_RED_DHCP_AUTOHEALING.md
└── setup.sh                   # Script de despliegue automatizado del servidor
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

1. Compilar el ejecutable o copiar el instalador generado `SmartMonitor-Agent-Setup.exe`.
2. Ejecutar el instalador en el equipo del usuario e ingresar la IP o Dominio del Servidor de SmartMonitor.
3. El servicio `SmartMonitorAgent` se registrará e iniciará automáticamente en Windows.

### En Equipos / Servidores Linux

Ejecuta el siguiente comando en la máquina Linux a monitorear:

```bash
sudo bash agents/linux/install-agent-linux.sh <IP_DEL_SERVIDOR> "NombreDelEquipo"
```

---

## ✅ Lista de Chequeo para Funcionamiento Correcto en Producción

Antes de pasar el servidor a producción, verifica los siguientes puntos clave:

- [ ] **Ajuste de Variables de Entorno en `docker-compose.yml`:**
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

Para más detalles sobre la arquitectura y funcionamiento técnico, consulta los documentos en la carpeta `docs/`:

- 📄 **[Resumen Ejecutivo General](./docs/RESUMEN_EJECUTIVO_SMARTMONITOR.md)**
- 📄 **[Informe Ejecutivo de Cambios y Resiliencia](./docs/INFORME_EJECUTIVO_CAMBIOS_OPCION_C.md)**
- 📄 **[Documentación Técnica de Red, DHCP y Auto-Healing](./docs/DOC_RED_DHCP_AUTOHEALING.md)**
- 💡 **[Propuesta de Arquitectura Futura: Agente Propietario v4.0](./docs/PROPUESTA_AGENTE_PROPIETARIO_v4.md)**

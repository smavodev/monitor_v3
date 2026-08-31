# Guía Completa de Despliegue, Compilación e Instalación: SmartMonitor v3

**Proyecto:** SmartMonitor v3  
**Cliente:** SmartBoleta  
**Fecha:** Agosto 2026  
**Documento:** Guía Oficial de Despliegue y Operación de Sistema  

---

## 1. Visión General del Despliegue

La solución **SmartMonitor v3** está compuesta por dos partes principales:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      1. SERVIDOR CENTRAL (Linux / Docker)                   │
│  - Backend REST API (FastAPI)       - Base de Datos (PostgreSQL)           │
│  - Dashboard Web (HTML5/JS SPA)     - Servidor DNS/TLS (dns_blocker.py)    │
│  - Red VPN (Headscale WireGuard)                                            │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                ┌──────────────────────┴──────────────────────┐
                │                                             │
┌───────────────▼──────────────────────┐   ┌──────────────────▼──────────────────────┐
│  2. AGENTES WINDOWS (.exe)           │   │  3. AGENTES LINUX (Daemon/Cron)         │
│  - Servicio Background (Metrics/DNS) │   │  - Reporte de Métricas / Hardware       │
│  - System Tray Icon (Control Usuario)│   │  - Instalación vía bash script          │
└──────────────────────────────────────┘   └─────────────────────────────────────────┘
```

---

## 2. Fase 1: Despliegue del Servidor Central (Backend + Frontend)

### Requisitos del Servidor

- Servidor dedicado con Linux (Ubuntu 20.04 / 22.04 LTS o Debian 11/12 recomendado).
- Privilegios de administrador (`sudo`).
- Puertos necesarios abiertos en Firewall: `8000 TCP` (Web/API), `53 UDP/TCP` (DNS), `8090 TCP` (VPN Headscale), `41641 UDP` (STUN).

### Opción A: Despliegue Automatizado (Recomendado)

Ejecuta el script oficial de instalación en la terminal del servidor:

```bash
sudo bash setup.sh
```

El script `setup.sh` realizará automáticamente:

1. Verificación e instalación de **Docker** y **Docker Compose**.
2. Creación del archivo de configuración sensible `server/.env` a partir de `server/.env.example` (si no existe).
3. Creación de volúmenes persistentes (`db_data`, `headscale_data`, `app_data`).
4. Compilación de imágenes Docker y arranque de servicios.
5. Verificación de salud de la base de datos PostgreSQL.

### Opción B: Despliegue Manual con Docker Compose

```bash
cd server

# Copiar la plantilla de configuración sensible
cp .env.example .env

# Modificar datos sensibles como contraseñas y claves secretas
nano .env

# Levantar contenedores
docker compose build
docker compose up -d
```

### Verificación del Servidor

Accede desde el navegador a la URL:

- **URL:** `http://<IP_DEL_SERVIDOR>:8000`
- **Usuario Inicial:** `admin@smartmonitor.local`
- **Contraseña Inicial:** `Admin2024!`

---

## 3. Fase 2: Compilación del Instalador para Windows (`.exe`)

Para generar el instalador distribuible `SmartMonitor-Agent-Setup.exe` para las estaciones de trabajo de los usuarios:

### Requisitos en la Máquina de Compilación (Windows)

- Computadora con Windows 10/11 (o VM Windows).
- **Python 3.10+** instalado.
- **Inno Setup 6+** instalado (Descargar de [jrsoftware.org](https://jrsoftware.org/isinfo.php)).

### Pasos de Compilación

#### Paso 1: Instalar dependencias en Python

Abre CMD como Administrador e instala PyInstaller:

```cmd
pip install pyinstaller pywin32
```

#### Paso 2: Posicionarse en el directorio de código fuente del agente

```cmd
cd agents\windows\src
```

#### Paso 3: Compilar los 3 binarios del agente

Ejecuta los siguientes comandos:

1. **Compilar el Agente Principal (Servicio nativo `SmartMonitorAgent`):**

   ```cmd
   pyinstaller --onedir --noconsole --name smartmonitor-agent --icon icon.ico --add-data "cloudflared.exe;." --hidden-import win32timezone --hidden-import win32serviceutil --hidden-import win32service --hidden-import win32event --hidden-import servicemanager --collect-submodules win32com smartmonitor_agent.py
   ```

2. **Compilar el Helper de Instalación / Desinstalación:**

   ```cmd
   pyinstaller --onedir --name smartmonitor-installer-helper --icon icon.ico --hidden-import win32timezone --collect-submodules win32com smartmonitor_installer_helper.py
   ```

3. **Compilar el Icono de Bandeja (Tray Icon para el Usuario):**

   ```cmd
   pyinstaller --onedir --noconsole --name smartmonitor-tray --icon icon.ico --hidden-import win32timezone --collect-submodules win32com smartmonitor_tray.py
   ```

#### Paso 4: Empaquetar con Inno Setup

Ejecuta el compilador de Inno Setup:

```cmd
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" smartmonitor-agent.iss
```

👉 **Resultado:** El paquete final **`SmartMonitor-Agent-Setup.exe`** quedará generado en la carpeta `dist/`.

---

## 4. Fase 3: Instalación de Agentes Cliente en Equipos

### A. Instalación en Equipos Windows

1. Copia el instalador `SmartMonitor-Agent-Setup.exe` a la computadora cliente.
2. Ejecuta el archivo e ingresa la IP o Dominio del Servidor (ejemplo: `http://192.168.1.50:8000`).
3. El instalador se encargará automáticamente de:
   - Registrar e iniciar el servicio nativo `SmartMonitorAgent`.
   - Instalar el certificado CA local para filtrado TLS.
   - Iniciar el Tray Icon en la sesión de usuario.

> 💡 **Despliegue Desatendido / Silencioso:**  
> Para instalar sin mostrar ventanas de interfaz:
>
> ```cmd
> SmartMonitor-Agent-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES
> ```
>
> 🔄 **Actualización de Equipos Existentes:**  
> Para actualizar una versión previa, simplemente ejecuta el nuevo `SmartMonitor-Agent-Setup.exe` encima. No es necesario desinstalar la versión anterior; el instalador detendrá el servicio, actualizará los binarios y reactivará el servicio automáticamente.

### B. Instalación en Equipos / Servidores Linux

Ejecuta en la terminal de la máquina Linux:

```bash
sudo bash agents/linux/src/install-agent-linux.sh <IP_DEL_SERVIDOR> "NombreDelEquipo"
```

---

## 5. Fase 4: Operación Diaria y Lista de Chequeo de Producción

### 1. Panel de Control Web

Accede a `http://<IP_DEL_SERVIDOR>:8000`:

- **Dashboard:** Estado online/offline de equipos, métricas de CPU, RAM, temperatura y almacenamiento.
- **Seguridad Web:** Gestión de categorías de bloqueo, dominios específicos y horarios de acceso.
- **ITAM / Inventario:** Asignación de equipos a usuarios, inventariado de insumos y registro de entregas/devoluciones.
- **Códigos de Pausa:** Generación de códigos PIN temporales para permitir pausas autorizadas en clientes.

### 2. Checklist de Producción y Seguridad

Antes de entregar el sistema a producción y subir el código al repositorio Git:

- [ ] **Configuración de Variables Sensibles (`.env`):**
  - Asegurar que `.env` esté en `.gitignore` (para no subir contraseñas a Git).
  - Cambiar la clave de usuario administrador (`ADMIN_PASSWORD`).
  - Cambiar la contraseña de PostgreSQL (`POSTGRES_PASSWORD`).
  - Cambiar la clave secreta `SECRET_KEY` por una cadena aleatoria fuerte.
  - Ajustar `DNS_BLOCK_REDIRECT_IP` y `HEADSCALE_PUBLIC_URL` a la IP real del servidor.
- [ ] **VPN Headscale / WireGuard:**
  - **Generar `HEADSCALE_API_KEY`:** Ejecutar en el servidor:

    ```bash
    docker exec -it smartmonitor-headscale headscale apikeys create
    ```

    *Copiar la clave devuelta e ingresarla en `server/.env`.*
  - **Consultar / Crear `HEADSCALE_USER_ID`:** Para ver los usuarios creados en Headscale:

    ```bash
    docker exec -it smartmonitor-headscale headscale users list
    ```

    *Si se requiere crear un usuario nuevo:*

    ```bash
    docker exec -it smartmonitor-headscale headscale users create smartmonitor
    ```

- [ ] **Firewall:**
  - Verificar que los puertos `8000` (Web/API), `53` (DNS), `8090` (Headscale) y `41641` (STUN WireGuard) estén abiertos en el firewall del servidor.

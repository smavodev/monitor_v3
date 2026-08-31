# Propuesta de Arquitectura Futura: Agente 100% Propietario (SmartMonitor v4)

**Proyecto:** SmartMonitor  
**Documento:** Evaluación de Viabilidad y Diseño de Agente Propietario (Sin Binarios de Terceros)  
**Estado:** 💡 Propuesta de Evolución Futura (SmartMonitor v4.0)  

---

## 1. Motivación y Objetivo

Actualmente, el agente cliente de Windows de **SmartMonitor v3** depende de dos ejecutables externos de terceros:

1. **`cloudflared.exe` (68 MB):** Utilizado como proxy DNS-over-HTTPS (DoH) local en `127.0.0.1:53`.
2. **`tailscale.exe` (cliente VPN):** Utilizado para establecer túneles de red WireGuard hacia el servidor Headscale.

### Objetivos de la Propuesta v4

- **Eliminar el 100% de los binarios externos** (`cloudflared` y `tailscale`).
- Reducir el tamaño del instalador cliente de **~110 MB a solo ~15 - 25 MB** (80% más ligero).
- Garantizar **cero falsos positivos en antivirus** (Kaspersky, Windows Defender) al no realizar ejecuciones ni lanzamientos repetidos de procesos secundarios (`netsh`, `tailscale`, `cloudflared`).
- Lograr un control **100% propietario y mantenible** del código fuente y del ciclo de vida del agente.

---

## 2. Diseño Arquitectónico Propuesto

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       AGENTE PROPIETARIO UNIFICADO                          │
│                                                                             │
│  ┌──────────────────────────────┐        ┌──────────────────────────────┐   │
│  │   Servidor DNS UDP Embebido  │        │   Cliente de Telemetría     │   │
│  │   (Escucha en 127.0.0.1:53)  │        │   y Control (HTTPS/WSS)     │   │
│  │   - Caché en memoria (TTL)   │        │   - Recolección WMI/psutil   │   │
│  │   - Evaluación local / REST  │        │   - Tokens / SSL Cert        │   │
│  └──────────────┬───────────────┘        └──────────────┬───────────────┘   │
└─────────────────┼──────────────────────────────────────┼────────────────────┘
                  │                                      │
                  │ (Consultas DNS / Reglas)             │ (Métricas / Heartbeat)
                  ▼                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SERVIDOR CENTRAL (SmartMonitor API)                      │
│                  - Endpoint HTTPS REST / WebSockets                         │
│                  - Engine de Filtrado DNS / Reglas / Sedes                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Componente 1: Servidor DNS UDP Embebido (Reemplazo de `cloudflared`)

- El agente incluye un socket UDP liviano escuchando en `127.0.0.1:53` dentro del mismo proceso del Servicio de Windows.
- **Funcionamiento:**
  - Mantiene un caché en memoria RAM con TTL (ej. 300 segundos) para resolver peticiones locales en < 2ms.
  - Para dominios permitidos, resuelve hacia los servidores DNS públicos (ej. `8.8.8.8` o DNS asignado por la red).
  - Para dominios bloqueados según la política corporativa, responde con la IP de redirección de bloqueo (`DNS_BLOCK_REDIRECT_IP`).
- **Beneficio:** Elimina el ejecutable `cloudflared.exe` de 68 MB y todas las invocaciones a subprocesos externos.

### Componente 2: Comunicación Directa HTTPS / WebSockets (Reemplazo de `tailscale`)

- La comunicación de métricas y sincronización de reglas se realiza directamente sobre **HTTPS estándar cifrado** (puerto 443 / 8000) usando autenticación por Token de Dispositivo o Certificado de Cliente (mTLS).
- **Beneficio:** Elimina la necesidad de instalar el cliente de VPN Tailscale y la sobrecarga de adaptadores virtuales TAP/TUN en los clientes.

---

## 3. Matriz Comparativa de Viabilidad

| Criterio | Arquitectura v3 Actual (Híbrida) | Propuesta v4 (100% Propietaria) |
| :--- | :--- | :--- |
| **Binarios de Terceros** | `cloudflared.exe` + `tailscale.exe` | **Ninguno (0 MB)** |
| **Tamaño del Instalador** | ~110 MB - 120 MB | **~15 MB - 25 MB** |
| **Instalación y Despliegue** | Complejo (Servicios extra + VPN) | **Ultra-rápido (1 ejecutable nativo)** |
| **Compatibilidad Antivirus** | Vulnerable a heurística de subprocesos | **Máxima compatibilidad (Sin subprocesos externos)** |
| **Control del Código** | Parcial (Sujeto a cambios de Cloudflare) | **Total (Código de la empresa 100%)** |
| **Consumo de Recursos** | ~120 MB RAM / Subprocesos activos | **< 30 MB RAM / 1 solo proceso** |

---

## 4. Requisitos y Factores a Considerar para la Implementación

1. **Lenguaje de Compilación del Agente:**
   - **Opción A (Python empaquetado con PyInstaller / Nuitka):** Mantiene la base de código actual en Python, agregando una librería ligera de DNS asíncrono (`dnspython` o `asyncio`).
   - **Opción B (Go / Golang):** Permite compilar a un ejecutable nativo estático de ~10 MB, con manejo impecable de concurrencia para DNS y cero dependencias de Python.
2. **Firma Digital (Code Signing Certificate):**
   - Se recomienda firmar el `.exe` compilado con un certificado de firma de código de la empresa para evitar advertencias de *SmartScreen* de Windows.
3. **Caché e Idempotencia:**
   - Diseñar el caché DNS en memoria con expiración suave para no depender de llamadas constantes a la API central en cada petición web.

---

## 5. Conclusión y Siguiente Paso

La transición a un **Agente 100% Propietario (SmartMonitor v4)** es técnicamente viable con un índice de factibilidad del **9.5/10**.

Se recomienda mantener esta documentación como **Hoja de Ruta (Roadmap) tecnológica** para ser evaluada y desarrollada en la siguiente fase de evolución del proyecto.

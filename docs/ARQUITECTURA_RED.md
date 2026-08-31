# Documentación Técnica: Funcionamiento de Red, DHCP e IPs Dinámicas en SmartMonitor v3

**Proyecto:** SmartMonitor v3  
**Módulo:** Agente de Windows (`smartmonitor_agent.py`)  
**Tema:** Resiliencia de Red, Manejo de IP Dinámica (DHCP) y Auto-Healing  

---

## 1. Principio de Funcionamiento de Red

En Windows, cada adaptador de red (Wi-Fi o Ethernet) mantiene dos configuraciones independientes en la pila TCP/IP:

1. **Dirección IP del Equipo (IP Address):** Asignada dinámicamente por el router Wi-Fi a través del protocolo DHCP de la red (ejemplo: `192.168.1.150`).
2. **Servidores DNS (DNS Servers):** Servidores encargados de traducir nombres de dominio (ej. `google.com`) a direcciones IP de destino.

> [!IMPORTANT]
> **Garantía de Configuración:** El agente de **SmartMonitor v3 NUNCA modifica la Dirección IP ni la máscara de red del equipo**. La laptop mantiene en todo momento su IP dinámica asignada por el router local o corporativo. El agente solo conmuta dinámicamente la configuración de los **Servidores DNS**.

---

## 2. Flujo de Transición Automática entre Redes

```
                   ┌──────────────────────────────────────────────┐
                   │   Laptop se Conecta a una Red (Wi-Fi)        │
                   │   Windows recibe IP Dinámica por DHCP        │
                   └──────────────────────┬───────────────────────┘
                                          │
                   ┌──────────────────────▼───────────────────────┐
                   │  Agente realiza Test de Conectividad         │
                   │  hacia el Servidor Central de SmartMonitor   │
                   └──────────┬────────────────────────┬──────────┘
                              │                        │
               ¿Responde el Servidor Central?          │
                              │                        │
                    SÍ        │                        │ NO
           ┌──────────────────▼──────┐      ┌──────────▼─────────────────┐
           │ Modo Red Corporativa    │      │ Modo Red Externa / Fallback│
           │ (Empresa)               │      │ (Casa, Cliente, Hotspot)   │
           ├─────────────────────────┤      ├────────────────────────────┤
           │ - IP: Dinámica (DHCP)   │      │ - IP: Dinámica (DHCP)      │
           │ - DNS: Local 127.0.0.1  │      │ - DNS: Automático (DHCP)   │
           │ - Filtro Web: ACTIVO    │      │ - Filtro Web: Libre        │
           └─────────────────────────┘      └────────────────────────────┘
```

### 2.1 Flujo al entrar a la Red Corporativa (Empresa)

1. La laptop se conecta al Wi-Fi de la empresa.
2. El servidor DHCP corporativo le otorga una IP dinámica de la subred local (ej. `192.168.10.45`).
3. El agente de SmartMonitor detecta el cambio de red (`_network_changed`) y consulta al servidor central.
4. Al recibir respuesta **HTTP 200 OK**, el agente ejecuta `ensure_local_dns()`.
5. Los Servidores DNS de la interfaz Wi-Fi se fijan a `127.0.0.1` (`cloudflared.exe`) para aplicar las reglas de bloqueo web y protección.
6. La IP dinámica no sufre ningún corte ni reasignación.

### 2.2 Flujo al salir a una Red Externa (Hogar, Cliente, Hotspot)

1. La laptop se conecta al Wi-Fi externo y recibe una IP dinámica del router de la casa/cliente.
2. El agente realiza la prueba de conectividad hacia el servidor central de SmartMonitor, la cual falla por no estar en la red corporativa ni en la VPN.
3. Al acumular 2 reintentos fallidos, el agente activa automáticamente el **Fallback a DHCP** mediante `restore_dhcp_dns()`.
4. Los Servidores DNS de la interfaz Wi-Fi vuelven a `source=dhcp` (DNS del router del hogar o proveedor de Internet).
5. **Resultado:** El usuario navega libremente y sin ninguna desconexión ni mensaje de "Sin Internet".

---

## 3. Estado de `cloudflared` y Archivo `hosts` durante la Conmutación

### 3.1 Proceso `cloudflared.exe` en `127.0.0.1:53`

- El proceso `cloudflared` se mantiene corriendo en segundo plano como un servicio silencioso en `127.0.0.1:53`.
- **En la empresa:** El adaptador Wi-Fi apunta a `127.0.0.1`, por lo que el tráfico DNS pasa por `cloudflared` para aplicar filtrado.
- **En red externa:** El adaptador Wi-Fi conmuta a DNS DHCP (router de la casa). Aunque `cloudflared` sigue escuchando en `127.0.0.1`, **Windows ya no le envía peticiones a él**, redirigiéndolas limpiamente al router local.

### 3.2 Registro en `C:\Windows\System32\drivers\etc\hosts`

El agente mantiene la línea:

```text
100.x.y.z dns.smartmonitor.local # SmartMonitor DoH upstream
```

- **Dominio Exclusivo:** Solo mapea el nombre interno `dns.smartmonitor.local` para que `cloudflared` sepa a qué IP de la VPN conectarse cuando haya cobertura.
- **Inocuo para la Navegación Externa:** No afecta sitios públicos como `google.com`, `youtube.com` o bancos.

### 3.3 Matriz de Estados de Componentes

| Componente | Modo Red Corporativa (Empresa) | Modo Red Externa (Casa / Cliente / Hotspot) |
| :--- | :--- | :--- |
| **`cloudflared.exe`** | Activo procesando DNS en `127.0.0.1:53` | Activo en reposo escuchando en `127.0.0.1:53` |
| **Servidor DNS Adaptador Wi-Fi** | Estático `127.0.0.1` | **Automático por DHCP (Router Local)** |
| **Archivo `hosts`** | Mantiene `dns.smartmonitor.local` | Mantiene `dns.smartmonitor.local` |
| **Experiencia de Navegación** | Filtrada y protegida según políticas | **100% libre, fluida y sin desconexiones** |

---

## 4. Preguntas Frecuentes y Soporte TI (FAQ)

### ¿Puede este mecanismo causar conflictos de IP o fallos al regresar a la empresa?

**No.** Dado que el agente solo conmuta los servidores DNS y no toca la dirección IP, el router de la empresa administra la concesión DHCP (*DHCP Lease*) exactamente igual que con cualquier otra computadora.

### ¿Se requiere alguna intervención por parte del equipo de soporte técnico?

**No.** El sistema es 100% autónomo y "auto-sanable" (*self-healing*). No requiere ejecutar scripts, reiniciar servicios ni ingresar códigos de pausa cuando el usuario entra o sale de la empresa.

### ¿Se requieren reinicios de la computadora?

**No.** La conmutación entre DNS local `127.0.0.1` y DNS `DHCP` se realiza mediante llamadas nativas NDIS en caliente (`netsh interface ipv4/ipv6 set dnsservers`). La interfaz de red nunca se deshabilita ni pierde el controlador.

### ¿Cómo verificar el estado en los logs del agente?

El archivo de registro ubicado en `C:\Program Files\SmartMonitor Agent\agent.log` registrará los eventos de conmutación transparente:

- **Al entrar a la empresa:**  
  `Conectividad con servidor restablecida. Reaplicando DNS local 127.0.0.1 y protecciones.`
- **Al salir a una red externa:**  
  `WARN: Servidor no alcanzable en la red actual. Activando fallback automatico de DNS a DHCP para evitar desconexion de Wi-Fi...`

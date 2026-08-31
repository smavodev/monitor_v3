# Centro de Documentación Técnica: SmartMonitor v3

¡Bienvenido al centro de documentación técnica de **SmartMonitor v3**! Aquí encontrarás las guías de arquitectura, despliegue, operación y propuestas de evolución del sistema.

---

## 📚 Índice de Documentos

| Documento | Descripción | Audiencia / Caso de Uso |
| :--- | :--- | :--- |
| 📘 **[GUIA_DESPLIEGUE.md](./GUIA_DESPLIEGUE.md)** | Guía paso a paso para desplegar el servidor (Docker), compilar los binarios de Windows (`.exe` e Inno Setup) e instalar agentes en Linux. | **SysAdmins / DevOps / Soporte TI** |
| 📄 **[RESUMEN_EJECUTIVO.md](./RESUMEN_EJECUTIVO.md)** | Visión general del proyecto, arquitectura de alto nivel, módulos principales y stack tecnológico. | **Líderes de Proyecto / Gerencia** |
| 🛡️ **[ARQUITECTURA_RED.md](./ARQUITECTURA_RED.md)** | Explicación técnica detallada sobre la resiliencia en redes externas, DHCP, Auto-Healing y no interferencia con Wi-Fi. | **Ingenieros de Red / Soporte TI** |
| 📊 **[INFORME_CAMBIOS.md](./INFORME_CAMBIOS.md)** | Informe ejecutivo sobre los cambios implementados para garantizar la continuidad operativa de los laptops corporativos. | **Auditoría / IT Managers** |
| 💡 **[PROPUESTA_AGENTE_V4.md](./PROPUESTA_AGENTE_V4.md)** | Estudio de factibilidad y propuesta técnica para el desarrollo de un agente 100% propietario (Python/Go embebido). | **Desarrolladores Core / Arquitectos** |

---

## 🏛️ Estructura del Repositorio

```text
smartmonitor3/
├── README.md                      # Punto de entrada principal al proyecto
├── setup.sh                       # Instalador automatizado del Servidor Linux
├── config/                        # Configuraciones de Infraestructura (Headscale VPN)
├── docs/                          # Documentación centralizada (este directorio)
├── server/                        # Backend FastAPI + Dashboard Frontend SPA
└── agents/                        # Código fuente de Agentes Clientes
    ├── windows/src/               # Agente nativo de Windows (.exe / Servicio)
    └── linux/src/                 # Agente nativo de Linux (Bash / Daemon)
```

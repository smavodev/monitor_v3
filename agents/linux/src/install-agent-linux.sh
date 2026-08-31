#!/bin/sh
# SmartMonitor v3 — Instalador de agente Linux
# POSIX puro a proposito (no bashismos: $EUID, [[ ]], BASH_SOURCE, etc.) -
# en Ubuntu/Debian y derivados (Parrot, Zorin) /bin/sh es dash, no bash, y
# es comun invocarlo como "sh install-agent-linux.sh" en vez de "bash ..." -
# con bashismos, eso rompia el instalador silenciosamente en esos casos.
set -e

GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { printf '%b\n' "${GREEN}✓${NC} $1"; }
info() { printf '%b\n' "${CYAN}→${NC} $1"; }
fail() { printf '%b\n' "${RED}✗ ERROR:${NC} $1"; exit 1; }

# IP del servidor SmartMonitor por defecto — UNICO lugar a tocar si el server
# se muda de IP. Se usa solo si no se pasa un argumento (mismo criterio que
# SMARTMONITOR_DEFAULT_SERVER_IP en install-agent-windows.bat).
SMARTMONITOR_DEFAULT_SERVER_IP="monitoreo.smarthrlatam.com"

# Se asegura de poder correrse directo (./install-agent-linux.sh) sin que
# haga falta acordarse de chmod +x el archivo primero.
chmod +x "$0" 2>/dev/null || true

# Si no se corre como root, se re-ejecuta el mismo script via sudo - pide la
# contraseña ahi mismo (el flujo normal de sudo) en vez de solo fallar
# pidiendo que lo vuelvas a correr vos mismo con "sudo" por delante. Se usa
# "$(id -u)" en vez de "$EUID" (variable de bash, no existe en dash/sh).
if [ "$(id -u)" -ne 0 ]; then
    echo "Este instalador necesita permisos de administrador."
    exec sudo sh "$0" "$@"
fi

SERVER_IP="${1:-$SMARTMONITOR_DEFAULT_SERVER_IP}"
EQUIPO_NOMBRE="${2:-$(hostname)}"
# "$0" en vez de "${BASH_SOURCE[0]}" (array de bash, no existe en dash) -
# funciona igual para encontrar la carpeta del propio script.
AGENT_SRC="$(cd "$(dirname "$0")" && pwd)/smartmonitor-push.py"
AGENT_DEST="/usr/local/bin/smartmonitor-push.py"
SERVICE_FILE="/etc/systemd/system/smartmonitor-agent.service"

[ ! -f "$AGENT_SRC" ] && fail "No encuentro $AGENT_SRC"

printf '%b\n' "\n${BOLD}SmartMonitor v3 — Instalando agente${NC}"
info "Servidor : http://${SERVER_IP}:8000"
info "Equipo   : $EQUIPO_NOMBRE"

# ── CA propia del server (para que la página de bloqueo se vea también en
# sitios HTTPS, incluido YouTube) ────────────────────────────────────────────
# Se instala en el almacén de certificados del sistema (Chrome/Chromium la
# heredan de ahí) y, además, en el almacén NSS de cada perfil de Firefox y de
# Chrome (que en Linux NO usan el almacén del sistema por defecto).
install_ca() {
    # Se prueba primero por HTTPS (mismo certificado, tambien servido por la
    # app principal detras de nginx - GET /smartmonitor-ca.crt) antes que HTTP
    # plano al puerto 80: descargar un .crt por HTTP directo a una IP (sin
    # dominio, sin cifrar) es un patron que la heuristica de varios antivirus
    # (Kaspersky confirmado en Windows) marca como sitio malintencionado -
    # aunque en Linux no es tan comun tener un antivirus corriendo, se deja
    # igual de consistente con el instalador de Windows. Se ignora la
    # validacion del certificado (-k / --no-check-certificate) porque, si
    # SERVER_IP es la IP en vez de un dominio real, el nombre nunca va a
    # coincidir - igual se gana cifrado en transito.
    local CA_URL_HTTPS="https://${SERVER_IP}/smartmonitor-ca.crt"
    local CA_URL_HTTP="http://${SERVER_IP}/smartmonitor-ca.crt"
    local CA_DEST="/usr/local/share/ca-certificates/smartmonitor-ca.crt"
    local tmp; tmp="$(mktemp)"

    if ! curl -fsSLk --max-time 10 "$CA_URL_HTTPS" -o "$tmp" 2>/dev/null && ! wget -q --no-check-certificate --timeout=10 -O "$tmp" "$CA_URL_HTTPS" 2>/dev/null && \
       ! curl -fsSL --max-time 10 "$CA_URL_HTTP" -o "$tmp" 2>/dev/null && ! wget -q --timeout=10 -O "$tmp" "$CA_URL_HTTP" 2>/dev/null; then
        printf '%b\n' "  ⚠ No se pudo descargar la CA de $CA_URL_HTTPS ni $CA_URL_HTTP (¿servidor apagado?) — se omite, reintenta luego con este script"
        rm -f "$tmp"
        return
    fi
    if ! grep -q "BEGIN CERTIFICATE" "$tmp"; then
        printf '%b\n' "  ⚠ La respuesta de $CA_URL_HTTPS/$CA_URL_HTTP no parece un certificado — se omite"
        rm -f "$tmp"
        return
    fi

    cp "$tmp" "$CA_DEST"
    rm -f "$tmp"
    if command -v update-ca-certificates >/dev/null 2>&1; then
        update-ca-certificates >/dev/null 2>&1
        ok "CA instalada en el almacén del sistema (Chrome/Chromium la heredan)"
    fi

    # Firefox / Chrome en Linux usan su propio almacén NSS por perfil, no el
    # del sistema. Requiere 'certutil' (paquete libnss3-tools).
    if ! command -v certutil >/dev/null 2>&1; then
        apt-get install -y --no-install-recommends libnss3-tools >/dev/null 2>&1 || true
    fi
    if command -v certutil >/dev/null 2>&1; then
        local installed=0
        for profile_dir in /root/.mozilla/firefox/*.* /home/*/.mozilla/firefox/*.* \
                            /root/.pki/nssdb /home/*/.pki/nssdb; do
            [ -d "$profile_dir" ] || continue
            certutil -D -n "SmartMonitor Root CA" -d "sql:$profile_dir" >/dev/null 2>&1 || true
            if certutil -A -n "SmartMonitor Root CA" -t "C,," -i "$CA_DEST" -d "sql:$profile_dir" >/dev/null 2>&1; then
                installed=$((installed + 1))
            fi
        done
        [ "$installed" -gt 0 ] && ok "CA instalada en $installed perfil(es) de Firefox/Chrome (NSS)"
    else
        printf '%b\n' "  ⚠ 'certutil' no disponible: Firefox/Chrome mostrarán advertencia de certificado en sitios bloqueados HTTPS"
    fi
}

install_ca

# ── Tailscale (tunel WireGuard/Headscale) ───────────────────────────────────
# Mismo motivo que en Windows: da a este equipo una IP unica en el tunel para
# que dns_blocker.py lo distinga de otros equipos que comparten la IP publica
# de la oficina. No es indispensable - si falla o no hay internet, el agente
# sigue bloqueando igual que siempre por la IP publica compartida.
install_tailscale() {
    if command -v tailscale >/dev/null 2>&1; then
        ok "Tailscale ya estaba instalado"
    else
        info "Instalando cliente Tailscale..."
        # Prerequisitos minimos que el instalador oficial de Tailscale
        # necesita (curl, gnupg, ca-certificates) - en instalaciones muy
        # minimas (algunas imagenes de Ubuntu Server/cloud) pueden faltar, y
        # ahi el instalador de Tailscale fallaba en silencio sin decir por
        # que (bug real reportado: "en Ubuntu no instalaba el tailnet").
        # Cubre Debian, Ubuntu, Parrot y Zorin (todos derivados de Debian,
        # todos con apt-get).
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -qq >/dev/null 2>&1 || true
            apt-get install -y --no-install-recommends curl gnupg ca-certificates lsb-release >/dev/null 2>&1 || true
        fi
        local tmp tslog
        tmp="$(mktemp)"; tslog="$(mktemp)"
        if curl -fsSL --max-time 15 https://tailscale.com/install.sh -o "$tmp" 2>/dev/null \
           || wget -q --timeout=15 -O "$tmp" https://tailscale.com/install.sh 2>/dev/null; then
            # timeout acota el script completo (apt update/install real) -
            # si algo se cuelga (ej. un mirror de apt caido), no se queda
            # esperando para siempre y el resto del instalador sigue. La
            # salida se guarda (no se silencia del todo) para poder mostrar
            # el motivo real si falla, en vez de un mensaje generico sin pistas.
            if timeout 180 sh "$tmp" >"$tslog" 2>&1; then
                ok "Tailscale instalado"
            else
                printf '%b\n' "  ⚠ No se pudo instalar Tailscale (reintenta luego re-ejecutando este instalador; el agente sigue bloqueando por IP publica mientras tanto)"
                echo "  Detalle del error:"
                tail -n 15 "$tslog" | sed 's/^/    /'
            fi
        else
            printf '%b\n' "  ⚠ No se pudo descargar el instalador de Tailscale — se omite"
        fi
        rm -f "$tmp" "$tslog"
    fi

    # NetworkManager tiene su propio perfil de conexion para la interfaz
    # tailscale0 y puede pisarle el DNS/la IP en cualquier momento (bug real
    # encontrado en producción: "tailscale status" mostraba la IP correcta
    # mientras "ip addr show tailscale0" mostraba una vieja, hasta reiniciar
    # tailscaled). Se le dice a NetworkManager que ignore esa interfaz por
    # completo - Tailscale ya la gestiona sola.
    if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager 2>/dev/null; then
        mkdir -p /etc/NetworkManager/conf.d
        cat > /etc/NetworkManager/conf.d/99-tailscale-unmanaged.conf <<'NMEOF'
[keyfile]
unmanaged-devices=interface-name:tailscale0
NMEOF
        nmcli connection delete tailscale0 >/dev/null 2>&1 || true
        systemctl reload NetworkManager >/dev/null 2>&1 || systemctl restart NetworkManager >/dev/null 2>&1
        ok "NetworkManager configurado para no interferir con tailscale0"
    fi
}

install_tailscale

# Si es una reinstalacion/actualizacion sobre un agente ya instalado, se
# detiene el servicio Y se mata cualquier proceso suelto que no este bajo
# systemd (ej. si alguna vez se corrio a mano) - sin esto, un proceso viejo
# podia seguir corriendo con el codigo anterior en memoria mientras el
# binario ya se reemplazo, o pelear con el proceso nuevo por el mismo
# puerto/recursos. Mismo criterio que ya usa el desinstalador.
systemctl stop smartmonitor-agent >/dev/null 2>&1 || true
pkill -f "smartmonitor-push.py" >/dev/null 2>&1 || true
sleep 1

# Copiar agente
cp "$AGENT_SRC" "$AGENT_DEST"
chmod +x "$AGENT_DEST"

# Inyectar SERVER y HOSTNAME en el script
sed -i "s|^SERVER.*=.*|SERVER    = \"http://${SERVER_IP}:8000\"|" "$AGENT_DEST"
sed -i "s|^HOSTNAME.*=.*|HOSTNAME  = \"${EQUIPO_NOMBRE}\"|"        "$AGENT_DEST"

# El .py fuente ya trae puesto el server real por defecto (no un placeholder
# - un despliegue manual sin pasar por este instalador, ej. "cp" directo,
# tiene que quedar funcional igual). Verificar aca que el sed de arriba
# realmente inyecto el SERVER_IP pedido, no sea que haya fallado en
# silencio y el agente quede apuntando al default en vez de a donde se le
# dijo (visto en produccion: un "cp" manual del .py de este repo piso el
# reemplazo de un despliegue existente y dejo el agente sin poder resolver
# DNS durante horas sin ningun aviso).
if ! grep -q "^SERVER.*http://${SERVER_IP}:8000" "$AGENT_DEST"; then
    fail "El reemplazo del servidor NO se aplico - $AGENT_DEST no quedo apuntando a ${SERVER_IP}."
fi

ok "Agente copiado a $AGENT_DEST"

# Crear servicio systemd
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SmartMonitor v3 Agent
After=network.target

[Service]
# PYTHONUNBUFFERED=1: sin esto, el stdout de Python queda con buffer
# completo (no por linea) al no ser una tty - systemd/journald recien ve
# los print() cuando el buffer interno se llena (~8KB), asi que docenas de
# lineas de minutos u horas de diferencia terminan todas con el MISMO
# timestamp en el journal (bug real encontrado en LAP-ISAAVEDRA
# investigando cortes de wifi: el log parecia mostrar cientos de eventos
# "al mismo tiempo" cuando en realidad estaban repartidos en horas - hacia
# imposible diagnosticar nada por journalctl).
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 $AGENT_DEST
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable smartmonitor-agent --quiet
systemctl start smartmonitor-agent
ok "Servicio smartmonitor-agent iniciado y habilitado"

# Verificación final: mostrar el SERVER que de verdad quedó en el archivo
# instalado, no el que se pidió — así un fallo silencioso del sed (o una
# copia vieja del instalador) se nota en el momento y no hay que
# diagnosticarlo después por SSH viendo a qué servidor llega el tráfico.
DEPLOYED_SERVER="$(grep '^SERVER' "$AGENT_DEST" | head -1)"
echo ""
printf '%b\n' "${BOLD}${GREEN}Agente activo.${NC} El primer reporte se manda de inmediato al arrancar"
echo "(no espera el intervalo configurado) - datos visibles en el dashboard en unos segundos"
printf '%b\n' "  Servidor configurado (verificado en el archivo instalado): ${CYAN}${DEPLOYED_SERVER}${NC}"
case "$DEPLOYED_SERVER" in
    *"$SERVER_IP"*) ;;
    *) printf '%b\n' "  ${RED}⚠ ADVERTENCIA: no coincide con la IP pedida (${SERVER_IP}). Revisa el archivo.${NC}" ;;
esac
printf '%b\n' "  Estado: ${CYAN}systemctl status smartmonitor-agent${NC}"
printf '%b\n' "  Logs:   ${CYAN}journalctl -u smartmonitor-agent -f${NC}"
echo ""

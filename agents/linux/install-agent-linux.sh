#!/bin/bash
# SmartMonitor v3 — Instalador de agente Linux
set -e

GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $1"; }
info() { echo -e "${CYAN}→${NC} $1"; }
fail() { echo -e "${RED}✗ ERROR:${NC} $1"; exit 1; }

[ "$EUID" -ne 0 ] && fail "Ejecutar con sudo: sudo bash install-agent-linux.sh <IP_SERVIDOR> [NOMBRE_EQUIPO]"

SERVER_IP="${1:-localhost}"
EQUIPO_NOMBRE="${2:-$(hostname)}"
AGENT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/smartmonitor-push.py"
AGENT_DEST="/usr/local/bin/smartmonitor-push.py"
SERVICE_FILE="/etc/systemd/system/smartmonitor-agent.service"

[ ! -f "$AGENT_SRC" ] && fail "No encuentro $AGENT_SRC"

echo -e "\n${BOLD}SmartMonitor v3 — Instalando agente${NC}"
info "Servidor : http://${SERVER_IP}:8000"
info "Equipo   : $EQUIPO_NOMBRE"

# ── CA propia del server (para que la página de bloqueo se vea también en
# sitios HTTPS, incluido YouTube) ────────────────────────────────────────────
# Se instala en el almacén de certificados del sistema (Chrome/Chromium la
# heredan de ahí) y, además, en el almacén NSS de cada perfil de Firefox y de
# Chrome (que en Linux NO usan el almacén del sistema por defecto).
install_ca() {
    local CA_URL="http://${SERVER_IP}/smartmonitor-ca.crt"
    local CA_DEST="/usr/local/share/ca-certificates/smartmonitor-ca.crt"
    local tmp; tmp="$(mktemp)"

    if ! curl -fsSL "$CA_URL" -o "$tmp" 2>/dev/null && ! wget -qO "$tmp" "$CA_URL" 2>/dev/null; then
        echo -e "  ⚠ No se pudo descargar la CA de $CA_URL (¿servidor apagado?) — se omite, reintenta luego con este script"
        rm -f "$tmp"
        return
    fi
    if ! grep -q "BEGIN CERTIFICATE" "$tmp"; then
        echo -e "  ⚠ La respuesta de $CA_URL no parece un certificado — se omite"
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
        echo -e "  ⚠ 'certutil' no disponible: Firefox/Chrome mostrarán advertencia de certificado en sitios bloqueados HTTPS"
    fi
}

install_ca

# Copiar agente
cp "$AGENT_SRC" "$AGENT_DEST"
chmod +x "$AGENT_DEST"

# Inyectar SERVER y HOSTNAME en el script
sed -i "s|^SERVER.*=.*|SERVER    = \"http://${SERVER_IP}:8000\"|" "$AGENT_DEST"
sed -i "s|^HOSTNAME.*=.*|HOSTNAME  = \"${EQUIPO_NOMBRE}\"|"        "$AGENT_DEST"

ok "Agente copiado a $AGENT_DEST"

# Detener si ya existe
systemctl stop smartmonitor-agent 2>/dev/null || true

# Crear servicio systemd
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=SmartMonitor v3 Agent
After=network.target

[Service]
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
echo -e "${BOLD}${GREEN}Agente activo.${NC} Datos visibles en el dashboard en ~30s"
echo -e "  Servidor configurado (verificado en el archivo instalado): ${CYAN}${DEPLOYED_SERVER}${NC}"
if [[ "$DEPLOYED_SERVER" != *"$SERVER_IP"* ]]; then
    echo -e "  ${RED}⚠ ADVERTENCIA: no coincide con la IP pedida (${SERVER_IP}). Revisa el archivo.${NC}"
fi
echo -e "  Estado: ${CYAN}systemctl status smartmonitor-agent${NC}"
echo -e "  Logs:   ${CYAN}journalctl -u smartmonitor-agent -f${NC}"
echo ""

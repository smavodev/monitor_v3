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

echo ""
echo -e "${BOLD}${GREEN}Agente activo.${NC} Datos visibles en el dashboard en ~30s"
echo -e "  Estado: ${CYAN}systemctl status smartmonitor-agent${NC}"
echo -e "  Logs:   ${CYAN}journalctl -u smartmonitor-agent -f${NC}"
echo ""

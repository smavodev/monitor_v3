#!/bin/bash
# SmartMonitor v3 — Instalador
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $1"; }
info() { echo -e "${CYAN}→${NC} $1"; }
step() { echo -e "\n${BOLD}[$1]${NC} $2"; }
fail() { echo -e "${RED}✗ ERROR:${NC} $1"; exit 1; }

[ "$EUID" -ne 0 ] && fail "Ejecutar con sudo: sudo bash setup.sh"

REAL_USER="${SUDO_USER:-$USER}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$SCRIPT_DIR"

echo -e "\n${BOLD}╔══════════════════════════════════════╗${NC}"
echo -e "${BOLD}║      SmartMonitor v3.0 Setup         ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════╝${NC}\n"

DEFAULT_HOSTNAME=$(hostname)
echo -e "Nombre para este equipo en el dashboard [${CYAN}${DEFAULT_HOSTNAME}${NC}]: \c"
read -r EQUIPO_NOMBRE
EQUIPO_NOMBRE="${EQUIPO_NOMBRE:-$DEFAULT_HOSTNAME}"

echo ""
info "Equipo   : $EQUIPO_NOMBRE"
info "Directorio: $INSTALL_DIR"

# ─── 0. Limpieza ────────────────────────────────────────────────────────────
step "0/4" "Limpiando instalación previa"
if [ -f "$INSTALL_DIR/server/docker-compose.yml" ]; then
  docker compose -f "$INSTALL_DIR/server/docker-compose.yml" down -v --remove-orphans 2>/dev/null || true
fi
docker volume rm smartmonitor3_db_data smartmonitor3_app_data 2>/dev/null || true
rm -f /usr/local/bin/smartmonitor-push.sh /etc/cron.d/smartmonitor /tmp/sm_hw_sent
ok "Limpieza completa"

# ─── 1. Docker ──────────────────────────────────────────────────────────────
step "1/4" "Verificando Docker"
apt-get update -qq
apt-get install -y -qq curl wget ca-certificates > /dev/null

if command -v docker &>/dev/null; then
  ok "Docker ya instalado: $(docker --version | cut -d' ' -f3 | tr -d ',')"
else
  info "Instalando Docker..."
  curl -fsSL https://get.docker.com | bash > /dev/null 2>&1
  ok "Docker instalado"
fi

if ! groups "$REAL_USER" | grep -q docker; then
  usermod -aG docker "$REAL_USER"
  ok "Usuario $REAL_USER añadido al grupo docker"
fi

if ! docker compose version &>/dev/null 2>&1; then
  apt-get install -y -qq docker-compose-plugin > /dev/null
fi

systemctl enable docker --quiet && systemctl start docker
ok "Docker Compose: $(docker compose version --short)"

# ─── 2. Verificar archivos y configuración (.env) ───────────────────────────
step "2/4" "Verificando archivos y variables de entorno"
[ ! -f "$INSTALL_DIR/server/docker-compose.yml" ] && fail "No encuentro server/docker-compose.yml"

if [ ! -f "$INSTALL_DIR/server/.env" ] && [ -f "$INSTALL_DIR/server/.env.example" ]; then
  cp "$INSTALL_DIR/server/.env.example" "$INSTALL_DIR/server/.env"
  info "Archivo server/.env creado desde plantilla (.env.example)"
fi

ok "Archivos y configuración listos"

# ─── 3. Levantar servidor ────────────────────────────────────────────────────
step "3/4" "Construyendo e iniciando SmartMonitor v3"
cd "$INSTALL_DIR/server"
docker compose build --quiet
docker compose up -d

info "Esperando que el servidor inicie..."
MAX_WAIT=90; WAIT=0
until curl -s http://localhost:8000/ > /dev/null 2>&1; do
  sleep 3; WAIT=$((WAIT+3))
  [ $WAIT -ge $MAX_WAIT ] && { echo ""; warn "El servidor tardó más de lo esperado."; break; }
  echo -ne "\r   ${CYAN}Esperando... ${WAIT}s${NC}   "
done
echo ""
ok "Servidor activo"

# ─── 4. Agente local ─────────────────────────────────────────────────────────
step "4/4" "Instalando agente en este equipo"
AGENT="$INSTALL_DIR/agents/linux/src/install-agent-linux.sh"
[ -f "$AGENT" ] && bash "$AGENT" localhost "$EQUIPO_NOMBRE" || true

echo -e "\n${BOLD}${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║         ✅  SmartMonitor v3 activo           ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════╝${NC}\n"
echo -e "  ${BOLD}Dashboard:${NC}   http://localhost:8000"
echo -e "  ${BOLD}Usuario:${NC}     admin@smartmonitor.local"
echo -e "  ${BOLD}Contraseña:${NC}  Admin2024!"
echo -e "  ${BOLD}Equipo:${NC}      $EQUIPO_NOMBRE (visible en ~30s)"
echo ""
echo -e "  ${BOLD}Agregar equipos Linux:${NC}"
echo -e "  ${CYAN}sudo bash agents/linux/src/install-agent-linux.sh <IP> \"Nombre\"${NC}"
echo ""
warn "Cambia la contraseña desde el panel de Usuarios después del primer acceso."
echo ""

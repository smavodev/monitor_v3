#!/bin/sh
# SmartMonitor v3 — Desinstalador de agente Linux (limpieza completa)
# Espejo del desinstalador de Windows: revierte todo lo que hace
# install-agent-linux.sh, en el mismo orden de importancia.
# POSIX puro a proposito (no bashismos: $EUID, [[ ]], <<<, read -t/-p) - en
# Ubuntu/Debian y derivados (Parrot, Zorin) /bin/sh es dash, no bash, y es
# comun invocarlo como "sh uninstall-agent-linux.sh" en vez de "bash ..." -
# con bashismos, eso rompia el desinstalador silenciosamente en esos casos.

GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { printf '%b\n' "${GREEN}✓${NC} $1"; }
info() { printf '%b\n' "${CYAN}→${NC} $1"; }
warn() { printf '%b\n' "  ⚠ $1"; }

# Se asegura de poder correrse directo (./uninstall-agent-linux.sh) sin que
# haga falta acordarse de chmod +x el archivo primero.
chmod +x "$0" 2>/dev/null || true

# Si no se corre como root, se re-ejecuta el mismo script via sudo - pide la
# contraseña ahi mismo en vez de solo fallar pidiendo que lo vuelvas a correr
# vos mismo con "sudo" por delante. Se usa "$(id -u)" en vez de "$EUID"
# (variable de bash, no existe en dash/sh).
if [ "$(id -u)" -ne 0 ]; then
    echo "Este desinstalador necesita permisos de administrador."
    exec sudo sh "$0" "$@"
fi

AGENT_DEST="/usr/local/bin/smartmonitor-push.py"
SERVICE_FILE="/etc/systemd/system/smartmonitor-agent.service"

printf '%b\n' "\n${BOLD}SmartMonitor v3 — Desinstalando y revirtiendo todos los cambios...${NC}\n"

# 1) Detener y deshabilitar el servicio, borrar la unidad systemd
systemctl stop smartmonitor-agent >/dev/null 2>&1
systemctl disable smartmonitor-agent >/dev/null 2>&1
rm -f "$SERVICE_FILE"
systemctl daemon-reload >/dev/null 2>&1
ok "Servicio smartmonitor-agent detenido y eliminado"

# 2) Matar cualquier proceso del agente que quede vivo (por si no corria
# como servicio, o el stop no alcanzo a matarlo)
pkill -f "smartmonitor-push.py" >/dev/null 2>&1
sleep 1
if pgrep -f "smartmonitor-push.py" >/dev/null 2>&1; then
    warn "Sigue vivo un proceso del agente - revisa manualmente (ps aux | grep smartmonitor)"
else
    ok "Procesos del agente detenidos"
fi

# 3) Restaurar el DNS automatico - mismo mecanismo que restore_dns_central()
# del propio agente (nmcli si NetworkManager esta activo, si no resolvectl,
# si no limpiar el marcador que el agente deja en /etc/resolv.conf).
if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager 2>/dev/null; then
    # Se pasa por un pipe (no un here-string "<<<", que es bashismo y no
    # existe en dash/sh) - corre en subshell pero aca no hace falta que las
    # variables del loop sobrevivan afuera.
    nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null \
        | awk -F: '$2 !~ /^(docker|br-|veth|lo)/ {print $1}' \
        | while IFS= read -r name; do
            [ -z "$name" ] && continue
            nmcli connection modify "$name" ipv4.dns "" ipv4.ignore-auto-dns no \
                                            ipv6.dns "" ipv6.ignore-auto-dns no >/dev/null 2>&1
            nmcli connection up "$name" >/dev/null 2>&1
        done
elif command -v resolvectl >/dev/null 2>&1; then
    resolvectl revert '*' >/dev/null 2>&1
fi
sed -i '/# SmartMonitor CENTRAL DNS/d' /etc/resolv.conf 2>/dev/null
ok "DNS restaurado a automatico"

# 4) Desconectar del tunel WireGuard - "logout" con limite de tiempo (necesita
# contactar al control server por red, no se lo puede esperar para siempre)
if command -v tailscale >/dev/null 2>&1; then
    timeout 10 tailscale logout >/dev/null 2>&1
    ok "Sesion de Tailscale cerrada (logout de Headscale)"
fi

# 5) Quitar la configuracion de NetworkManager que ignoraba tailscale0
if [ -f /etc/NetworkManager/conf.d/99-tailscale-unmanaged.conf ]; then
    rm -f /etc/NetworkManager/conf.d/99-tailscale-unmanaged.conf
    systemctl reload NetworkManager >/dev/null 2>&1 || systemctl restart NetworkManager >/dev/null 2>&1
    ok "Configuracion de NetworkManager para tailscale0 revertida"
fi

# 6) Desinstalar el paquete de Tailscale (solo si SmartMonitor lo instalo -
# no se fuerza si el usuario ya lo usaba para otra cosa antes; se pregunta)
if command -v tailscale >/dev/null 2>&1; then
    if [ -t 0 ]; then
        # "read -t/-p" son bashismos (dash no los soporta) - se imprime el
        # prompt aparte con printf, y el limite de tiempo se hace con el
        # comando externo "timeout" envolviendo un "read" simple.
        printf '¿Desinstalar tambien el paquete de Tailscale? [s/N]: '
        resp="$(timeout 15 sh -c 'read -r x && printf "%s" "$x"' 2>/dev/null)"
    else
        # Sin terminal interactiva (ej. corrido via un pipe) - "read" se
        # quedaria esperando input que nunca llega. Se deja Tailscale
        # instalado por defecto (seguro, ya sin sesion activa por el logout
        # de arriba) en vez de colgar el desinstalador.
        resp=""
        info "Sin terminal interactiva - se deja Tailscale instalado (podes desinstalarlo a mano despues)"
    fi
    case "$resp" in
        s|S)
            if command -v apt-get >/dev/null 2>&1; then
                timeout 60 apt-get remove -y tailscale >/dev/null 2>&1 && ok "Paquete de Tailscale desinstalado" \
                    || warn "No se pudo desinstalar el paquete de Tailscale - revisa manualmente"
            else
                warn "Gestor de paquetes no reconocido (no es apt) - desinstala Tailscale manualmente si quieres"
            fi
            ;;
        *) info "Se deja Tailscale instalado (ya sin sesion activa)" ;;
    esac
fi

# 7) Quitar el certificado de la CA de SmartMonitor (almacen del sistema + NSS)
CA_DEST="/usr/local/share/ca-certificates/smartmonitor-ca.crt"
if [ -f "$CA_DEST" ]; then
    rm -f "$CA_DEST"
    command -v update-ca-certificates >/dev/null 2>&1 && update-ca-certificates >/dev/null 2>&1
    ok "Certificado de la CA eliminado del almacen del sistema"
fi
if command -v certutil >/dev/null 2>&1; then
    for profile_dir in /root/.mozilla/firefox/*.* /home/*/.mozilla/firefox/*.* \
                        /root/.pki/nssdb /home/*/.pki/nssdb; do
        [ -d "$profile_dir" ] || continue
        certutil -D -n "SmartMonitor Root CA" -d "sql:$profile_dir" >/dev/null 2>&1
    done
    ok "Certificado de la CA eliminado de los perfiles NSS (Firefox/Chrome)"
fi

# 8) Revertir las politicas de DoH escritas por el agente (mismas rutas que
# _write_doh_policy en smartmonitor-push.py)
for base in /etc/chromium/policies/managed /etc/opt/chrome/policies/managed \
            /etc/brave/policies/managed /opt/brave/policies/managed \
            /usr/lib/brave/policies/managed \
            /usr/lib/firefox/distribution /usr/lib64/firefox/distribution \
            /opt/firefox/distribution; do
    rm -f "$base/policies.json" 2>/dev/null
done
ok "Politicas de DNS-over-HTTPS de navegadores revertidas"

# 9) Quitar las reglas de firewall que bloqueaban los endpoints de DoH publicos
for ip in 1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 149.112.112.112; do
    iptables -D OUTPUT -d "$ip" -j DROP >/dev/null 2>&1
    nft delete rule inet filter output ip daddr "$ip" drop >/dev/null 2>&1
done
ok "Reglas de firewall de bloqueo de DoH eliminadas"

# 10) Borrar el script instalado
rm -f "$AGENT_DEST"
ok "Agente eliminado ($AGENT_DEST)"

echo ""
printf '%b\n' "${BOLD}${GREEN}Desinstalacion completada.${NC} El equipo deberia quedar como antes de instalar el agente."
echo "Si segundos despues sigues viendo el equipo en el panel de SmartMonitor, es normal:"
echo "el servidor lo marcara offline solo tras dejar de recibir reportes."
echo ""
exit 0

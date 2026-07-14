#!/bin/sh
# Arranca el panel en :8000 (HTTP, uso directo/LAN) y, si hay un certificado
# real montado (ej. Let's Encrypt para exponer el panel por dominio detrás de
# un proxy propio), también en :8443 con TLS. El puerto HTTPS es opcional: si
# no hay certificado, el contenedor sigue funcionando solo con :8000 como
# siempre.
set -e

CERT="${ADMIN_TLS_CERT:-/data/tls/fullchain.pem}"
KEY="${ADMIN_TLS_KEY:-/data/tls/privkey.pem}"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
    echo "[entrypoint] Certificado encontrado, panel también disponible en :8443 (HTTPS, solo loopback)"
    SMARTMONITOR_ROLE=web-only uvicorn main:app --host "${ADMIN_TLS_BIND:-127.0.0.1}" --port 8443 --ssl-certfile "$CERT" --ssl-keyfile "$KEY" &
fi

exec uvicorn main:app --host 0.0.0.0 --port 8000

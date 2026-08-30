import json, os, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from datetime import datetime

SENDER_DISPLAY_NAME = "SmartMonitor"

CONFIG_PATH = "/data/config.json"
ADMIN_PANEL_DOMAIN = os.getenv("ADMIN_PANEL_DOMAIN")

WELCOME_HTML_TEMPLATE = """<div style="font-family:'Segoe UI',Arial,sans-serif;max-width:560px;margin:0 auto;background:#eef1f6;padding:24px">
  <div style="border-radius:20px;overflow:hidden;box-shadow:0 8px 32px rgba(15,23,42,.12);background:#ffffff">
    <div style="text-align:center;padding:32px 28px 20px">
      <div style="display:inline-block;width:44px;height:44px;background:linear-gradient(135deg,#2563eb,#1d4ed8);border-radius:12px;text-align:center;line-height:44px;font-size:22px">🖥️</div>
      <div style="margin-top:10px;font-size:20px;font-weight:800;color:#0f172a">Smart<span style="color:#2563eb">Monitor</span></div>
      <div style="margin-top:2px;font-size:12px;color:#94a3b8">Sistema de Gestión de Equipos</div>
    </div>
    <div style="background:linear-gradient(135deg,#1e40af,#0f172a);border-radius:0 0 50% 50% / 0 0 28px 28px;padding:36px 28px 48px;text-align:center">
      <div style="display:inline-block;width:88px;height:88px;background:rgba(255,255,255,.14);border-radius:50%;line-height:88px;font-size:38px">🎉</div>
      <div style="margin-top:18px;color:#ffffff;font-size:22px;font-weight:700">¡Bienvenido a SmartMonitor!</div>
      <div style="margin-top:8px;color:#bfdbfe;font-size:13px;max-width:360px;margin-left:auto;margin-right:auto">Gracias por unirte. Tu cuenta ha sido creada exitosamente y ya puedes comenzar.</div>
    </div>
    <div style="padding:28px">
      <div style="font-size:15px;color:#0f172a">Hola, <span style="color:#2563eb;font-weight:700">{{nombre}}</span> 👋</div>
      <p style="margin:10px 0 20px;color:#475569;font-size:14px;line-height:1.5">Estamos emocionados de tenerte con nosotros. Con SmartMonitor podrás gestionar, monitorear y optimizar tus equipos de forma eficiente.</p>

      <div style="background:#f8fafc;border-radius:14px;padding:18px 20px;margin-bottom:18px">
        <div style="font-size:12px;font-weight:700;color:#0f172a;margin-bottom:10px">Tus datos de acceso</div>
        <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;font-size:13px">
          <tr><td style="padding:5px 0;color:#64748b;width:100px">Usuario</td><td style="padding:5px 0;color:#1e293b;font-weight:700">{{email}}</td></tr>
          <tr><td style="padding:5px 0;color:#64748b">Contraseña</td><td style="padding:5px 0;color:#1e293b;font-weight:700">{{password}}</td></tr>
        </table>
      </div>
      {{temp_notice}}

      <div style="background:#f8fafc;border-radius:14px;padding:20px;margin-top:18px">
        <div style="font-size:13px;font-weight:700;color:#0f172a;margin-bottom:14px">¿Qué puedes hacer ahora?</div>
        <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%"><tr>
          <td style="width:33%;text-align:center;vertical-align:top;padding:0 4px">
            <div style="width:40px;height:40px;background:#dbeafe;border-radius:10px;margin:0 auto;line-height:40px;font-size:18px">🖥️</div>
            <div style="margin-top:8px;font-size:12px;font-weight:700;color:#1e293b">Monitorea tus equipos</div>
            <div style="margin-top:2px;font-size:11px;color:#94a3b8">Visualiza el estado y rendimiento en tiempo real.</div>
          </td>
          <td style="width:33%;text-align:center;vertical-align:top;padding:0 4px">
            <div style="width:40px;height:40px;background:#dcfce7;border-radius:10px;margin:0 auto;line-height:40px;font-size:18px">🔔</div>
            <div style="margin-top:8px;font-size:12px;font-weight:700;color:#1e293b">Recibe alertas</div>
            <div style="margin-top:2px;font-size:11px;color:#94a3b8">Mantente informado sobre eventos importantes.</div>
          </td>
          <td style="width:33%;text-align:center;vertical-align:top;padding:0 4px">
            <div style="width:40px;height:40px;background:#ede9fe;border-radius:10px;margin:0 auto;line-height:40px;font-size:18px">📊</div>
            <div style="margin-top:8px;font-size:12px;font-weight:700;color:#1e293b">Toma mejores decisiones</div>
            <div style="margin-top:2px;font-size:11px;color:#94a3b8">Con datos claros para optimizar el rendimiento.</div>
          </td>
        </tr></table>
      </div>

      <div style="text-align:center;margin-top:22px">
        {{login_button}}
      </div>

      <div style="margin-top:20px;background:#f1f5f9;border-radius:12px;padding:14px 16px">
        <table role="presentation" cellpadding="0" cellspacing="0"><tr>
          <td style="width:36px;vertical-align:top">
            <div style="width:28px;height:28px;background:#dbeafe;border-radius:8px;text-align:center;line-height:28px;font-size:13px">🛡</div>
          </td>
          <td style="padding-left:10px">
            <div style="font-size:13px;font-weight:700;color:#1e293b">Tu seguridad es importante</div>
            <div style="margin-top:2px;font-size:12px;color:#64748b">Si no creaste esta cuenta, por favor ignora este correo o contáctanos inmediatamente.</div>
          </td>
        </tr></table>
      </div>
    </div>
    <div style="background:#f8fafc;padding:16px 28px;text-align:center;border-top:1px solid #e2e8f0">
      <div style="font-size:16px">🛡</div>
      <div style="margin-top:4px;font-size:11px;color:#94a3b8">SmartMonitor · Sistema de Gestión de Equipos</div>
      <div style="font-size:10px;color:#cbd5e1;margin-top:2px">© {{anio}} SmartMonitor. Todos los derechos reservados.</div>
    </div>
  </div>
</div>"""

DEFAULT_SUBJECT_TEMPLATE = "SmartMonitor — {{tipo}}: {{equipo}}"

DEFAULT_HTML_TEMPLATE = """<div style="font-family:'Segoe UI',Arial,sans-serif;max-width:560px;margin:0 auto;background:#eef1f6;padding:24px">
  <div style="border-radius:20px;overflow:hidden;box-shadow:0 8px 32px rgba(15,23,42,.12)">
    <div style="background:#0b1220;padding:28px 28px 32px">
      <table role="presentation" cellpadding="0" cellspacing="0"><tr>
        <td style="width:34px;height:34px;background:#2563eb;border-radius:9px;text-align:center;vertical-align:middle;font-size:17px">🖥️</td>
        <td style="padding-left:10px;color:#ffffff;font-size:17px;font-weight:700;vertical-align:middle">SmartMonitor</td>
      </tr></table>
      <div style="margin-top:18px">
        <span style="display:inline-block;background:#ef4444;color:#ffffff;font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:5px 12px;border-radius:999px">⚠ Alerta crítica</span>
      </div>
      <div style="margin-top:14px;color:#ffffff;font-size:22px;font-weight:700;line-height:1.3">Se detectó una condición crítica</div>
      <div style="margin-top:4px;color:#94a3b8;font-size:13px">en uno de tus equipos monitoreados.</div>
    </div>
    <div style="background:#ffffff;border-left:4px solid #ef4444;padding:24px 28px">
      <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse">
        <tr>
          <td style="width:48px;padding:10px 0;vertical-align:top">
            <div style="width:36px;height:36px;background:#dbeafe;border-radius:10px;text-align:center;line-height:36px;font-size:16px">🖥️</div>
          </td>
          <td style="padding:10px 0;border-bottom:1px solid #eef1f6">
            <div style="color:#64748b;font-size:12px">Equipo</div>
            <div style="color:#1e293b;font-size:15px;font-weight:700;margin-top:2px">{{equipo}}</div>
          </td>
        </tr>
        <tr>
          <td style="width:48px;padding:10px 0;vertical-align:top">
            <div style="width:36px;height:36px;background:#fee2e2;border-radius:10px;text-align:center;line-height:36px;font-size:16px">📈</div>
          </td>
          <td style="padding:10px 0;border-bottom:1px solid #eef1f6">
            <div style="color:#64748b;font-size:12px">Detalle</div>
            <div style="color:#1e293b;font-size:14px;margin-top:2px">{{detalle}}</div>
          </td>
        </tr>
        <tr>
          <td style="width:48px;padding:10px 0;vertical-align:top">
            <div style="width:36px;height:36px;background:#ede9fe;border-radius:10px;text-align:center;line-height:36px;font-size:16px">📅</div>
          </td>
          <td style="padding:10px 0">
            <div style="color:#64748b;font-size:12px">Fecha</div>
            <div style="color:#1e293b;font-size:14px;font-weight:600;margin-top:2px">{{fecha}}</div>
          </td>
        </tr>
      </table>
      <div style="margin-top:18px;background:#fef2f2;border-radius:12px;padding:14px 16px">
        <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%"><tr>
          <td style="vertical-align:middle">
            <div style="color:#1e293b;font-size:13px;font-weight:700">🛡 Notificación automática</div>
            <div style="color:#64748b;font-size:12px;margin-top:2px">Este es un mensaje automático generado por SmartMonitor.</div>
          </td>
          <td style="text-align:right;vertical-align:middle;white-space:nowrap">{{panel_button}}</td>
        </tr></table>
      </div>
    </div>
  </div>
  <div style="text-align:center;margin-top:20px;color:#94a3b8;font-size:12px">
    🛡 SmartMonitor · Sistema de Gestión de Equipos<br>
    <span style="font-size:11px">© {{anio}} SmartMonitor. Todos los derechos reservados.</span>
  </div>
</div>"""

def _read_config():
    try:
        return json.load(open(CONFIG_PATH))
    except Exception:
        return {}

def _render_template(template: str, context: dict) -> str:
    out = template
    for key, val in context.items():
        out = out.replace("{{" + key + "}}", str(val))
    return out

def send_email(subject: str, body: str, context: dict = None):
    """Envía un correo usando la configuración SMTP guardada. Devuelve (ok, error)."""
    cfg = _read_config()
    if not cfg.get("smtp_enabled", False):
        return False, "Notificaciones por correo desactivadas"

    host   = cfg.get("smtp_host", "")
    port   = int(cfg.get("smtp_port", 587) or 587)
    user   = cfg.get("smtp_username", "")
    pwd    = cfg.get("smtp_password", "")
    sender = cfg.get("smtp_from", "") or user
    to     = [a.strip() for a in cfg.get("smtp_to", "").split(",") if a.strip()]
    cc     = [a.strip() for a in cfg.get("smtp_cc", "").split(",") if a.strip()]
    bcc    = [a.strip() for a in cfg.get("smtp_bcc", "").split(",") if a.strip()]

    if not (host and sender and to):
        return False, "Servidor, remitente o destinatario no configurados"

    # Si el contexto trae agent_id (alertas de un equipo puntual), el boton
    # lleva directo al detalle de ESE equipo en vez de solo al panel general -
    # visto en produccion: el usuario esperaba llegar al equipo, no tener que
    # buscarlo de nuevo. agent_id no es una variable de plantilla, se
    # descarta del ctx final para no dejar "{{agent_id}}" sin reemplazar en
    # ningun lado.
    agent_id = (context or {}).pop("agent_id", None) if context else None
    panel_url = f"https://{ADMIN_PANEL_DOMAIN}" if ADMIN_PANEL_DOMAIN else ""
    if panel_url and agent_id:
        panel_url += f"/?agent={agent_id}"
    panel_button = (
        f'<a href="{panel_url}" style="display:inline-block;background:#2563eb;color:#ffffff;'
        f'text-decoration:none;font-weight:600;font-size:12px;padding:8px 14px;border-radius:8px;'
        f'white-space:nowrap">Ir a SmartMonitor →</a>'
        if panel_url else ""
    )
    ctx = {
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "anio": datetime.now().year,
        "panel_button": panel_button, **(context or {}),
    }
    subject_template = cfg.get("smtp_subject_template") or DEFAULT_SUBJECT_TEMPLATE
    rendered_subject = _render_template(subject_template, ctx) if context else subject
    ctx["titulo"] = rendered_subject
    html_template = cfg.get("smtp_html_template") or DEFAULT_HTML_TEMPLATE

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = rendered_subject
        msg["From"] = formataddr((SENDER_DISPLAY_NAME, sender))
        msg["To"] = ", ".join(to)
        if cc:
            msg["Cc"] = ", ".join(cc)
        msg.attach(MIMEText(body, "plain"))
        msg.attach(MIMEText(_render_template(html_template, ctx), "html"))

        all_recipients = to + cc + bcc  # Bcc no va en headers, solo en el sobre SMTP

        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls()
        try:
            if user and pwd:
                server.login(user, pwd)
            server.sendmail(sender, all_recipients, msg.as_string())
        finally:
            server.quit()
        return True, None
    except Exception as e:
        return False, str(e)

def send_email_silent(subject: str, body: str, context: dict = None):
    """Igual que send_email pero traga cualquier error (uso en alertas automáticas)."""
    try:
        send_email(subject, body, context)
    except Exception:
        pass


def send_welcome_email(name: str, email: str, password: str, is_temp: bool):
    """Correo de bienvenida al dar de alta un usuario con acceso a la consola.
    Reutiliza el mismo servidor SMTP configurado para alertas (host/puerto/
    credenciales/remitente), pero envía al correo del usuario nuevo en vez de
    la lista fija de destinatarios de alertas. Silencioso: nunca debe romper
    el alta del usuario si el correo no se pudo enviar."""
    cfg = _read_config()
    if not cfg.get("smtp_enabled", False):
        return False, "Notificaciones por correo desactivadas"

    host   = cfg.get("smtp_host", "")
    port   = int(cfg.get("smtp_port", 587) or 587)
    user   = cfg.get("smtp_username", "")
    pwd    = cfg.get("smtp_password", "")
    sender = cfg.get("smtp_from", "") or user
    if not (host and sender and email):
        return False, "Servidor o remitente no configurados"

    temp_notice = (
        '<div style="margin-top:14px;color:#b45309;background:#fffbeb;border:1px solid #fde68a;'
        'border-radius:10px;padding:10px 14px;font-size:12px">⚠ Deberás cambiar esta contraseña '
        'en tu primer inicio de sesión.</div>'
        if is_temp else ""
    )
    login_url = f"https://{ADMIN_PANEL_DOMAIN}" if ADMIN_PANEL_DOMAIN else ""
    login_button = (
        f'<a href="{login_url}" style="display:inline-block;background:#2563eb;color:#ffffff;'
        f'text-decoration:none;font-weight:700;font-size:14px;padding:12px 28px;border-radius:10px">'
        f'Ir a SmartMonitor →</a>'
        if login_url else ""
    )
    ctx = {
        "nombre": name, "email": email, "password": password, "anio": datetime.now().year,
        "temp_notice": temp_notice, "login_button": login_button,
    }
    html = _render_template(WELCOME_HTML_TEMPLATE, ctx)
    text_lines = [
        f"Hola {name},", "",
        "Se creó una cuenta de acceso a la consola de SmartMonitor a tu nombre.",
        f"Usuario: {email}", f"Contraseña: {password}",
    ]
    if is_temp:
        text_lines.append("Deberás cambiarla en tu primer inicio de sesión.")
    if login_url:
        text_lines += ["", login_url]
    text = "\n".join(text_lines)

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Bienvenido a SmartMonitor — datos de acceso"
        msg["From"] = formataddr((SENDER_DISPLAY_NAME, sender))
        msg["To"] = email
        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls()
        try:
            if user and pwd:
                server.login(user, pwd)
            server.sendmail(sender, [email], msg.as_string())
        finally:
            server.quit()
        return True, None
    except Exception as e:
        return False, str(e)


def send_welcome_email_silent(name: str, email: str, password: str, is_temp: bool):
    try:
        send_welcome_email(name, email, password, is_temp)
    except Exception:
        pass


RESET_HTML_TEMPLATE = """<div style="font-family:'Segoe UI',Arial,sans-serif;max-width:560px;margin:0 auto;background:#eef1f6;padding:24px">
  <div style="border-radius:20px;overflow:hidden;box-shadow:0 8px 32px rgba(15,23,42,.12);background:#ffffff">
    <div style="text-align:center;padding:32px 28px 20px">
      <div style="display:inline-block;width:44px;height:44px;background:linear-gradient(135deg,#2563eb,#1d4ed8);border-radius:12px;text-align:center;line-height:44px;font-size:22px">🖥️</div>
      <div style="margin-top:10px;font-size:20px;font-weight:800;color:#0f172a">Smart<span style="color:#2563eb">Monitor</span></div>
      <div style="margin-top:2px;font-size:12px;color:#94a3b8">Sistema de Gestión de Equipos</div>
    </div>
    <div style="background:linear-gradient(135deg,#1e40af,#0f172a);border-radius:0 0 50% 50% / 0 0 28px 28px;padding:36px 28px 48px;text-align:center">
      <div style="display:inline-block;width:88px;height:88px;background:rgba(255,255,255,.14);border-radius:50%;line-height:88px;font-size:38px">🔐</div>
      <div style="margin-top:18px;color:#ffffff;font-size:22px;font-weight:700">Recuperación de contraseña</div>
      <div style="margin-top:8px;color:#bfdbfe;font-size:13px;max-width:360px;margin-left:auto;margin-right:auto">Hemos recibido una solicitud para restablecer la contraseña de tu cuenta en SmartMonitor.</div>
    </div>
    <div style="padding:28px">
      <div style="font-size:15px;color:#0f172a">Hola, <span style="color:#2563eb;font-weight:700">{{nombre}}</span></div>
      <p style="margin:10px 0 22px;color:#475569;font-size:14px;line-height:1.5">Si fuiste tú quien solicitó restablecer tu contraseña, haz clic en el botón para crear una nueva. Este enlace vence en {{expiry_minutes}} minutos.</p>

      <div style="text-align:center">
        <a href="{{reset_url}}" style="display:inline-block;background:#2563eb;color:#ffffff;text-decoration:none;font-weight:700;font-size:14px;padding:12px 28px;border-radius:10px">🔒 Restablecer contraseña</a>
      </div>

      <div style="text-align:center;margin:20px 0;color:#94a3b8;font-size:12px">o copia y pega este enlace en tu navegador</div>
      <div style="background:#f8fafc;border-radius:10px;padding:12px 16px;font-size:12px;color:#475569;word-break:break-all">{{reset_url}}</div>

      <div style="margin-top:20px;background:#f1f5f9;border-radius:12px;padding:14px 16px">
        <table role="presentation" cellpadding="0" cellspacing="0"><tr>
          <td style="width:36px;vertical-align:top">
            <div style="width:28px;height:28px;background:#dbeafe;border-radius:8px;text-align:center;line-height:28px;font-size:13px">ℹ️</div>
          </td>
          <td style="padding-left:10px">
            <div style="font-size:13px;font-weight:700;color:#1e293b">¿No solicitaste este cambio?</div>
            <div style="margin-top:2px;font-size:12px;color:#64748b">Si no solicitaste restablecer tu contraseña, puedes ignorar este correo. Tu contraseña actual seguirá siendo válida y tu cuenta está segura.</div>
          </td>
        </tr></table>
      </div>
    </div>
    <div style="background:#f8fafc;padding:16px 28px;text-align:center;border-top:1px solid #e2e8f0">
      <div style="font-size:16px">🛡</div>
      <div style="margin-top:4px;font-size:11px;color:#94a3b8">SmartMonitor · Sistema de Gestión de Equipos</div>
      <div style="font-size:10px;color:#cbd5e1;margin-top:2px">© {{anio}} SmartMonitor. Todos los derechos reservados.</div>
    </div>
  </div>
</div>"""

_RESET_TOKEN_EXPIRY_MINUTES = 30

def send_password_reset_email(name: str, email: str, token: str):
    """Correo de 'olvidé mi contraseña' - mismo servidor SMTP que el resto,
    enviado al correo del usuario que lo pidió, nunca a la lista fija de
    destinatarios de alertas."""
    cfg = _read_config()
    if not cfg.get("smtp_enabled", False):
        return False, "Notificaciones por correo desactivadas"

    host   = cfg.get("smtp_host", "")
    port   = int(cfg.get("smtp_port", 587) or 587)
    user   = cfg.get("smtp_username", "")
    pwd    = cfg.get("smtp_password", "")
    sender = cfg.get("smtp_from", "") or user
    if not (host and sender and email):
        return False, "Servidor o remitente no configurados"
    if not ADMIN_PANEL_DOMAIN:
        return False, "Dominio del panel no configurado (ADMIN_PANEL_DOMAIN)"

    reset_url = f"https://{ADMIN_PANEL_DOMAIN}/?reset={token}"
    ctx = {
        "nombre": name, "reset_url": reset_url, "expiry_minutes": _RESET_TOKEN_EXPIRY_MINUTES,
        "anio": datetime.now().year,
    }
    html = _render_template(RESET_HTML_TEMPLATE, ctx)
    text = (
        f"Hola {name},\n\nPediste restablecer tu contraseña de SmartMonitor. "
        f"Este enlace vence en {_RESET_TOKEN_EXPIRY_MINUTES} minutos:\n\n{reset_url}\n\n"
        "Si no pediste esto, podés ignorar este correo."
    )

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "SmartMonitor — Restablecer contraseña"
        msg["From"] = formataddr((SENDER_DISPLAY_NAME, sender))
        msg["To"] = email
        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls()
        try:
            if user and pwd:
                server.login(user, pwd)
            server.sendmail(sender, [email], msg.as_string())
        finally:
            server.quit()
        return True, None
    except Exception as e:
        return False, str(e)


def send_password_reset_email_silent(name: str, email: str, token: str):
    try:
        send_password_reset_email(name, email, token)
    except Exception:
        pass

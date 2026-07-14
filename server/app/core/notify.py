import json, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

CONFIG_PATH = "/data/config.json"

DEFAULT_SUBJECT_TEMPLATE = "SmartMonitor — {{tipo}}: {{equipo}}"

DEFAULT_HTML_TEMPLATE = """<div style="font-family:'Segoe UI',Arial,sans-serif;max-width:520px;margin:0 auto;background:#f1f5f9;padding:24px">
  <div style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
    <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);padding:24px 28px">
      <div style="color:#dbeafe;font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;margin-bottom:4px">SmartMonitor</div>
      <div style="color:#ffffff;font-size:20px;font-weight:700">{{tipo}}</div>
    </div>
    <div style="padding:28px">
      <table style="width:100%;border-collapse:collapse;font-size:14px;color:#1e293b">
        <tr><td style="padding:8px 0;color:#64748b;width:110px;vertical-align:top">Equipo</td><td style="padding:8px 0;font-weight:600">{{equipo}}</td></tr>
        <tr><td style="padding:8px 0;color:#64748b;vertical-align:top">Detalle</td><td style="padding:8px 0">{{detalle}}</td></tr>
        <tr><td style="padding:8px 0;color:#64748b;vertical-align:top">Fecha</td><td style="padding:8px 0">{{fecha}}</td></tr>
      </table>
    </div>
    <div style="background:#f8fafc;padding:14px 28px;color:#94a3b8;font-size:11px;border-top:1px solid #e2e8f0">Notificación automática · SmartMonitor</div>
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

    ctx = {"fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), **(context or {})}
    subject_template = cfg.get("smtp_subject_template") or DEFAULT_SUBJECT_TEMPLATE
    rendered_subject = _render_template(subject_template, ctx) if context else subject
    ctx["titulo"] = rendered_subject
    html_template = cfg.get("smtp_html_template") or DEFAULT_HTML_TEMPLATE

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = rendered_subject
        msg["From"] = sender
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

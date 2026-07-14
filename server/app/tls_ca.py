"""
CA propia para la página de bloqueo por HTTPS.

Los navegadores de hoy usan HTTPS por defecto (muchos dominios como YouTube o
Google llevan HSTS "preload", que impide siquiera mostrar la opción de
"continuar de todos modos" ante un certificado no confiable). Para que la
página de bloqueo se vea también en esos sitios, el servidor genera una CA
raíz propia una sola vez y firma al vuelo un certificado por cada dominio que
un cliente intenta visitar (identificado por SNI). Los equipos deben confiar
en esta CA — los instaladores de agente (Linux/Windows) la agregan al almacén
de certificados del sistema al desplegar el agente.
"""
import os
import ssl
import threading
import datetime
import hashlib
import re

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CA_DIR    = "/data/ca"
CA_KEY    = f"{CA_DIR}/ca_key.pem"
CA_CERT   = f"{CA_DIR}/ca_cert.pem"
HOSTS_DIR = f"{CA_DIR}/hosts"

_DEFAULT_HOST = "block.smartmonitor.local"
_HOSTNAME_RE  = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$")
_MAX_CACHE    = 1000  # tope de contextos SSL en memoria (evita crecimiento sin límite)

_lock      = threading.Lock()
_ctx_cache = {}
_ca_key    = None
_ca_cert   = None


def _gen_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def ensure_ca():
    """Crea la CA (clave + certificado raíz) si no existe todavía. Idempotente
    — se llama en cada arranque del server; si ya existe, solo la carga."""
    global _ca_key, _ca_cert
    os.makedirs(CA_DIR, exist_ok=True)
    os.makedirs(HOSTS_DIR, exist_ok=True)

    if os.path.exists(CA_KEY) and os.path.exists(CA_CERT):
        _ca_key  = serialization.load_pem_private_key(open(CA_KEY, "rb").read(), password=None)
        _ca_cert = x509.load_pem_x509_certificate(open(CA_CERT, "rb").read())
        return

    key  = _gen_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "SmartMonitor Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SmartMonitor"),
    ])
    now  = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(CA_KEY, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    os.chmod(CA_KEY, 0o600)
    with open(CA_CERT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    _ca_key, _ca_cert = key, cert
    print(f"[TLS-CA] CA generada en {CA_DIR}")


def _issue_leaf_cert(hostname: str):
    key  = _gen_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64])])
    now  = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(_ca_key, hashes.SHA256())
    )
    return key, cert


def _safe_hostname(hostname: str) -> str:
    """Valida que parezca un nombre DNS razonable; si no, usa el genérico
    (evita emitir certificados para SNI basura enviado por escáneres/bots)."""
    if hostname and len(hostname) <= 253 and _HOSTNAME_RE.match(hostname):
        return hostname.lower()
    return _DEFAULT_HOST


def get_context_for_host(hostname: str) -> ssl.SSLContext:
    """SSLContext con un certificado válido (firmado por nuestra CA) para
    `hostname`. Se genera y cachea en disco (por hash, evita cualquier
    problema de path traversal) + en memoria la primera vez que se pide."""
    hostname = _safe_hostname(hostname)
    with _lock:
        ctx = _ctx_cache.get(hostname)
        if ctx:
            return ctx

        if len(_ctx_cache) >= _MAX_CACHE:
            _ctx_cache.clear()  # tope simple: si se llena, se limpia (se regeneran los frecuentes)

        digest    = hashlib.sha256(hostname.encode()).hexdigest()[:32]
        host_dir  = f"{HOSTS_DIR}/{digest}"
        key_path  = f"{host_dir}/key.pem"
        cert_path = f"{host_dir}/cert.pem"

        if not (os.path.exists(key_path) and os.path.exists(cert_path)):
            os.makedirs(host_dir, exist_ok=True)
            key, cert = _issue_leaf_cert(hostname)
            with open(key_path, "wb") as f:
                f.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ))
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

        new_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        new_ctx.load_cert_chain(cert_path, key_path)
        _ctx_cache[hostname] = new_ctx
        return new_ctx


def ca_cert_pem() -> bytes:
    return open(CA_CERT, "rb").read()

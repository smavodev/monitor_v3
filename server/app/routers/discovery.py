from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc
from core.db import get_db
from core.permissions import require_permission
from models.models import Agent, Metric
import subprocess, ipaddress, concurrent.futures, socket, time, fcntl

router = APIRouter(prefix="/api/discovery", tags=["discovery"])

def _ping(ip: str):
    t0 = time.time()
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                           capture_output=True, timeout=3)
        if r.returncode == 0:
            latency = round((time.time() - t0) * 1000, 1)
            hostname = ""
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
            return {"ip": ip, "alive": True, "latency_ms": latency, "hostname": hostname}
    except Exception:
        pass
    return None

def _local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return None

@router.get("/local-subnet")
def local_subnet(user=Depends(require_permission("discovery", "view"))):
    return {"subnet": _local_subnet()}

@router.post("/scan")
def scan(data: dict, user=Depends(require_permission("discovery", "edit")), db: Session = Depends(get_db)):
    subnet = data.get("subnet", "")
    results = []
    try:
        if "/" in subnet:
            network = ipaddress.IPv4Network(subnet, strict=False)
            ips = [str(ip) for ip in network.hosts()]
        elif "-" in subnet:
            parts = subnet.split("-")
            start = ipaddress.IPv4Address(parts[0].strip())
            end   = ipaddress.IPv4Address(parts[1].strip())
            ips = [str(ipaddress.IPv4Address(i))
                   for i in range(int(start), int(end) + 1)]
        else:
            ips = [subnet.strip()]

        ips = ips[:254]
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(_ping, ip): ip for ip in ips}
            for f in concurrent.futures.as_completed(futures):
                r = f.result()
                if r:
                    results.append(r)
    except Exception as e:
        return {"error": str(e), "results": []}

    # Cruzar con agentes registrados en la DB
    agents = db.query(Agent).all()
    agents_by_ip = {a.ip: a for a in agents if a.ip}
    agents_by_hostname = {a.hostname: a for a in agents}

    for host in results:
        agent = agents_by_ip.get(host["ip"])
        if not agent and host["hostname"]:
            agent = agents_by_hostname.get(host["hostname"])

        if agent:
            last = db.query(Metric).filter(Metric.agent_id == agent.id)\
                     .order_by(desc(Metric.timestamp)).first()
            host["agent"] = {
                "id":           agent.id,
                "hostname":     agent.hostname,
                "display_name": agent.display_name or agent.hostname,
                "status":       agent.status,
                "os":           agent.os,
                "os_version":   agent.os_version,
                "cpu_model":    agent.cpu_model,
                "cpu_cores":    agent.cpu_cores,
                "ram_total_gb": agent.ram_total_gb,
                "manufacturer": agent.manufacturer,
                "model":        agent.model,
                "cpu_percent":  last.cpu_percent  if last else None,
                "ram_percent":  last.ram_percent  if last else None,
                "disk_percent": last.disk_percent if last else None,
                "cpu_temp":     last.cpu_temp     if last else None,
            }
        else:
            host["agent"] = None

    results.sort(key=lambda x: list(map(int, x["ip"].split("."))))
    return {"total": len(results), "results": results}

"""Enrichissement maximal des infos sur le(s) processus derrière un port.

Cible : Linux, macOS, Windows. Détecte Docker, Podman, Kubernetes, LXC,
systemd units, snap, flatpak. Renvoie un dict riche.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
from functools import lru_cache
from typing import Optional


PLAT = platform.system().lower()


def _run(cmd: list[str], timeout: float = 3.0) -> str:
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, text=True, errors="ignore", timeout=timeout
        )
    except Exception:
        return ""


# --- Listening sockets cache ----------------------------------------------- #

@lru_cache(maxsize=1)
def _ss_snapshot() -> dict:
    """Snapshot des sockets en écoute (Linux/macOS via ss/lsof, Windows via netstat).
    Retourne {(proto, port): [{'pid', 'comm', 'addr', 'user'}]}.
    """
    res: dict[tuple, list] = {}
    if "linux" in PLAT:
        for flag, proto in (("-tlnpH", "tcp"), ("-ulnpH", "udp")):
            out = _run(["ss", flag])
            for line in out.splitlines():
                # ex: LISTEN 0  128  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=812,fd=3))
                cols = line.split()
                if len(cols) < 5:
                    continue
                local = cols[3] if proto == "tcp" else cols[4]
                m_port = re.search(r":(\d+)$", local)
                if not m_port:
                    continue
                port = int(m_port.group(1))
                users = []
                for um in re.finditer(r'\(\("([^"]+)",pid=(\d+),fd=\d+\)', line):
                    users.append({"comm": um.group(1), "pid": int(um.group(2)), "addr": local})
                if not users:
                    users = [{"comm": None, "pid": None, "addr": local}]
                res.setdefault((proto, port), []).extend(users)
    elif "darwin" in PLAT:
        out = _run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            comm, pid, user, _, _, _, _, _, name = parts[:9]
            m = re.search(r":(\d+)$", name)
            if not m:
                continue
            port = int(m.group(1))
            try:
                res.setdefault(("tcp", port), []).append(
                    {"comm": comm, "pid": int(pid), "addr": name, "user": user}
                )
            except ValueError:
                pass
    elif "windows" in PLAT:
        out = _run(["netstat", "-ano", "-p", "TCP"])
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5 or not parts[-1].isdigit():
                continue
            local = parts[1]
            m = re.search(r":(\d+)$", local)
            if not m:
                continue
            res.setdefault(("tcp", int(m.group(1))), []).append(
                {"comm": None, "pid": int(parts[-1]), "addr": local}
            )
    return res


def refresh_listening_cache():
    _ss_snapshot.cache_clear()


# --- Détails processus ----------------------------------------------------- #

def _read_proc(pid: int, file: str) -> str:
    try:
        with open(f"/proc/{pid}/{file}", "rb") as f:
            return f.read().decode("utf-8", errors="ignore")
    except OSError:
        return ""


def _process_info_linux(pid: int) -> dict:
    info = {"pid": pid}
    cmdline = _read_proc(pid, "cmdline").replace("\x00", " ").strip()
    info["cmdline"] = cmdline
    try:
        info["exe"] = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        info["exe"] = None
    try:
        info["cwd"] = os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        info["cwd"] = None

    status = _read_proc(pid, "status")
    for line in status.splitlines():
        if line.startswith("Name:"):
            info["name"] = line.split(":", 1)[1].strip()
        elif line.startswith("Uid:"):
            uid = line.split()[1]
            info["uid"] = int(uid)
            try:
                import pwd
                info["user"] = pwd.getpwuid(int(uid)).pw_name
            except Exception:
                info["user"] = uid
        elif line.startswith("PPid:"):
            info["ppid"] = int(line.split()[1])
        elif line.startswith("State:"):
            info["state"] = line.split(":", 1)[1].strip()

    # Open files count
    try:
        info["fds"] = len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        pass

    # Container detection
    info["container"] = _detect_container_linux(pid)

    # systemd unit
    info["systemd_unit"] = _systemd_unit_for_pid(pid)

    # snap / flatpak
    if cmdline.startswith("/snap/") or "/snap/" in (info.get("exe") or ""):
        info["packaging"] = "snap"
    elif "/var/lib/flatpak/" in cmdline or "/.local/share/flatpak/" in cmdline:
        info["packaging"] = "flatpak"
    elif "/app/" in (info.get("exe") or "") and os.path.exists("/.flatpak-info"):
        info["packaging"] = "flatpak"

    return info


def _detect_container_linux(pid: int) -> Optional[dict]:
    cg = _read_proc(pid, "cgroup")
    if not cg:
        return None
    for line in cg.splitlines():
        m = re.search(r"docker[/-]([0-9a-f]{12,64})", line)
        if m:
            cid = m.group(1)[:12]
            info = {"runtime": "docker", "id": cid}
            info.update(_docker_inspect(cid) or {})
            return info
        if "kubepods" in line:
            m2 = re.search(r"kubepods.*?/([0-9a-f]{12,64})", line)
            return {"runtime": "kubernetes", "id": m2.group(1)[:12] if m2 else None}
        m = re.search(r"libpod[/-]([0-9a-f]{12,64})", line)
        if m:
            return {"runtime": "podman", "id": m.group(1)[:12]}
        if "/lxc/" in line:
            m2 = re.search(r"/lxc/([^/]+)", line)
            return {"runtime": "lxc", "id": m2.group(1) if m2 else None}
        if "containerd" in line:
            m2 = re.search(r"cri-containerd-([0-9a-f]{12,64})", line)
            return {"runtime": "containerd", "id": m2.group(1)[:12] if m2 else None}
    return None


def _systemd_unit_for_pid(pid: int) -> Optional[str]:
    if not shutil.which("systemctl"):
        return None
    out = _run(["systemctl", "status", str(pid), "--no-pager"], timeout=1.5)
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("●") or line.startswith("○"):
            parts = line.split(None, 2)
            if len(parts) >= 2 and parts[1].endswith((".service", ".socket", ".scope")):
                return parts[1]
    return None


def _process_info_psutil(pid: int) -> dict:
    try:
        import psutil
    except ImportError:
        return {"pid": pid}
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            info = {
                "pid": pid,
                "name": p.name(),
                "exe": p.exe() if hasattr(p, "exe") else None,
                "cmdline": " ".join(p.cmdline()),
                "user": p.username(),
                "ppid": p.ppid(),
                "state": p.status(),
                "create_time": int(p.create_time()),
                "cpu_percent": p.cpu_percent(interval=0.0),
                "memory_mb": round(p.memory_info().rss / 1024 / 1024, 1),
            }
            try:
                info["cwd"] = p.cwd()
            except Exception:
                pass
            try:
                info["fds"] = p.num_fds() if hasattr(p, "num_fds") else p.num_handles()
            except Exception:
                pass
            try:
                info["connections"] = len(p.net_connections(kind="inet"))
            except Exception:
                pass
        return info
    except Exception:
        return {"pid": pid}


def process_info(pid: int) -> dict:
    """Renvoie le maximum d'info dispo sur le PID, multi-plateforme."""
    if "linux" in PLAT:
        info = _process_info_linux(pid)
        ps = _process_info_psutil(pid)
        for k in ("cpu_percent", "memory_mb", "create_time", "connections"):
            if k in ps: info[k] = ps[k]
        return info

    info = _process_info_psutil(pid)

    # macOS : tente une détection container (Docker Desktop a un host dédié,
    # mais si on a docker CLI on peut retrouver via docker_container_for_port).
    if "darwin" in PLAT and shutil.which("docker"):
        # Pas de cgroup côté host macOS, on laisse le fallback docker_container_for_port
        # faire le boulot via enrich_port().
        pass

    # Windows : ajoute le service Windows lié au PID (sc.exe / tasklist /SVC)
    if "windows" in PLAT:
        info["windows_service"] = _windows_service_for_pid(pid)

    return info


def _windows_service_for_pid(pid: int) -> Optional[str]:
    if not shutil.which("tasklist"):
        return None
    out = _run(["tasklist", "/SVC", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], timeout=2)
    # ex: "svchost.exe","1234","RpcSs,EventSystem"
    if not out: return None
    parts = [p.strip('"') for p in out.strip().split(",")]
    if len(parts) >= 3 and parts[2] not in ("N/A", ""):
        return parts[2]
    return None


# --- Container lookup même quand le proc est docker-proxy ------------------ #

@lru_cache(maxsize=1)
def _docker_ps_cache():
    if not shutil.which("docker"):
        return []
    out = _run(["docker", "ps", "--no-trunc",
                "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}\t{{.Command}}"], timeout=3)
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        rows.append({
            "id": parts[0][:12],
            "name": parts[1],
            "image": parts[2],
            "ports": parts[3],
            "status": parts[4] if len(parts) > 4 else "",
            "command": parts[5].strip('"') if len(parts) > 5 else "",
        })
    return rows


def _docker_inspect(cid: str) -> Optional[dict]:
    if not shutil.which("docker"):
        return None
    out = _run(["docker", "inspect", "--format",
                "{{.Name}}|{{.Config.Image}}|{{.State.Status}}|{{.Config.Cmd}}",
                cid], timeout=2)
    if not out:
        return None
    parts = out.strip().split("|")
    if len(parts) < 3:
        return None
    return {
        "name": parts[0].lstrip("/"),
        "image": parts[1],
        "status": parts[2],
        "command": parts[3] if len(parts) > 3 else "",
    }


def docker_container_for_port(port: int) -> Optional[dict]:
    """Trouve un container Docker qui expose ce port côté host (mappage NAT)."""
    needle = f":{port}->"
    for row in _docker_ps_cache():
        if needle in row["ports"]:
            return row
    return None


def refresh_docker_cache():
    _docker_ps_cache.cache_clear()


# --- API publique : tout-en-un --------------------------------------------- #

def enrich_port(port: int, proto: str = "tcp") -> dict:
    """Retourne toutes les infos disponibles pour un port en écoute local."""
    snap = _ss_snapshot()
    entries = snap.get((proto, port), [])
    out: dict = {"port": port, "proto": proto, "processes": [], "container": None,
                 "listen_addr": None}

    for entry in entries:
        if entry.get("pid"):
            out["processes"].append(process_info(entry["pid"]))
            if not out["listen_addr"] and entry.get("addr"):
                out["listen_addr"] = entry["addr"]

    # Container côté processus
    for proc in out["processes"]:
        if proc.get("container"):
            out["container"] = proc["container"]
            break

    # Cas "docker-proxy" / port forwardé : pas de container dans le cgroup du proxy
    if not out["container"]:
        names = {(p.get("name") or "").lower() for p in out["processes"]}
        if any(n in names for n in ("docker-proxy", "dockerd", "containerd")) or not out["processes"]:
            cdata = docker_container_for_port(port)
            if cdata:
                out["container"] = {"runtime": "docker", **cdata}

    # Summary string
    out["summary"] = _summarize(out)
    return out


def _summarize(d: dict) -> str:
    if d.get("container"):
        c = d["container"]
        bits = [f"🐳 {c.get('runtime','container')}"]
        if c.get("name"): bits.append(c["name"])
        if c.get("image"): bits.append(f"({c['image']})")
        return " ".join(bits)
    if d["processes"]:
        p = d["processes"][0]
        bits = [p.get("name") or p.get("cmdline", "?")[:40]]
        if p.get("user"): bits.append(f"[{p['user']}]")
        if p.get("systemd_unit"): bits.append(f"⚙ {p['systemd_unit']}")
        if p.get("windows_service"): bits.append(f"⚙ {p['windows_service']}")
        if p.get("packaging"): bits.append(f"📦 {p['packaging']}")
        return " ".join(bits)
    return "inconnu (PID non visible — relancer en root ?)"

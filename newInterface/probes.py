"""Sondes intelligentes pour identifier un service derrière un port ouvert.

Chaque sonde envoie un payload adapté au protocole attendu et lit la réponse.
Renvoie un dict { service, product, version, banner, tls } — best-effort.
"""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional


# --- Sondes par port -------------------------------------------------------- #

HTTP_PORTS = {80, 81, 591, 2080, 2480, 3000, 4567, 5000, 5104, 5800, 7001,
              7080, 8000, 8008, 8080, 8081, 8088, 8090, 8888, 9000, 9080}
HTTPS_PORTS = {443, 465, 563, 636, 853, 989, 990, 993, 994, 995, 2376,
               4443, 5061, 5986, 6443, 8443, 9443}

HTTP_PROBE = (
    b"GET / HTTP/1.0\r\n"
    b"Host: %s\r\n"
    b"User-Agent: scan-port/1.0\r\n"
    b"Accept: */*\r\n\r\n"
)

# Services qui parlent en premier (juste écouter)
PASSIVE_BANNER_PORTS = {21, 22, 25, 110, 143, 220, 587, 2525, 3306, 5432, 6667}

PROBE_MAP: dict[int, bytes] = {
    23:    b"\r\n",                  # telnet
    25:    b"EHLO scan-port.local\r\n",
    110:   b"CAPA\r\n",
    143:   b"a01 CAPABILITY\r\n",
    389:   b"",                       # LDAP : on lit
    587:   b"EHLO scan-port.local\r\n",
    631:   b"GET / HTTP/1.0\r\n\r\n",  # CUPS
    1080:  b"\x05\x01\x00",            # SOCKS5 hello
    3306:  b"",                        # MySQL : serveur parle
    5432:  b"",                        # PostgreSQL : silencieux sans handshake
    5900:  b"",                        # VNC : serveur envoie "RFB 003.008"
    6379:  b"*1\r\n$4\r\nPING\r\n",    # Redis
    9200:  b"GET / HTTP/1.0\r\n\r\n",  # Elasticsearch
    11211: b"version\r\n",             # Memcached
    11434: b"GET /api/tags HTTP/1.0\r\n\r\n",  # Ollama
    27017: b"",                        # MongoDB
}


# --- Détecteurs de bannière ------------------------------------------------- #

_RE_HTTP_STATUS = re.compile(rb"^HTTP/\d\.\d\s+(\d+)\s+([^\r\n]+)")
_RE_HTTP_SERVER = re.compile(rb"^Server:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
_RE_HTTP_TITLE = re.compile(rb"<title[^>]*>([^<]{1,120})</title>", re.IGNORECASE)
_RE_SSH = re.compile(rb"^SSH-(\d\.\d)-([^\r\n ]+)")
_RE_SMTP = re.compile(rb"^220[ -]([^\r\n]+)")
_RE_FTP = re.compile(rb"^220[ -]([^\r\n]+)")
_RE_REDIS = re.compile(rb"\+PONG|-NOAUTH|-DENIED")
_RE_MYSQL_VER = re.compile(rb"\x00\x00\x00\x00\x0a([0-9][^\x00]{0,40})")


def _parse_mysql_handshake(raw: bytes) -> Optional[dict]:
    """Parse un Initial Handshake Packet MySQL (protocole v10)."""
    if len(raw) < 16 or raw[4:5] != b"\x0a":
        return None
    try:
        out: dict = {"protocol": 10}
        i = 5
        end = raw.find(b"\x00", i)
        if end < 0: return None
        out["version"] = raw[i:end].decode(errors="ignore")
        i = end + 1
        out["connection_id"] = int.from_bytes(raw[i:i+4], "little")
        i += 4
        i += 8  # auth-plugin-data part 1
        if i >= len(raw): return out
        i += 1  # filler
        cap_low = int.from_bytes(raw[i:i+2], "little"); i += 2
        if i + 1 < len(raw):
            out["charset"] = raw[i]; i += 1
            status = int.from_bytes(raw[i:i+2], "little"); i += 2
            cap_high = int.from_bytes(raw[i:i+2], "little"); i += 2
            caps = cap_low | (cap_high << 16)
            out["status_flags"] = status
            flags = []
            if caps & 0x00000200: flags.append("SSL")
            if caps & 0x00080000: flags.append("PLUGIN_AUTH")
            if caps & 0x00800000: flags.append("MULTI_STATEMENTS")
            if caps & 0x00200000: flags.append("CONNECT_WITH_DB")
            if flags: out["capabilities"] = ", ".join(flags)
            auth_len = raw[i]; i += 1
            i += 10  # reserved
            i += max(13, auth_len - 8)
            plug_end = raw.find(b"\x00", i)
            if plug_end > 0:
                out["auth_plugin"] = raw[i:plug_end].decode(errors="ignore")
        out["product"] = f"MySQL {out['version']}"
        return out
    except Exception:
        return None


def _parse_banner(port: int, raw: bytes) -> dict:
    info: dict = {"banner": raw[:400].decode(errors="ignore").strip()}
    if not raw:
        return info

    # HTTP family
    m = _RE_HTTP_STATUS.search(raw)
    if m:
        info["service"] = "http"
        info["http_status"] = f"{m.group(1).decode()} {m.group(2).decode(errors='ignore')}"
        s = _RE_HTTP_SERVER.search(raw)
        if s:
            info["product"] = s.group(1).decode(errors="ignore").strip()
        t = _RE_HTTP_TITLE.search(raw)
        if t:
            info["title"] = t.group(1).decode(errors="ignore").strip()
        return info

    m = _RE_SSH.search(raw)
    if m:
        info["service"] = "ssh"
        info["version"] = m.group(1).decode()
        info["product"] = m.group(2).decode(errors="ignore")
        return info

    if port in (25, 587, 465):
        m = _RE_SMTP.search(raw)
        if m:
            info["service"] = "smtp"
            info["product"] = m.group(1).decode(errors="ignore").strip()
            return info

    if port == 21:
        m = _RE_FTP.search(raw)
        if m:
            info["service"] = "ftp"
            info["product"] = m.group(1).decode(errors="ignore").strip()
            return info

    if port == 6379 and _RE_REDIS.search(raw):
        info["service"] = "redis"
        return info

    if port == 3306 or (len(raw) > 5 and raw[4:5] == b"\x0a"):
        parsed = _parse_mysql_handshake(raw)
        if parsed:
            info["service"] = "mysql"
            info.update(parsed)
            # Remplace la bannière binaire par une version lisible
            info["banner"] = (
                f"MySQL {parsed.get('version','?')} "
                f"(protocole {parsed.get('protocol','?')}, "
                f"auth={parsed.get('auth_plugin','?')})"
            )
            return info

    if port == 5432 and b"FATAL" in raw or b"SCRAM" in raw:
        info["service"] = "postgresql"
        return info

    if port == 11211 and raw.startswith(b"VERSION"):
        info["service"] = "memcached"
        info["product"] = raw.decode(errors="ignore").strip()
        return info

    if port == 5900 and raw.startswith(b"RFB"):
        info["service"] = "vnc"
        info["product"] = raw[:12].decode(errors="ignore").strip()
        return info

    return info


# --- TLS handshake & certificat -------------------------------------------- #

async def grab_tls_cert(host: str, port: int, timeout: float = 3.0) -> Optional[dict]:
    """Tente un handshake TLS et renvoie infos certificat."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=timeout,
        )
    except Exception:
        return None
    try:
        ssl_obj: ssl.SSLObject = writer.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert() if ssl_obj else None
        proto = ssl_obj.version() if ssl_obj else None
        if not cert:
            # binaire seulement
            return {"tls_version": proto}
        subj = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        san = [v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"]
        not_after = cert.get("notAfter")
        days_left = None
        if not_after:
            try:
                dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (dt - datetime.now(timezone.utc)).days
            except Exception:
                pass
        return {
            "tls_version": proto,
            "cn": subj.get("commonName"),
            "issuer": issuer.get("commonName") or issuer.get("organizationName"),
            "san": san[:6],
            "not_after": not_after,
            "days_left": days_left,
        }
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# --- Probe principal -------------------------------------------------------- #

async def probe_tcp(host: str, port: int, timeout: float = 1.5) -> dict:
    """Connexion TCP + sonde adaptée. Retourne {open: bool, ...}."""
    out: dict = {"open": False, "port": port, "proto": "tcp"}

    # 1) HTTPS / TLS direct
    if port in HTTPS_PORTS:
        tls = await grab_tls_cert(host, port, timeout=timeout)
        if tls is not None:
            out.update({"open": True, "service": "https" if port != 993 else "imaps",
                        "tls": tls})
            # essayer GET sur la connexion TLS pour avoir Server header
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                    timeout=timeout,
                )
                writer.write(HTTP_PROBE % host.encode())
                await writer.drain()
                raw = await asyncio.wait_for(reader.read(2048), timeout=timeout)
                writer.close()
                try: await writer.wait_closed()
                except Exception: pass
                parsed = _parse_banner(port, raw)
                if "product" in parsed: out["product"] = parsed["product"]
                if "title" in parsed: out["title"] = parsed["title"]
                if "http_status" in parsed: out["http_status"] = parsed["http_status"]
                if parsed.get("banner"): out["banner"] = parsed["banner"]
            except Exception:
                pass
            return out

    # 2) TCP plain
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return out

    out["open"] = True
    try:
        # Choisir le payload
        if port in HTTP_PORTS:
            payload = HTTP_PROBE % host.encode()
        else:
            payload = PROBE_MAP.get(port, None)

        if payload and port not in PASSIVE_BANNER_PORTS:
            try:
                writer.write(payload); await writer.drain()
            except Exception:
                pass

        try:
            raw = await asyncio.wait_for(reader.read(2048), timeout=min(timeout, 1.2))
        except asyncio.TimeoutError:
            raw = b""

        # second essai si silencieux & pas de sonde envoyée → GET générique
        if not raw and not payload:
            try:
                writer.write(HTTP_PROBE % host.encode()); await writer.drain()
                raw = await asyncio.wait_for(reader.read(2048), timeout=0.8)
            except Exception:
                pass

        out.update(_parse_banner(port, raw))
    finally:
        try:
            writer.close(); await writer.wait_closed()
        except Exception:
            pass
    return out


# --- UDP -------------------------------------------------------------------- #

UDP_PROBES: dict[int, bytes] = {
    # DNS query for "version.bind" CHAOS TXT
    53: bytes.fromhex("aaaa01000001000000000000")
        + b"\x07version\x04bind\x00\x00\x10\x00\x03",
    # NTP v2 client
    123: b"\x1b" + b"\x00" * 47,
    # SNMP v1 get sysDescr (community=public)
    161: bytes.fromhex(
        "302902010004067075626c6963a01c020401020304020100020100"
        "300e300c06082b060102010101000500"
    ),
    # NetBIOS name query
    137: bytes.fromhex(
        "8000000000010000000000002043"
        "4b4141414141414141414141414141414141414141414141414141414141410000210001"
    ),
}


def probe_udp_sync(host: str, port: int, timeout: float = 0.6) -> dict:
    out = {"open": False, "port": port, "proto": "udp"}
    payload = UDP_PROBES.get(port, b"\x00")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(payload, (host, port))
        try:
            data, _ = s.recvfrom(2048)
            out["open"] = True
            out["banner"] = data[:200].hex() if not data.isascii() else data.decode(errors="ignore").strip()
            if port == 53: out["service"] = "dns"
            elif port == 123: out["service"] = "ntp"
            elif port == 161: out["service"] = "snmp"
        except socket.timeout:
            # Pas de réponse : open|filtered → on marque "open" pour les ports usuels seulement
            if port in UDP_PROBES:
                out["open"] = True
                out["banner"] = "no-response (open|filtered)"
        s.close()
    except Exception as e:
        out["error"] = str(e)
    return out

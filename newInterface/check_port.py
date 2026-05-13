#!/usr/bin/env python3
# Scanner de ports avancé avec fermeture intelligente

import socket
import sys
import time
import platform
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_TARGET = "localhost"
DEFAULT_TIMEOUT = 0.8
DEFAULT_UDP_TIMEOUT = 0.2
DEFAULT_WORKERS = 500
COMMON_PORTS = [21,22,23,25,53,80,88,110,111,123,135,139,143,161,389,443,445,465,514,631,993,995,1433,1521,3306,3389,5900,8080,8443,8000]
ALL_PORTS = list(range(1, 65536))

def parse_ports(arg):
    """Analyse l'argument des ports et retourne une liste de ports à scanner"""
    if not arg:
        return COMMON_PORTS
    
    if arg.lower() == "all":
        return ALL_PORTS
    elif arg.lower() == "common":
        return COMMON_PORTS
    elif arg.lower().startswith("top"):
        try:
            num = int(arg[3:]) if len(arg) > 3 else 1000
            return list(range(1, min(num + 1, 65536)))
        except Exception:
            return list(range(1, 1001))
    
    parts = arg.split(',')
    ports = set()
    for p in parts:
        p = p.strip()
        if '-' in p:
            a,b = p.split('-',1)
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(p))
    return sorted(p for p in ports if 0 <= p <= 65535)

def scan_port_tcp(target_ip, port, timeout=DEFAULT_TIMEOUT):
    """Scanne un port TCP spécifique et retourne son statut"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((target_ip, port))
        if code == 0:
            try:
                sock.settimeout(0.3)
                banner = sock.recv(512)
                banner = banner.decode(errors="ignore").strip()
            except Exception:
                banner = ""
            sock.close()
            return (port, "open", banner)
        else:
            sock.close()
            return (port, "closed", "")
    except socket.timeout:
        return (port, "filtered", "timeout")
    except Exception as e:
        return (port, "filtered", str(e))


def scan_port_udp(target_ip, port, timeout=DEFAULT_TIMEOUT):
    """Scanne un port UDP (best-effort). No response = open|filtered."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(min(timeout, DEFAULT_UDP_TIMEOUT))
        sock.sendto(b"", (target_ip, port))
        try:
            data, _ = sock.recvfrom(512)
            info = data.decode(errors="ignore").strip()
            sock.close()
            return (port, "open", f"udp/response: {info}" if info else "udp/response")
        except socket.timeout:
            sock.close()
            return (port, "open", "udp/no-response")
    except Exception as e:
        return (port, "filtered", f"udp/error: {e}")


def scan_port(target_ip, port, timeout=DEFAULT_TIMEOUT, proto="tcp"):
    """Scanne un port selon le protocole"""
    if proto.lower() == "udp":
        return scan_port_udp(target_ip, port, timeout)
    return scan_port_tcp(target_ip, port, timeout)

def get_local_ips():
    """Récupère toutes les adresses IP locales de la machine"""
    ips = {"127.0.0.1", "::1", "localhost"}
    try:
        hostname = socket.gethostname()
        for af, socktype, proto, canonname, sa in socket.getaddrinfo(hostname, None):
            ips.add(sa[0])
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return ips

def is_local_target_strict(target_ip):
    """Vérifie si la cible correspond exactement à une interface locale"""
    return target_ip in get_local_ips()

def find_pids_linux(port):
    """Trouve les PID des processus utilisant un port donné sous Linux"""
    pids = set()
    try:
        out = subprocess.check_output(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"], stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            try:
                pids.add(int(line.strip()))
            except Exception:
                pass
    except Exception:
        pass
    try:
        out = subprocess.check_output(["ss", "-ltnp"], stderr=subprocess.DEVNULL).decode(errors="ignore")
        for line in out.splitlines():
            if f":{port} " in line or f":{port}\n" in line or f":{port}\t" in line:
                if "pid=" in line:
                    import re
                    m = re.search(r"pid=(\d+),", line)
                    if m:
                        pids.add(int(m.group(1)))
    except Exception:
        pass
    return pids

def find_pids_windows(port):
    """Trouve les PID des processus utilisant un port donné sous Windows"""
    pids = set()
    try:
        out = subprocess.check_output(["netstat", "-ano"], stderr=subprocess.DEVNULL).decode(errors="ignore")
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            # sauter l'entête (Proto Local Address Foreign Address State PID)
            if line.lower().startswith("proto"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            # Le PID est normalement la dernière colonne
            pid = parts[-1]
            # Rechercher une colonne contenant le port local (prise en charge IPv4/IPv6)
            try:
                for col in parts[:-1]:
                    if f":{port}" in col or col.endswith(f".{port}"):
                        try:
                            pids.add(int(pid))
                        except Exception:
                            pass
                        break
            except Exception:
                # Ne pas laisser une ligne foireuse casser tout
                continue
    except Exception:
        pass
    return pids

def get_service_info(port, pid=None):
    """Détecte le type de service et retourne des infos utiles"""
    service_map = {
        20: ("FTP-data", "ftp", "vsftpd"),
        21: ("FTP", "vsftpd", "vsftpd"),
        22: ("SSH", "ssh", "openssh-server"),
        23: ("TELNET", "telnet", None),
        25: ("SMTP", "postfix", "postfix"),
        53: ("DNS", "bind9", "bind9"),
        67: ("DHCP-server", "isc-dhcp-server", "isc-dhcp-server"),
        68: ("DHCP-client", None, None),
        69: ("TFTP", "tftpd-hpa", "tftpd-hpa"),
        80: ("HTTP", "apache2", "apache2"),
        88: ("Kerberos", "krb5-kdc", "krb5-kdc"),
        110: ("POP3", "dovecot", "dovecot"),
        111: ("rpcbind", "rpcbind", "rpcbind"),
        123: ("NTP", "ntp", "ntp"),
        135: ("MS-RPC", None, None),
        139: ("NetBIOS-SSN", None, None),
        143: ("IMAP", "dovecot", "dovecot"),
        161: ("SNMP", "snmpd", "snmpd"),
        389: ("LDAP", "slapd", "slapd"),
        443: ("HTTPS", "nginx", "nginx"),
        445: ("SMB", "smbd", "smbd"),
        465: ("SMTPS", "postfix", "postfix"),
        514: ("syslog", "rsyslog", "rsyslog"),
        631: ("CUPS-Imprimante", "cups", "cups"),
        993: ("IMAPS", "dovecot", "dovecot"),
        995: ("POP3S", "dovecot", "dovecot"),
        1080: ("SOCKS", None, None),
        1433: ("MSSQL", None, None),
        1521: ("Oracle", None, None),
        2049: ("NFS", "nfs-kernel-server", "nfs-kernel-server"),
        2082: ("cPanel", None, None),
        2083: ("cPanel-SSL", None, None),
        3306: ("MySQL", "mysql", "mysql"),
        3389: ("RDP", None, None),
        3690: ("Subversion", None, None),
        4444: ("Metasploit", None, None),
        4662: ("eDonkey", None, None),
        5000: ("UPnP/Dev", None, None),
        5001: ("iperf", None, None),
        5432: ("PostgreSQL", "postgresql", "postgresql"),
        5601: ("Kibana", None, None),
        5900: ("VNC", None, None),
        6000: ("X11", None, None),
        6379: ("Redis", "redis-server", "redis-server"),
        6667: ("IRC", None, None),
        6881: ("BitTorrent", None, None),
        8000: ("HTTP-Alt", None, None),
        8008: ("HTTP-Alt", None, None),
        8080: ("HTTP-Alt", "tomcat", "tomcat"),
        8443: ("HTTPS-Alt", None, None),
        9000: ("Sonar/Php-FPM", None, None),
        9200: ("Elasticsearch", "elasticsearch", "elasticsearch"),
        9300: ("Elasticsearch-TCP", None, None),
        10000: ("Webmin", "webmin", "webmin"),
        11211: ("Memcached", "memcached", "memcached"),
        11434: ("Ollama-IA", "ollama", "ollama"),
        25565: ("Minecraft", None, None),
        27015: ("Game-Server", None, None),
        27017: ("MongoDB", "mongod", "mongodb"),
        27018: ("MongoDB-Alt", None, None),
        28017: ("MongoDB-HTTP", None, None),
        50070: ("HDFS Namenode", None, None),
    }
    
    # Ports dynamiques/éphémères (plages communes)
    if 32768 <= port <= 65535:
        return ("Port-Dynamique", None, None)
    
    if port in service_map:
        return service_map[port]
    return ("Service-Inconnu", None, None)

def get_process_details(pid):
    """Récupère les détails d'un processus donné"""
    try:
        import psutil
        process = psutil.Process(pid)
        return {
            "name": process.name(),
            "username": process.username(),
            "cmdline": " ".join(process.cmdline()),
            "status": process.status()
        }
    except ImportError:
        # Alternative sans psutil
        try:
            plat = platform.system().lower()
            if "linux" in plat or "darwin" in plat:
                cmd = subprocess.check_output(["ps", "-p", str(pid), "-o", "pid,user,comm,cmd"], stderr=subprocess.DEVNULL).decode(errors="ignore")
                lines = cmd.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split(None, 3)
                    return {
                        "name": parts[2] if len(parts) > 2 else "unknown",
                        "username": parts[1] if len(parts) > 1 else "unknown",
                        "cmdline": parts[3] if len(parts) > 3 else "unknown",
                        "status": "running"
                    }
        except Exception:
            pass
    return {"name": "unknown", "username": "unknown", "cmdline": "unknown", "status": "unknown"}

def get_pids_for_port(port):
    """Retourne une liste d'infos procesus (pid,name,user,cmd) pour un port donné (best-effort)."""
    plat = platform.system().lower()
    pids = set()
    if "linux" in plat or "darwin" in plat:
        pids = find_pids_linux(port)
    elif "windows" in plat:
        pids = find_pids_windows(port)
    infos = []
    for pid in sorted(pids):
        info = get_process_details(pid)
        infos.append({
            "pid": pid,
            "name": info.get("name", "unknown"),
            "user": info.get("username", "unknown"),
            "cmd": info.get("cmdline", "")
        })
    return infos

def suggest_service_commands(port, pids, service_name, service_cmd):
    """Suggère des commandes de service appropriées"""
    print(f"\n🔧 COMMANDES RECOMMANDÉES pour le port {port} ({service_name}):")
    
    if service_cmd:
        print("📋 Arrêter le service proprement:")
        print(f"   sudo systemctl stop {service_cmd}")
        print(f"   sudo service {service_cmd} stop")
        
        print("📋 Désactiver le service au démarrage:")
        print(f"   sudo systemctl disable {service_cmd}")
        
        print("📋 Redémarrer le service:")
        print(f"   sudo systemctl restart {service_cmd}")
        
        print("📋 Vérifier le statut:")
        print(f"   sudo systemctl status {service_cmd}")
    
    print("📋 Forcer l'arrêt des processus (ATTENTION: peut corrompre les données!):")
    for pid in pids:
        print(f"   sudo kill -9 {pid}")
    
    print("📋 Vérifier que le port est fermé après:")
    print(f"   sudo lsof -i :{port}")
    print(f"   sudo netstat -tlnp | grep :{port}")
    
    return service_cmd

def kill_pids(pids, port=None):
    """Tente de tuer les processus donnés"""
    results = {}
    plat = platform.system().lower()
    
    service_name, service_cmd, _ = get_service_info(port) if port else ("Unknown", None, None)
    
    for pid in pids:
        process_info = get_process_details(pid)
        print(f"    🔍 PID {pid}: {process_info['name']} (utilisateur: {process_info['username']})")
        
        try:
            if "linux" in plat or "darwin" in plat:
                subprocess.check_output(["kill", "-9", str(pid)], stderr=subprocess.STDOUT)
                results[pid] = (True, "killed")
            elif "windows" in plat:
                subprocess.check_output(["taskkill", "/PID", str(pid), "/F"], stderr=subprocess.STDOUT)
                results[pid] = (True, "taskkilled")
            else:
                results[pid] = (False, f"unsupported platform {plat}")
        except subprocess.CalledProcessError as e:
            error_msg = e.output.decode(errors="ignore") if hasattr(e, "output") else str(e)
            
            if ("Permission" in error_msg or "not permitted" in error_msg) and service_cmd:
                results[pid] = (False, f"Permission refusée. Essayez: sudo systemctl stop {service_cmd}")
                suggest_service_commands(port, [pid], service_name, service_cmd)
            else:
                results[pid] = (False, error_msg)
        except Exception as e:
            results[pid] = (False, str(e))
    
    return results

def suggest_remote_commands(target, ports, remote_os_hint=None):
    """Génère des commandes pour bloquer les ports sur une machine distante"""
    pstr = ",".join(str(p) for p in ports)
    print("\n--- Commandes à exécuter SUR LA MACHINE DISTANTE ---")
    print(f"Target: {target} ports: {pstr}\n")
    
    print("Windows (PowerShell en Administrateur) - Bloquer via Pare-feu :")
    print(f'  New-NetFirewallRule -DisplayName "Block ports {pstr}" -Direction Inbound -Action Block -Protocol TCP -LocalPort {pstr}')
    print("Pour trouver PID et killer si nécessaire (PowerShell Admin):")
    print(f'  netstat -ano | findstr ":{ports[0]}"')
    print('  taskkill /PID <PID> /F\n')
    
    print("Linux (exécuter en root) - UFW :")
    print(f'  sudo ufw deny proto tcp from any to any port {pstr}')
    print("Linux (iptables direct) :")
    for p in ports:
        print(f'  sudo iptables -A INPUT -p tcp --dport {p} -j REJECT')
    print("\nNote: Bloquer via pare-feu est préférable à tuer des services critiques.")
    print("--- Fin des commandes distantes ---\n")

def analyze_port(port):
    """Analyse un port spécifique et retourne des informations détaillées"""
    service_name, service_cmd, _ = get_service_info(port)
    
    port_info = {
        631: {
            "nom": "CUPS (Common Unix Printing System)",
            "description": "Serveur d'impression - Interface web sur http://localhost:631",
            "securite": "🟡 Peu risqué - Service d'impression local",
            "action": "Peut être arrêté si pas d'imprimantes"
        },
        11434: {
            "nom": "Ollama (IA/LLM local)",
            "description": "Serveur pour modèles de langage IA - API sur http://localhost:11434",
            "securite": "🟡 Peu risqué - Service IA local",
            "action": "Peut être arrêté si pas utilisé"
        },
        3306: {
            "nom": "MySQL/MariaDB",
            "description": "Serveur de base de données",
            "securite": "🔴 Critique - Contient des données importantes",
            "action": "⚠️ Arrêt délicat - Risque de corruption"
        },
        22: {
            "nom": "SSH (Secure Shell)",
            "description": "Accès distant sécurisé",
            "securite": "🟡 Important - Accès administrateur",
            "action": "⚠️ Ne pas fermer si connexion SSH active"
        }
    }
    
    if port in port_info:
        return port_info[port]
    elif 32768 <= port <= 65535:
        return {
            "nom": f"Port dynamique {port}",
            "description": "Port assigné temporairement par le système",
            "securite": "🟢 Généralement sans risque",
            "action": "Peut être fermé - Se réouvre automatiquement si nécessaire"
        }
    else:
        return {
            "nom": f"Service sur port {port}",
            "description": "Service non identifié",
            "securite": "🟡 À vérifier",
            "action": "Identifier le service avant de fermer"
        }

def show_help():
    """Affiche l'aide du script"""
    use_color = sys.stdout.isatty()
    C = {
        "reset": "\033[0m" if use_color else "",
        "bold": "\033[1m" if use_color else "",
        "cyan": "\033[36m" if use_color else "",
        "yellow": "\033[33m" if use_color else "",
        "green": "\033[32m" if use_color else "",
    }
    def h(s):
        return f"{C['bold']}{C['cyan']}{s}{C['reset']}"
    def k(s):
        return f"{C['bold']}{s}{C['reset']}"
    def ex(s):
        return f"{C['green']}{s}{C['reset']}"
    def note(s):
        return f"{C['yellow']}{s}{C['reset']}"

    print(h("PORT SCANNER — CLI"))
    print("=" * 60)
    print(k("USAGE:"))
    print("  python3 check_port.py <target> [ports] [options]")
    print()
    print(k("TARGET:"))
    print("  IP ou hostname (ex: localhost, 192.168.1.1)")
    print()
    print(k("PORTS (preset / liste / plage):"))
    print("  common      : ports courants (défaut)")
    print("  top1000     : ports 1–1000")
    print("  top5000     : ports 1–5000")
    print("  all         : ports 1–65535 (très long)")
    print("  1-1024      : plage personnalisée")
    print("  22,80,443   : liste explicite")
    print()
    print(k("OPTIONS:"))
    print("  --show-dynamic  Afficher les ports dynamiques/éphémères")
    print("  --udp           Activer un scan UDP (best-effort, plus lent)")
    print("  -h, --help      Afficher cette aide")
    print()
    print(k("EXEMPLES:"))
    print(ex("  python3 check_port.py localhost"))
    print(ex("  python3 check_port.py 192.168.1.1 top1000"))
    print(ex("  python3 check_port.py 10.0.0.1 1-1024"))
    print(ex("  python3 check_port.py 10.0.0.1 22,80,443"))
    print(ex("  python3 check_port.py 192.168.1.1 top1000 --udp"))
    print()
    print(k("NOTES:"))
    print(note("  - Le script ajuste automatiquement timeout/workers selon le volume"))
    print(note("  - Pour voir/stopper des PID: exécuter en sudo/administrateur"))
    print()

def main():
    # Simple parsing des arguments: support -h/--help et --show-dynamic
    args = sys.argv[1:]
    if any(a in ("-h", "--help", "help") for a in args):
        show_help()
        return

    show_dynamic = False
    if "--show-dynamic" in args:
        show_dynamic = True
        args = [a for a in args if a != "--show-dynamic"]

    use_udp = False
    if "--udp" in args:
        use_udp = True
        args = [a for a in args if a != "--udp"]

    if len(args) >= 1:
        target = args[0]
    else:
        target = DEFAULT_TARGET
    ports_arg = args[1] if len(args) >= 2 else None
    ports = parse_ports(ports_arg)

    try:
        target_ip = socket.gethostbyname(target)
    except Exception as e:
        print(f"Erreur résolution DNS pour {target}: {e}")
        sys.exit(1)

    # Optimisation automatique selon le nombre de ports
    num_ports = len(ports)
    if num_ports > 10000:
        timeout = 0.3
        workers = min(1000, num_ports // 10)
        print(f"⚡ Mode scan rapide activé: {num_ports} ports, timeout={timeout}s, workers={workers}")
    elif num_ports > 1000:
        timeout = 0.5
        workers = min(800, num_ports // 5)
        print(f"🚀 Mode scan accéléré: {num_ports} ports, timeout={timeout}s, workers={workers}")
    else:
        timeout = DEFAULT_TIMEOUT
        workers = min(DEFAULT_WORKERS, max(50, num_ports))

    if use_udp:
        timeout = min(timeout, DEFAULT_UDP_TIMEOUT)
        workers = min(workers, 300)

    print(f"Début du scan sur: {target} ({target_ip})")
    proto_note = "TCP" + (" + UDP" if use_udp else "")
    print(f"Ports à scanner: {num_ports} ports ({proto_note})")
    print(f"Configuration: timeout={timeout}s, workers={workers}")
    
    if (num_ports * (2 if use_udp else 1)) > 1000:
        print("📊 Affichage du progrès activé pour les gros scans...")
    
    start = time.time()
    open_ports = []
    scanned_count = 0
    progress_interval = max(100, num_ports // 20)

    protocols = ["tcp"] + (["udp"] if use_udp else [])
    total_tasks = num_ports * len(protocols)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, target_ip, p, timeout, proto): (p, proto) for proto in protocols for p in ports}
        for fut in as_completed(futures):
            port, status, info = fut.result()
            _, proto = futures[fut]
            scanned_count += 1
            
            if status == "open":
                open_ports.append((port, info, proto))
                print(f"🟢 {proto.upper()} port {port} is OPEN{f' - {info[:50]}' if info else ''}")
            
            if total_tasks > 1000 and scanned_count % progress_interval == 0:
                percentage = (scanned_count / total_tasks) * 100
                elapsed = time.time() - start
                rate = scanned_count / elapsed if elapsed > 0 else 0
                eta = (total_tasks - scanned_count) / rate if rate > 0 else 0
                print(f"📈 Progrès: {scanned_count}/{total_tasks} ({percentage:.1f}%) - "
                      f"Vitesse: {rate:.0f} ports/s - ETA: {eta:.0f}s")
    
    end = time.time()
    rate = num_ports / (end - start) if (end - start) > 0 else 0
    print(f"\n✅ Scan terminé en {end - start:.2f} secondes.")
    print(f"📊 Vitesse moyenne: {rate:.0f} ports/seconde")

    # Filtrer les ports dynamiques par défaut (masqués)
    if not show_dynamic:
        display_ports = [ (p,b,proto) for (p,b,proto) in open_ports if get_service_info(p)[0] != "Port-Dynamique" ]
    else:
        display_ports = open_ports[:]

    if not display_ports:
        print("❌ Aucun port ouvert détecté (après filtrage des ports dynamiques).")
        if not show_dynamic:
            print("Si vous voulez afficher aussi les ports dynamiques, relancez avec --show-dynamic")
        return

    print(f"\n🎯 {len(display_ports)} ports ouverts trouvés:")
    for p, banner, proto in sorted(display_ports, key=lambda x: (x[2], x[0])):
        service_name, _, _ = get_service_info(p)
        # Récupérer les PID et infos d'application (best-effort)
        pid_infos = get_pids_for_port(p)
        pid_display = ""
        if pid_infos:
            pid_display = ", ".join(f"PID {x['pid']}:{x['name']}" for x in pid_infos)
        else:
            pid_display = "(PID inconnu - exécutez avec sudo pour plus de détails)"

        # Analyse du port pour plus d'infos
        port_analysis = analyze_port(p)
        security_icon = port_analysis["securite"][:2]  # Récupère juste l'emoji

        print(f"  🔓 {proto.upper()} Port {p} ({service_name}) {security_icon}  {pid_display}")
        print(f"      📋 {port_analysis['description']}")
        if banner:
            print(f"      🏷️  Banner: {banner[:80]}...")

    sel = input("\n🔧 Saisis les ports à fermer (séparés par des virgules), ou Enter pour quitter : ").strip()
    if not sel:
        print("Aucun port sélectionné, sortie.")
        return
    try:
        chosen = sorted({int(x.strip()) for x in sel.split(",") if x.strip()})
    except Exception:
        print("Entrée invalide. Ex : 135,139,445")
        return
    print(f"\n✅ Tu as choisi : {chosen}")

    local = is_local_target_strict(target_ip)
    if not local:
        print("\n🌐 La cible est DISTANTE -> génération des commandes à exécuter sur la machine distante.")
        suggest_remote_commands(target, chosen)
        return

    print("\n🏠 La cible correspond à une interface locale. Recherche des PID locaux.")
    
    is_root = False
    plat = platform.system().lower()
    if "linux" in plat or "darwin" in plat:
        is_root = (os.geteuid() == 0)
    elif "windows" in plat:
        is_root = True

    if not is_root:
        print("⚠️  Attention : le script n'est PAS exécuté avec privilèges root/admin.")
        print("Pour afficher et tuer les PID, relance avec sudo (Linux/macOS) ou en Administrateur (Windows).")
        print("Exemple: sudo python3 check_port.py", target, "all")
        
    confirm = input("Confirmer la recherche/arrêt des processus locaux ? (oui/no) ").strip().lower()
    if confirm not in ("o","oui","y","yes"):
        print("❌ Annulé.")
        return

    overall = {}
    for port in chosen:
        pids = set()
        if "linux" in plat or "darwin" in plat:
            pids = find_pids_linux(port)
        elif "windows" in plat:
            pids = find_pids_windows(port)
        else:
            print(f"Plateforme non supportée: {plat}")
            continue

        if not pids:
            print(f"  Port {port} : aucun PID trouvé (si tu es root, relance le script avec sudo).")
            overall[port] = {"found": [], "killed": {}}
            continue

        service_name, service_cmd, _ = get_service_info(port)
        print(f"  🔍 Port {port} ({service_name}) : PIDs trouvés -> {sorted(pids)}")
        
        for pid in sorted(pids):
            process_info = get_process_details(pid)
            print(f"    📋 PID {pid}: {process_info['name']} (user: {process_info['username']})")
            print(f"        CMD: {process_info['cmdline'][:80]}...")

        if service_cmd:
            print(f"    💡 Service détecté: {service_name}")
            print(f"    🔧 Commande recommandée: sudo systemctl stop {service_cmd}")
            
            choice = input(f"    Choisir une action:\n"
                          f"    1️⃣  Arrêter le service proprement (systemctl stop {service_cmd})\n"
                          f"    2️⃣  Forcer kill des PID (risque de corruption!)\n"
                          f"    3️⃣  Ignorer ce port\n"
                          f"    Votre choix (1/2/3): ").strip()
            
            if choice == "1":
                print(f"    🔧 Arrêt du service {service_cmd}...")
                try:
                    subprocess.check_output(["systemctl", "stop", service_cmd], stderr=subprocess.STDOUT)
                    print(f"    ✅ Service {service_cmd} arrêté avec succès")
                    overall[port] = {"found": sorted(pids), "service_stopped": True}
                    
                    time.sleep(1)
                    new_pids = find_pids_linux(port) if "linux" in plat else find_pids_windows(port)
                    if not new_pids:
                        print(f"    ✅ Port {port} fermé avec succès!")
                    else:
                        print(f"    ⚠️  Port {port} encore ouvert après arrêt du service")
                except subprocess.CalledProcessError as e:
                    error = e.output.decode(errors="ignore") if hasattr(e, "output") else str(e)
                    print(f"    ❌ Erreur lors de l'arrêt du service: {error}")
                    overall[port] = {"found": sorted(pids), "service_error": error}
                except Exception as e:
                    print(f"    ❌ Erreur: {e}")
                    overall[port] = {"found": sorted(pids), "error": str(e)}
                continue
            elif choice == "3":
                print(f"    ⏭️  Port {port} ignoré")
                overall[port] = {"found": sorted(pids), "skipped": True}
                continue

        kill_confirm = input(f"    💀 Tuer les PID {sorted(pids)} avec kill -9 ? (oui/no) ").strip().lower()
        if kill_confirm not in ("o","oui","y","yes"):
            print("    ⏭️  Kill ignoré.")
            overall[port] = {"found": sorted(pids), "killed": {}}
            continue

        res = kill_pids(pids, port)
        overall[port] = {"found": sorted(pids), "killed": res}
        for pid,(ok,msg) in res.items():
            print(f"    PID {pid} -> {'✅ OK' if ok else '❌ FAIL'} : {msg}")

    print("\n📋 Résumé :")
    for port, info in overall.items():
        service_name, _, _ = get_service_info(port)
        print(f" 🔓 Port {port} ({service_name}) :")
        
        if "service_stopped" in info:
            print("    ✅ Service arrêté proprement")
        elif "service_error" in info:
            print(f"    ❌ Erreur service: {info['service_error']}")
        elif "skipped" in info:
            print("    ⏭️  Ignoré par l'utilisateur")
        elif info.get("killed"):
            print(f"    📋 PIDs trouvés: {info['found']}")
            for pid,(ok,msg) in info["killed"].items():
                print(f"      PID {pid} -> {'✅ OK' if ok else '❌ FAIL'} : {msg}")
        else:
            print(f"    📋 PIDs trouvés: {info['found']} (aucune action)")
    print("\n🏁 Terminé.")

if __name__ == "__main__":
    main()

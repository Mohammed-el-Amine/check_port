#!/usr/bin/env python3
# Scanner de ports avancé avec fermeture intelligente

import socket, sys, time, platform, subprocess, os
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_TARGET = "192.168.1.36"
DEFAULT_TIMEOUT = 0.8
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
        except:
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

def scan_port(target_ip, port, timeout=DEFAULT_TIMEOUT):
    """Scanne un port spécifique et retourne son statut"""
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
            except:
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
        out = subprocess.check_output(["netstat", "-ano"], stderr=subprocess.DEVNULL).decode(errors="ignore", errors_replace=True)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                local = parts[1]
                pid = parts[-1]
                if f":{port}" in local:
                    try:
                        pids.add(int(pid))
                    except:
                        pass
    except Exception:
        pass
    return pids

def get_service_info(port, pid=None):
    """Détecte le type de service et retourne des infos utiles"""
    service_map = {
        21: ("FTP", "ftp", "vsftpd"),
        22: ("SSH", "ssh", "openssh-server"),
        25: ("SMTP", "postfix", "sendmail"),
        53: ("DNS", "bind9", "named"),
        80: ("HTTP", "apache2", "nginx"),
        110: ("POP3", "dovecot", "postfix"),
        143: ("IMAP", "dovecot", "postfix"),
        443: ("HTTPS", "apache2", "nginx"),
        993: ("IMAPS", "dovecot", "postfix"),
        995: ("POP3S", "dovecot", "postfix"),
        3306: ("MySQL", "mysql", "mariadb"),
        5432: ("PostgreSQL", "postgresql", "postgres"),
        6379: ("Redis", "redis-server", "redis"),
        27017: ("MongoDB", "mongod", "mongodb"),
        8080: ("HTTP-Alt", "tomcat", "jetty"),
    }
    
    if port in service_map:
        return service_map[port]
    return ("Unknown", None, None)

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

def suggest_service_commands(port, pids, service_name, service_cmd):
    """Suggère des commandes de service appropriées"""
    print(f"\n🔧 COMMANDES RECOMMANDÉES pour le port {port} ({service_name}):")
    
    if service_cmd:
        print(f"📋 Arrêter le service proprement:")
        print(f"   sudo systemctl stop {service_cmd}")
        print(f"   sudo service {service_cmd} stop")
        
        print(f"📋 Désactiver le service au démarrage:")
        print(f"   sudo systemctl disable {service_cmd}")
        
        print(f"📋 Redémarrer le service:")
        print(f"   sudo systemctl restart {service_cmd}")
        
        print(f"📋 Vérifier le statut:")
        print(f"   sudo systemctl status {service_cmd}")
    
    print(f"📋 Forcer l'arrêt des processus (ATTENTION: peut corrompre les données!):")
    for pid in pids:
        print(f"   sudo kill -9 {pid}")
    
    print(f"📋 Vérifier que le port est fermé après:")
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
    print(f'  taskkill /PID <PID> /F\n')
    
    print("Linux (exécuter en root) - UFW :")
    print(f'  sudo ufw deny proto tcp from any to any port {pstr}')
    print("Linux (iptables direct) :")
    for p in ports:
        print(f'  sudo iptables -A INPUT -p tcp --dport {p} -j REJECT')
    print("\nNote: Bloquer via pare-feu est préférable à tuer des services critiques.")
    print("--- Fin des commandes distantes ---\n")

def show_help():
    """Affiche l'aide du script"""
    print("🔍 SCANNER DE PORTS AVANCÉ")
    print("=" * 40)
    print("USAGE: python3 check2_port.py [target] [ports]")
    print()
    print("OPTIONS DE PORTS:")
    print("  (vide)       : ports communs seulement")
    print("  'all'        : TOUS les ports 1-65535 (⚠️ très long!)")
    print("  'common'     : ports communs uniquement")
    print("  'top1000'    : ports 1-1000")
    print("  'top5000'    : ports 1-5000")
    print("  '1-1024'     : plage personnalisée")
    print("  '22,80,443'  : ports spécifiques")
    print()
    print("EXEMPLES:")
    print("  python3 check2_port.py 192.168.1.1 all")
    print("  python3 check2_port.py localhost top1000")
    print("  python3 check2_port.py 10.0.0.1 1-1024")
    print("  python3 check2_port.py example.com 22,80,443")
    print()
    print("⚡ Le script s'optimise automatiquement selon le nombre de ports!")
    print()

def main():
    if len(sys.argv) >= 2 and sys.argv[1] in ["-h", "--help", "help"]:
        show_help()
        return
    
    if len(sys.argv) >= 2:
        target = sys.argv[1]
    else:
        target = DEFAULT_TARGET
    ports_arg = sys.argv[2] if len(sys.argv) >= 3 else None
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

    print(f"Début du scan sur: {target} ({target_ip})")
    print(f"Ports à scanner: {num_ports} ports")
    print(f"Configuration: timeout={timeout}s, workers={workers}")
    
    if num_ports > 1000:
        print("📊 Affichage du progrès activé pour les gros scans...")
    
    start = time.time()
    open_ports = []
    scanned_count = 0
    progress_interval = max(100, num_ports // 20)
    
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, target_ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            port, status, info = fut.result()
            scanned_count += 1
            
            if status == "open":
                open_ports.append((port, info))
                print(f"🟢 port {port} is OPEN{f' - {info[:50]}' if info else ''}")
            
            if num_ports > 1000 and scanned_count % progress_interval == 0:
                percentage = (scanned_count / num_ports) * 100
                elapsed = time.time() - start
                rate = scanned_count / elapsed if elapsed > 0 else 0
                eta = (num_ports - scanned_count) / rate if rate > 0 else 0
                print(f"📈 Progrès: {scanned_count}/{num_ports} ({percentage:.1f}%) - "
                      f"Vitesse: {rate:.0f} ports/s - ETA: {eta:.0f}s")
    
    end = time.time()
    rate = num_ports / (end - start) if (end - start) > 0 else 0
    print(f"\n✅ Scan terminé en {end - start:.2f} secondes.")
    print(f"📊 Vitesse moyenne: {rate:.0f} ports/seconde")

    if not open_ports:
        print("❌ Aucun port ouvert détecté.")
        return

    print(f"\n🎯 {len(open_ports)} ports ouverts trouvés:")
    for p, banner in sorted(open_ports):
        banner_info = f" - {banner[:60]}..." if banner and len(banner) > 60 else f" - {banner}" if banner else ""
        print(f"  🔓 {p}{banner_info}")

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
            print(f"    ✅ Service arrêté proprement")
        elif "service_error" in info:
            print(f"    ❌ Erreur service: {info['service_error']}")
        elif "skipped" in info:
            print(f"    ⏭️  Ignoré par l'utilisateur")
        elif info.get("killed"):
            print(f"    📋 PIDs trouvés: {info['found']}")
            for pid,(ok,msg) in info["killed"].items():
                print(f"      PID {pid} -> {'✅ OK' if ok else '❌ FAIL'} : {msg}")
        else:
            print(f"    📋 PIDs trouvés: {info['found']} (aucune action)")
    print("\n🏁 Terminé.")

if __name__ == "__main__":
    main()

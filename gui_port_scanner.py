#!/usr/bin/env python3
# Interface graphique Tkinter pour le scanner de ports avec privilèges admin

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import tkinter.font as tkfont
import sys
import os
import io
import contextlib
import platform
import subprocess
import shutil
import threading
import time
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket



# Texte d'aide intégré — guide d'utilisation de l'interface graphique (en français)
HELP_TEXT = """
Guide d'utilisation - Scanner de Ports (Interface Graphique)
=========================================================

1) Configuration de base
- Cible : saisissez une adresse IP ou un nom d'hôte (ex: localhost, 192.168.1.1).
- Ports : choisissez une option dans la liste (common, top1000, top5000, all, 1-1024),
    ou entrez une liste/intervalle manuellement (ex: 22,80,443 or 8000-8100).

2) Options
- "Afficher les ports dynamiques" : cochez pour inclure les ports éphémères (32768-65535).
    Par défaut ils sont masqués pour réduire le bruit.

3) Contrôles principaux
- 🚀 Démarrer le Scan : lance le scan en arrière-plan et affiche la progression.
- ⏹️ Arrêter : stoppe le scan en cours (les résultats déjà trouvés restent affichés).
- 🗑️ Effacer : supprime toutes les lignes de résultats affichées.
- ❓ Aide : ouvre cette fenêtre d'aide.

4) Résultats
- La table affiche : Port | Service | PID | Processus | Sécurité | Actions
- Double-clic sur une ligne : ouvre une fenêtre de détails pour ce port (banner, PIDs, cmdline, actions).
- Clic droit (menu contextuel) : options rapides pour arrêter le service, tuer le processus ou copier les détails.

5) Actions nécessitant des privilèges
- Pour voir les PID locaux complets et arrêter/tuer des processus, exécutez l'application en mode administrateur.
    L'interface proposera de relancer avec sudo si nécessaire.
- Sur Linux, choisir "Relancer avec sudo" fermera la fenêtre actuelle et relancera le script en root
    (vous saisirez votre mot de passe dans le terminal).

6) Détails et bonnes pratiques
- La fenêtre de détail montre le banner réseau (si présent), la liste des PIDs, leur utilisateur
    et la ligne de commande (si disponible). Si la cible est distante, les PID locaux ne sont pas récupérables.
- Avant de tuer un processus, préférer d'abord arrêter proprement le service (ex: systemctl stop <service>).
- Attention : tuer un processus peut provoquer une perte ou corruption de données.

7) Dépannage rapide
- Si l'interface ne peut pas relancer en sudo (ou si l'affichage échoue en root), exécutez le script
    manuellement depuis un shell :
        sudo python3 gui_port_scanner.py
- Si vous ne voyez pas les PID après relance en root, vérifiez que vous avez les droits et que
    les outils système (ss/lsof) sont disponibles.

8) Exemples rapides
- Scanner les ports web communs sur localhost : sélectionnez 'common' puis Démarrer.
- Scanner 1-1024 : choisissez '1-1024' puis Démarrer.

Questions / amélioration
- Si vous voulez que j'ajoute des info-bulles (tooltips) sur les boutons ou l'option
    pour afficher le chemin complet de l'exécutable (via psutil), dites-le et je l'implémente.

"""

HELP_TEXT_EN = """
User Guide - Port Scanner (GUI)
===============================

1) Basic configuration
- Target: enter an IP or hostname (e.g., localhost, 192.168.1.1).
- Ports: choose a preset (common, top1000, top5000, all, 1-1024),
    or enter a custom list/range (e.g., 22,80,443 or 8000-8100).

2) Options
- "Show dynamic ports": include ephemeral ports (32768-65535).
    Hidden by default to reduce noise.

3) Main controls
- 🚀 Start Scan: runs the scan in background and shows progress.
- ⏹️ Stop: stops the current scan (results already found stay visible).
- 🗑️ Clear: clears all results.
- ❓ Help: opens this help window.

4) Results
- Table columns: Port | Service | PID | Process | Security | Actions
- Double-click a row: opens details (banner, PIDs, cmdline, actions).
- Right-click: quick actions (stop service, kill process, copy details).

5) Actions requiring privileges
- To see full local PIDs and stop/kill processes, run as administrator.
- On Linux, "Relaunch with sudo" will restart the app as root (password prompt in terminal).

6) Details & best practices
- Details show banner (if any), PID list, user and command line (if available).
- Prefer stopping services cleanly (e.g., systemctl stop <service>) before killing.
- Warning: killing processes may cause data loss.

7) Quick troubleshooting
- If sudo relaunch fails, run manually:
        sudo python3 gui_port_scanner.py
- If PIDs are missing after sudo, ensure you have permissions and tools (ss/lsof).

8) Examples
- Scan common web ports on localhost: choose 'common' then Start.
- Scan 1-1024: choose '1-1024' then Start.

Questions / improvements
- Want tooltips or full executable path (via psutil)? Tell me and I’ll add it.

"""

# Palette macOS-like (light)
PALETTE = {
    # macOS Sonoma-like palette
    "bg": "#f3f4f6",        # window background
    "card": "#ffffff",      # card / panel background
    "accent": "#9ca3af",    # soft gray accent
    "muted": "#6b7280",     # muted text
    "text": "#0b1320",      # primary text
    "danger": "#ff375f",    # macOS red
}

# Polices (San Francisco preferred with fallbacks)
FONT_TITLE = ("SF Pro Display", 18, "bold")
FONT_SUB = ("SF Pro Text", 12)
FONT_UI = ("SF Pro Text", 12)


# Import des fonctions du scanner principal
try:
    from check_port import (
        parse_ports, scan_port, get_service_info, get_pids_for_port,
        find_pids_linux, find_pids_windows, get_process_details,
        kill_pids, is_local_target_strict, get_local_ips,
        DEFAULT_TARGET, DEFAULT_TIMEOUT, DEFAULT_WORKERS,
        COMMON_PORTS, ALL_PORTS
    )
except ImportError:
    messagebox.showerror("Erreur", "Impossible d'importer check_port.py\nAssurez-vous qu'il est dans le même dossier.")
    sys.exit(1)

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        # If launched with an admin-ready marker, create it immediately
        marker = os.environ.get("SCAN_PORT_ADMIN_READY")
        if marker:
            try:
                with open(marker, "w") as f:
                    f.write("ok")
            except Exception:
                pass
        # If admin instance knows the parent PID, request it to close immediately
        parent_pid = os.environ.get("SCAN_PORT_PARENT_PID")
        if parent_pid:
            try:
                os.kill(int(parent_pid), 15)
            except Exception:
                pass

        # If running as root, kill any remaining non-root instances of this script
        try:
            if os.geteuid() == 0:
                out = subprocess.check_output(["ps", "-eo", "pid,uid,args"], text=True, errors="ignore")
                for line in out.splitlines():
                    parts = line.strip().split(None, 2)
                    if len(parts) != 3:
                        continue
                    pid, uid, args = parts
                    if "gui_port_scanner.py" in args and uid != "0":
                        try:
                            os.kill(int(pid), 15)
                        except Exception:
                            pass
        except Exception:
            pass
        self.root.title("Scanner de Ports Avancé - Interface Graphique")
        self.root.geometry("1120x740")
        self.root.minsize(980, 680)
        # Use the palette background for a macOS-like window
        try:
            self.root.configure(bg=PALETTE["bg"])
        except Exception:
            pass
        
        # Variables
        self.scan_running = False
        self.scan_results = []
        self.is_admin = self.check_admin_privileges()
        self.admin_dialog_shown = False  # Pour éviter de redemander

        # Compute a one-time scale based on the screen size and derive
        # scaled font tuples. This makes the UI responsive to screen
        # resolution at startup but avoids continuous resizing.
        try:
            self.root.update_idletasks()
            sw = float(self.root.winfo_screenwidth() or 1200)
            sh = float(self.root.winfo_screenheight() or 800)
            base_w, base_h = 1200.0, 800.0
            scale = min(max(min(sw / base_w, sh / base_h), 0.8), 1.4)
        except Exception:
            scale = 1.0

        def scaled_font(tpl, default_size):
            try:
                fam = tpl[0] if isinstance(tpl, (list, tuple)) and len(tpl) > 0 else tpl
                size = tpl[1] if isinstance(tpl, (list, tuple)) and len(tpl) > 1 else default_size
                weight = tpl[2] if isinstance(tpl, (list, tuple)) and len(tpl) > 2 else None
                new_size = max(9, int(size * scale))
                if weight:
                    return (fam, new_size, weight)
                return (fam, new_size)
            except Exception:
                return (tpl if tpl else "", int(default_size * scale))

        self.scaled_font_title = scaled_font(FONT_TITLE, 18)
        self.scaled_font_sub = scaled_font(FONT_SUB, 12)
        self.scaled_font_ui = scaled_font(FONT_UI, 12)
        
        # Initialiser l'UI d'abord
        self.setup_ui()
        
        # Puis vérifier les privilèges
        self.root.after(100, self.check_and_request_admin)

        # Do not bind a global resize font-scaler to avoid feedback/render loops.
        # The layout uses grid weights and proportional Treeview columns.
    
    def check_admin_privileges(self):
        """Vérifie si le script s'exécute avec des privilèges administrateur"""
        plat = platform.system().lower()
        
        if "linux" in plat or "darwin" in plat:
            return os.geteuid() == 0
        elif "windows" in plat:
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        return False
    
    def check_and_request_admin(self):
        """Demande les privilèges admin si nécessaire"""
        if not self.is_admin and not self.admin_dialog_shown:
            self.admin_dialog_shown = True
            self.show_admin_dialog()
        elif self.is_admin:
            self.status_label.config(text="✅ Privilèges administrateur détectés", fg="green")
    
    def show_admin_dialog(self):
        """Affiche la boîte de dialogue pour les privilèges admin"""
        # Créer une boîte de dialogue personnalisée avec 3 options
        dialog = tk.Toplevel(self.root)
        dialog.title("Privilèges Administrateur")
        dialog.transient(self.root)
        # Taille proportionnelle à l'écran (one-time) pour rester responsive
        try:
            sw = int(self.root.winfo_screenwidth() or 1200)
            sh = int(self.root.winfo_screenheight() or 800)
            w = max(520, int(sw * 0.5))
            h = max(320, int(sh * 0.35))
            dialog.geometry(f"{w}x{h}")
        except Exception:
            dialog.geometry("600x360")
        dialog.minsize(520, 320)
        # Protéger grab_set: attendre que la fenêtre soit visible puis tenter le grab
        try:
            dialog.update_idletasks()
            dialog.wait_visibility()
            dialog.grab_set()
        except Exception:
            # Si la fenêtre n'est pas viewable (ex: environnement graphique restreint),
            # on continue sans grab pour éviter l'exception qui stoppe l'événement Tk
            pass
        
        # Centrer la fenêtre and set sensible minimum size so controls remain clickable
        try:
            dialog.update_idletasks()
            sx = dialog.winfo_screenwidth()
            sy = dialog.winfo_screenheight()
            dx = int((sx - w) / 2) if 'w' in locals() else int((sx - 500) / 2)
            dy = int((sy - h) / 2) if 'h' in locals() else int((sy - 300) / 2)
            dialog.geometry(f"+{dx}+{dy}")
            dialog.minsize(int((w if 'w' in locals() else 500) * 0.6), int((h if 'h' in locals() else 300) * 0.6))
        except Exception:
            pass
        
        # Frame principal
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)

        # Icône et titre
        title_label = tk.Label(
            main_frame,
            text="🔐 Privilèges Administrateur",
            font=self.scaled_font_title,
            bg=PALETTE["bg"],
            fg=PALETTE["text"]
        )
        title_label.grid(row=0, column=0, sticky="w", pady=(0, 10))

        # Variable pour la réponse
        self.admin_choice = None

        # Boutons - placer en bas et garder visible
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=2, column=0, sticky="ew", pady=(8, 0))

        ttk.Button(
            buttons_frame,
            text="🚀 Relancer avec sudo",
            command=lambda: self.set_admin_choice("restart", dialog),
            style="Accent.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(
            buttons_frame,
            text="📝 Continuer en mode limité",
            command=lambda: self.set_admin_choice("continue", dialog)
        ).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(
            buttons_frame,
            text="❌ Quitter",
            command=lambda: self.set_admin_choice("quit", dialog)
        ).pack(side=tk.LEFT)

        # Use a scrollable read-only text area for the message so it remains usable
        try:
            msg_height = max(4, int((h if 'h' in locals() else 300) * 0.18))
        except Exception:
            msg_height = 6

        msg_box = scrolledtext.ScrolledText(
            main_frame,
            height=msg_height,
            wrap=tk.WORD,
            font=self.scaled_font_ui,
            bg=PALETTE["bg"],
            fg=PALETTE["text"],
            relief=tk.FLAT
        )
        msg_box.insert(tk.END, (
            "Pour obtenir les informations complètes sur les PID et pouvoir arrêter les services,\n"
            "il est recommandé d'exécuter ce programme avec des privilèges administrateur.\n\n"
            "Que souhaitez-vous faire ?"
        ))
        msg_box.config(state=tk.DISABLED)
        msg_box.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        
        # Attendre la réponse
        # Ensure the dialog receives focus and behaves modally where possible
        try:
            dialog.lift()
            dialog.focus_force()
            dialog.grab_set()
        except Exception:
            pass

        dialog.wait_window()
        
        # Traiter la réponse
        if self.admin_choice == "restart":
            self.restart_as_admin()
        elif self.admin_choice == "continue":
            messagebox.showinfo(
                "Mode Limité",
                "Le programme continue en mode limité.\n\n"
                "📝 Certaines informations (PID, noms de processus) ne seront pas disponibles\n"
                "🔧 Vous ne pourrez pas arrêter les services directement"
            )
        elif self.admin_choice == "quit":
            self.root.quit()
    
    def set_admin_choice(self, choice, dialog):
        """Définit le choix de l'utilisateur pour les privilèges admin"""
        self.admin_choice = choice
        dialog.destroy()
    
    def restart_as_admin(self):
        """Relance le programme avec des privilèges administrateur"""
        plat = platform.system().lower()
        script_path = os.path.abspath(__file__)
        exe = sys.executable

        try:
            # macOS / Linux flow: prefer graphical helpers, then terminal fallback, then sudo exec
            if "linux" in plat or "darwin" in plat:
                # Try macOS AppleScript first
                if "darwin" in plat:
                    try:
                        # Use osascript to run the script with administrator privileges (will show password prompt)
                        osa_cmd = f"do shell script \"{exe} '{script_path}'\" with administrator privileges"
                        subprocess.Popen(["osascript", "-e", osa_cmd])
                        self.root.quit()
                        return
                    except Exception:
                        # fallthrough to other methods
                        pass

                # Prefer terminal-based sudo on Linux to guarantee a visible password prompt
                if hasattr(self, "_restart_with_terminal_sudo"):
                    if self._restart_with_terminal_sudo(exe, script_path):
                        return

                # Try pkexec as a secondary option (polkit GUI)
                pkexec_path = shutil.which("pkexec")
                if pkexec_path:
                    try:
                        env = os.environ.copy()
                        for k in ("DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"):
                            if k in os.environ:
                                env[k] = os.environ[k]

                        def mk_env_assignment(k):
                            v = env.get(k)
                            return f'{k}={shlex.quote(v)}' if v is not None else None

                        parts = []
                        for k in ("PATH", "DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"):
                            a = mk_env_assignment(k)
                            if a:
                                parts.append(a)

                        exec_cmd = ' '.join(parts + [f'exec {shlex.quote(exe)} {shlex.quote(script_path)}'])
                        shell_runner = ['/bin/sh', '-c', exec_cmd]
                        cmd = [pkexec_path] + shell_runner
                        subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
                        return
                    except Exception as e:
                        print(f"pkexec invocation error: {e}")

                # Try gksudo / kdesudo if available (older GUI sudo wrappers)
                for helper in ("gksudo", "kdesudo"):
                    helper_path = shutil.which(helper)
                    if helper_path:
                        try:
                            subprocess.Popen([helper_path, exe, script_path])
                            self.root.quit()
                            return
                        except Exception:
                            continue

                # Fallback: open a terminal emulator that runs sudo so the user sees a password prompt
                def launch_terminal_sudo(exe, script_path):
                    marker = f"/tmp/scan_port_admin_ready_{os.getpid()}"
                    # ensure old marker doesn't exist
                    try:
                        if os.path.exists(marker):
                            os.remove(marker)
                    except Exception:
                        pass

                    terminals = [
                        ("x-terminal-emulator", ["-e", "bash", "-lc"]),
                        ("gnome-terminal", ["--", "bash", "-lc"]),
                        ("konsole", ["-e"]),
                        ("xfce4-terminal", ["--command"]),
                        ("mate-terminal", ["--", "bash", "-lc"]),
                        ("lxterminal", ["-e"]),
                        ("terminator", ["-x"]),
                        ("xterm", ["-e"]),
                    ]

                    sudo_cmd = f"sudo -k SCAN_PORT_ADMIN_READY={marker} SCAN_PORT_PARENT_PID={os.getpid()} {exe} '{script_path}'"
                    def elevated_process_started():
                        try:
                            out = subprocess.check_output(["ps", "-eo", "uid,args"], text=True, errors="ignore")
                            for line in out.splitlines():
                                line = line.strip()
                                if not line:
                                    continue
                                parts = line.split(None, 1)
                                if len(parts) != 2:
                                    continue
                                uid, args = parts
                                if uid == "0" and "gui_port_scanner.py" in args:
                                    return True
                        except Exception:
                            pass
                        return False

                    def close_when_elevated():
                        try:
                            deadline = time.time() + 120
                            while time.time() < deadline:
                                # Close when the admin instance signals readiness
                                if os.path.exists(marker):
                                    try:
                                        self.root.after(0, self.root.quit)
                                    except Exception:
                                        pass
                                    return
                                if elevated_process_started():
                                    try:
                                        self.root.after(0, self.root.quit)
                                    except Exception:
                                        pass
                                    return
                                time.sleep(0.3)
                        except Exception:
                            pass

                    for term, extra_args in terminals:
                        if shutil.which(term):
                            try:
                                cmd = [term] + extra_args + [f"{sudo_cmd}; echo; read -n1 -s -r -p 'Press any key to close...'" ]
                                subprocess.Popen(cmd)
                                # Close the current GUI when the elevated instance actually starts
                                threading.Thread(target=close_when_elevated, daemon=True).start()
                                return True
                            except Exception:
                                continue
                    # If no terminal could be launched, keep GUI open silently
                    return False

                # Expose helper for pkexec fallback
                self._restart_with_terminal_sudo = launch_terminal_sudo

                if launch_terminal_sudo(exe, script_path):
                    return

                # Keep a helper for reuse by pkexec fallback
                self._restart_with_terminal_sudo = launch_terminal_sudo

                if launch_terminal_sudo():
                    return

                # Last resort: execvp with sudo (will open terminal if user launched from one)
                messagebox.showinfo(
                    "Redémarrage",
                    "Aucun helper graphique détecté. Le programme va être relancé avec sudo dans le même environnement."
                )
                self.root.quit()
                os.execvp('sudo', ['sudo', exe, script_path])

            elif "windows" in plat:
                import ctypes
                # Use ShellExecute 'runas' to trigger UAC; pass the script path as parameter
                params = f'"{script_path}"'
                try:
                    ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
                    if int(ret) > 32:
                        # launched successfully; exit current GUI
                        self.root.quit()
                        return
                    else:
                        messagebox.showwarning(
                            "Échec du redémarrage",
                            "Impossible de relancer en tant qu'administrateur. Continuation en mode limité."
                        )
                except Exception as e:
                    messagebox.showerror("Erreur", f"Échec du relancement UAC: {e}")

        except Exception as e:
            messagebox.showerror(
                "Erreur de redémarrage",
                f"Impossible de relancer avec privilèges admin: {e}\n\nContinuation en mode limité."
            )

    def setup_ui(self):
        """Configure l'interface utilisateur"""
        # Style
        style = ttk.Style()
        # Prefer native-looking theme on macOS when available
        try:
            if platform.system().lower().startswith('darwin'):
                style.theme_use('aqua')
            else:
                style.theme_use('clam')
        except Exception:
            pass

        # Base frame and label styles
        style.configure("TFrame", background=PALETTE["bg"]) 
        style.configure("TLabel", background=PALETTE["bg"], foreground=PALETTE["text"], font=self.scaled_font_ui)
        style.configure("TLabelframe", background=PALETTE["bg"], foreground=PALETTE["text"], font=self.scaled_font_ui)
        style.configure("TLabelframe.Label", background=PALETTE["bg"], foreground=PALETTE["muted"], font=self.scaled_font_ui)

        # Buttons (Sonoma-like)
        style.configure("TButton", font=self.scaled_font_ui, padding=(8, 5), background=PALETTE["card"], borderwidth=0, focusthickness=0, foreground=PALETTE["text"])
        style.configure("Accent.TButton", background=PALETTE["accent"], foreground="#ffffff", relief="flat")
        style.map("Accent.TButton",
                  background=[('active', '#0b74ff'), ('disabled', '#cbd5e1')],
                  foreground=[('disabled', '#e5e7eb')])

        # Inputs
        style.configure("TEntry", fieldbackground=PALETTE["card"], foreground=PALETTE["text"], background=PALETTE["card"], insertcolor=PALETTE["text"], borderwidth=0)
        style.configure("TCombobox", fieldbackground=PALETTE["card"], foreground=PALETTE["text"], background=PALETTE["card"], arrowsize=12)

        # Treeview / headings - Sonoma clean header
        style.configure("Treeview",
                        background=PALETTE["card"],
                        fieldbackground=PALETTE["card"],
                        foreground=PALETTE["text"],
                        rowheight=24,
                        font=self.scaled_font_ui)
        style.configure("Treeview.Heading", background="#f1f3f7", foreground=PALETTE["text"], font=self.scaled_font_sub)
        # Build heading font from scaled sub font (ensure bold)
        try:
            heading_family = self.scaled_font_sub[0]
            heading_size = int(self.scaled_font_sub[1]) if len(self.scaled_font_sub) > 1 else 11
        except Exception:
            heading_family = FONT_SUB[0]
            heading_size = 11
        style.configure("Treeview.Heading",
                        background=PALETTE["card"],
                        foreground=PALETTE["muted"],
                        font=(heading_family, max(10, heading_size), "bold"))

        # Progressbar
        style.configure("Colored.Horizontal.TProgressbar", troughcolor=PALETTE["card"], background=PALETTE["accent"]) 
        
        # Frame principal (card)
        main_frame = ttk.Frame(self.root, padding="14", style="TFrame")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=12, pady=12)
        # Root bg
        try:
            self.root.configure(bg=PALETTE["bg"])
        except Exception:
            pass

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)

        # Bandeau titre
        banner = tk.Frame(main_frame, bg=PALETTE["accent"], height=64)
        banner.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 12))
        banner.grid_propagate(False)
        title_label = tk.Label(
            banner,
            text="🔍 Scanner de Ports Avancé",
            font=self.scaled_font_title,
            bg=PALETTE["accent"],
            fg="#ffffff"
        )
        title_label.pack(side=tk.LEFT, padx=18, pady=10)
        # small subtitle on right
        subtitle = tk.Label(banner, text="Interface graphique — gestion et diagnostics", font=self.scaled_font_sub, bg=PALETTE["accent"], fg="#e6f0ff")
        subtitle.pack(side=tk.RIGHT, padx=12)

        # Status admin
        status_fg = "#10b981" if self.is_admin else "#f59e0b"
        self.status_label = tk.Label(
            main_frame,
            text="⚠️ Privilèges administrateur non détectés" if not self.is_admin else "✅ Privilèges administrateur détectés",
            fg=status_fg,
            bg=PALETTE["bg"],
            font=self.scaled_font_sub
        )
        self.status_label.grid(row=1, column=0, columnspan=3, pady=(0, 6))

        # Frame de configuration
        config_frame = ttk.LabelFrame(main_frame, text="Configuration du Scan", padding="10")
        config_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        config_frame.columnconfigure(1, weight=1)

        # Cible
        ttk.Label(config_frame, text="Cible:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.target_var = tk.StringVar(value=DEFAULT_TARGET)
        self.target_entry = ttk.Entry(config_frame, textvariable=self.target_var, width=20)
        self.target_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))

        # Ports
        ttk.Label(config_frame, text="Ports:").grid(row=0, column=2, sticky=tk.W, padx=(10, 5))
        self.ports_var = tk.StringVar(value="common")
        self.ports_combo = ttk.Combobox(
            config_frame, 
            textvariable=self.ports_var,
            values=["common", "top1000", "top5000", "all", "1-1024", "22,80,443,3306"],
            width=15
        )
        self.ports_combo.grid(row=0, column=3, sticky=tk.W)

        # Options
        options_frame = ttk.Frame(config_frame)
        options_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(10, 0))

        self.show_dynamic_var = tk.BooleanVar(value=False)
        self.show_dynamic_check = ttk.Checkbutton(
            options_frame,
            text="Afficher les ports dynamiques",
            variable=self.show_dynamic_var
        )
        self.show_dynamic_check.grid(row=0, column=0, sticky=tk.W)

        # Boutons
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=3, column=0, columnspan=3, pady=6)

        self.scan_button = ttk.Button(
            buttons_frame,
            text="🚀 Démarrer le Scan",
            command=self.start_scan,
            style="Accent.TButton"
        )
        self.scan_button.grid(row=0, column=0, padx=(0, 10))

        self.stop_button = ttk.Button(
            buttons_frame,
            text="⏹️ Arrêter",
            command=self.stop_scan,
            state=tk.DISABLED,
            style="TButton"
        )
        self.stop_button.grid(row=0, column=1, padx=(0, 10))

        self.clear_button = ttk.Button(
            buttons_frame,
            text="🗑️ Effacer",
            command=self.clear_results,
            style="TButton"
        )
        self.clear_button.grid(row=0, column=2)

        self.help_button = ttk.Button(
            buttons_frame,
            text="❓ Aide",
            command=self.show_help_window,
            style="TButton"
        )
        self.help_button.grid(row=0, column=3, padx=(10,0))

        # Résultats
        results_frame = ttk.LabelFrame(main_frame, text="Résultats du Scan", padding="10")
        results_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        # Treeview pour les résultats
        self.tree = ttk.Treeview(
            results_frame,
            columns=("Port", "Service", "PID", "Processus", "Sécurité", "Actions"),
            show="headings",
            height=15
        )

        # Configuration des colonnes
        self.tree.heading("Port", text="Port")
        self.tree.heading("Service", text="Service")
        self.tree.heading("PID", text="PID")
        self.tree.heading("Processus", text="Processus")
        self.tree.heading("Sécurité", text="Sécurité")
        self.tree.heading("Actions", text="Actions")

        self.tree.column("Port", width=80, anchor=tk.CENTER)
        self.tree.column("Service", width=120)
        self.tree.column("PID", width=80, anchor=tk.CENTER)
        self.tree.column("Processus", width=200)
        self.tree.column("Sécurité", width=100, anchor=tk.CENTER)
        self.tree.column("Actions", width=150)

        # Scrollbars
        v_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.tree.xview)

        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))

        # Bind double-click pour actions
        self.tree.bind("<Double-1>", self.on_port_double_click)

        # Menu contextuel
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="🔧 Arrêter le service", command=self.stop_service)
        self.context_menu.add_command(label="💀 Tuer le processus", command=self.kill_process)
        self.context_menu.add_command(label="📋 Copier les détails", command=self.copy_details)
        self.tree.bind("<Button-3>", self.show_context_menu)

        # Barre de progression
        self.progress_frame = ttk.Frame(main_frame)
        self.progress_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        self.progress_frame.columnconfigure(0, weight=1)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.progress_frame,
            variable=self.progress_var,
            maximum=100,
            style="Colored.Horizontal.TProgressbar"
        )
        self.progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))

        self.progress_label = tk.Label(
            self.progress_frame,
            text="Prêt pour le scan",
            bg=PALETTE["bg"],
            fg=PALETTE["muted"],
            font=self.scaled_font_sub
        )
        self.progress_label.grid(row=0, column=1)

    # Note: responsive auto-scaling of fonts was removed because it caused
    # feedback loops in some environments. The UI uses grid weights and
    # proportional column widths set at startup instead.

    def classify_port(self, port, service_name, pid_infos, banner, target_ip):
        """Classe un port et renvoie une étiquette lisible et un niveau de sévérité.

        Retour: (label_str, severity) où severity dans ('low','medium','high','info')
        La classification combine règles heuristiques (numéros bien connus),
        l'information sur les processus (ex: processus root) et le contenu du banner.
        """
        # Normaliser
        service = (service_name or "").lower()
        b = (banner or "").lower()

        # Priorité: dynamique (plage éphémère)
        if 32768 <= port <= 65535:
            return ("🟢 Dynamique", 'low')

        # Flags basés sur PID (si disponible)
        runs_as_root = False
        try:
            for p in (pid_infos or []):
                if p.get('user') in ('root', '0', 'administrator'):
                    runs_as_root = True
                    break
        except Exception:
            runs_as_root = False

        # Lists of well-known ports
        remote_ports = {22, 3389, 5900, 23}
        web_ports = {80, 443, 8080, 8443}
        db_ports = {3306, 5432, 27017, 1433, 1521, 6379}
        mail_ports = {25, 587, 110, 143, 993, 995}
        fileshare_ports = {139, 445}
        insecure_plain = {21, 23, 69}

        # Detecteurs dans le banner
        is_http_banner = ('http/' in b) or ('server:' in b and 'http' in b)
        is_ssh_banner = b.startswith('ssh-') or 'openssh' in b

        # Assignation par port/service
        if port in remote_ports or 'ssh' in service or is_ssh_banner:
            label = "🔴 Critique — Accès distant"
            return (label + (" (root)" if runs_as_root else ""), 'high')

        if port in web_ports or 'http' in service or is_http_banner:
            # Differentier HTTP vs HTTPS
            if port in (443, 8443) or 'https' in service or 'ssl' in b or 'tls' in b:
                label = "🟡 Web — HTTPS"
                severity = 'medium'
            else:
                label = "🟡 Web — HTTP"
                severity = 'medium'
            if runs_as_root:
                severity = 'high'
                label += " (process root)"
            return (label, severity)

        if port in db_ports or any(k in service for k in ('mysql', 'postgres', 'mongodb', 'redis', 'mssql', 'oracle')):
            return ("🔴 Base de données — Critique", 'high')

        if port in mail_ports or any(k in service for k in ('smtp', 'imap', 'pop3')):
            return ("🟠 Mail — Vérifier authentification/relay", 'medium')

        if port in fileshare_ports or any(k in service for k in ('smb', 'cifs')):
            return ("🔴 Partage de fichiers — Sensible", 'high')

        if port in insecure_plain or any(k in service for k in ('telnet', 'ftp', 'tftp')):
            return ("🔴 Non chiffré — Insecure (cleartext)", 'high')

        # Privileged port check
        if port < 1024:
            if service_name and service_name.lower() not in ('unknown', 'port-dynamique'):
                return (f"🔒 Privilégié — {service_name}", 'medium')
            return ("🔒 Privilégié (port <1024)", 'medium')

        # Suspicious heuristics: unknown service and not common
        common_known = remote_ports | web_ports | db_ports | mail_ports | fileshare_ports | insecure_plain
        if (service_name is None or service_name.lower() in ('unknown', '')) and port not in common_known:
            return ("🔴 Suspicious — Service inconnu", 'high')

        # Default
        return ("🟡 Service", 'low')
    
    def start_scan(self):
        """Démarre le scan en arrière-plan"""
        if self.scan_running:
            return
        
        # Validation
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Erreur", "Veuillez spécifier une cible")
            return
        
        ports_arg = self.ports_var.get().strip()
        if not ports_arg:
            messagebox.showerror("Erreur", "Veuillez spécifier des ports")
            return
        
        self.scan_running = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.clear_results()
        
        # Démarrer le thread de scan
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(target, ports_arg),
            daemon=True
        )
        self.scan_thread.start()
    
    def run_scan(self, target, ports_arg):
        """Exécute le scan (dans un thread séparé)"""
        try:
            # Résolution DNS
            try:
                target_ip = socket.gethostbyname(target)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Erreur DNS", f"Impossible de résoudre {target}: {e}"))
                return
            
            # Parse des ports
            try:
                ports = parse_ports(ports_arg)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Erreur Ports", f"Format de ports invalide: {e}"))
                return
            
            num_ports = len(ports)
            self.root.after(0, lambda: self.progress_label.config(text=f"Scan de {num_ports} ports sur {target_ip}..."))
            
            # Configuration optimisée
            if num_ports > 10000:
                timeout = 0.3
                workers = min(1000, num_ports // 10)
            elif num_ports > 1000:
                timeout = 0.5
                workers = min(800, num_ports // 5)
            else:
                timeout = DEFAULT_TIMEOUT
                workers = min(DEFAULT_WORKERS, max(50, num_ports))
            
            # Scan
            scanned_count = 0
            open_ports = []
            
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(scan_port, target_ip, p, timeout): p for p in ports}
                
                for future in as_completed(futures):
                    if not self.scan_running:  # Check si arrêt demandé
                        break
                    
                    port, status, banner = future.result()
                    scanned_count += 1
                    
                    if status == "open":
                        open_ports.append((port, banner))
                    
                    # Mise à jour de la progression
                    progress = (scanned_count / num_ports) * 100
                    self.root.after(0, lambda p=progress: self.progress_var.set(p))
                    
                    if scanned_count % max(1, num_ports // 20) == 0:
                        self.root.after(0, lambda c=scanned_count, t=num_ports: 
                                       self.progress_label.config(text=f"Scanné {c}/{t} ports..."))
            
            if not self.scan_running:
                self.root.after(0, lambda: self.progress_label.config(text="Scan arrêté"))
                return
            
            # Filtrage des ports dynamiques
            show_dynamic = self.show_dynamic_var.get()
            if not show_dynamic:
                display_ports = [(p, b) for (p, b) in open_ports if get_service_info(p)[0] != "Port-Dynamique"]
            else:
                display_ports = open_ports[:]
            
            # Ajout des résultats à l'interface
            self.root.after(0, lambda: self.populate_results(display_ports, target_ip))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Erreur de Scan", f"Erreur durant le scan: {e}"))
        finally:
            self.root.after(0, self.scan_finished)
    
    def populate_results(self, open_ports, target_ip):
        """Remplit le tableau avec les résultats"""
        self.scan_results = []
        
        for port, banner in sorted(open_ports):
            service_name, service_cmd, _ = get_service_info(port)
            
            # Récupération des PID
            pid_infos = get_pids_for_port(port)
            if pid_infos:
                pid_display = ", ".join(f"{x['pid']}" for x in pid_infos)
                process_display = ", ".join(f"{x['name']}" for x in pid_infos)
            else:
                pid_display = "Inconnu"
                process_display = "Inconnu" if not self.is_admin else "Aucun"
            
            # Analyse de sécurité (heuristiques améliorées)
            security, _ = self.classify_port(port, service_name, pid_infos, banner, target_ip)
            
            # Ajout à l'arbre
            item_id = self.tree.insert("", tk.END, values=(
                port,
                service_name,
                pid_display,
                process_display[:30] + "..." if len(process_display) > 30 else process_display,
                security,
                "Double-clic"
            ))
            
            # Stockage des données complètes
            self.scan_results.append({
                "item_id": item_id,
                "port": port,
                "service_name": service_name,
                "service_cmd": service_cmd,
                "banner": banner,
                "pid_infos": pid_infos,
                "target_ip": target_ip
            })
        
        # Mise à jour du statut
        num_results = len(open_ports)
        if num_results == 0:
            status_text = "Aucun port ouvert détecté"
            if not self.show_dynamic_var.get():
                status_text += " (ports dynamiques masqués)"
        else:
            status_text = f"Scan terminé - {num_results} port(s) ouvert(s) trouvé(s)"
        
        self.progress_label.config(text=status_text)
        self.progress_var.set(100)
    
    def scan_finished(self):
        """Nettoie après la fin du scan"""
        self.scan_running = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
    
    def stop_scan(self):
        """Arrête le scan en cours"""
        self.scan_running = False
        self.progress_label.config(text="Arrêt du scan...")
    
    def clear_results(self):
        """Efface les résultats"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.scan_results = []
        self.progress_var.set(0)
        self.progress_label.config(text="Prêt pour le scan")
    
    def get_selected_result(self):
        """Récupère l'élément sélectionné"""
        selection = self.tree.selection()
        if not selection:
            return None
        
        item_id = selection[0]
        for result in self.scan_results:
            if result["item_id"] == item_id:
                return result
        return None
    
    def on_port_double_click(self, event):
        """Gère le double-clic sur un port"""
        # Obtenir l'élément cliqué directement depuis l'événement
        item = self.tree.identify('item', event.x, event.y)
        if not item:
            return
        
        # Sélectionner l'élément
        self.tree.selection_set(item)
        
        # Trouver le résultat correspondant
        result = None
        for res in self.scan_results:
            if res["item_id"] == item:
                result = res
                break
        
        if result:
            self.show_port_details(result)
        else:
            messagebox.showwarning("Erreur", "Impossible de trouver les détails de ce port")
    
    def show_context_menu(self, event):
        """Affiche le menu contextuel"""
        item = self.tree.identify('item', event.x, event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def show_port_details(self, result):
        """Affiche les détails d'un port dans une fenêtre popup"""
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Détails du Port {result['port']}")
        details_window.transient(self.root)
        # Taille proportionnelle à l'écran
        try:
            sw = int(self.root.winfo_screenwidth() or 1200)
            sh = int(self.root.winfo_screenheight() or 800)
            w = max(600, int(sw * 0.6))
            h = max(400, int(sh * 0.6))
            details_window.geometry(f"{w}x{h}")
        except Exception:
            details_window.geometry("800x600")
        details_window.resizable(True, True)
        details_window.configure(bg='white')
        # Center and set minimum size so buttons remain visible
        try:
            details_window.update_idletasks()
            sx = details_window.winfo_screenwidth()
            sy = details_window.winfo_screenheight()
            dx = int((sx - w) / 2) if 'w' in locals() else int((sx - 800) / 2)
            dy = int((sy - h) / 2) if 'h' in locals() else int((sy - 600) / 2)
            details_window.geometry(f"+{dx}+{dy}")
            details_window.minsize(int((w if 'w' in locals() else 800) * 0.6), int((h if 'h' in locals() else 600) * 0.5))
        except Exception:
            pass
        
        # Frame principal
        frame = tk.Frame(details_window, padx=10, pady=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Résumé
        summary_label = tk.Label(
            frame,
            text=f"Port {result['port']} - {result['service_name']} sur {result['target_ip']}",
            font=self.scaled_font_sub,
            bg='white',
            fg=PALETTE['text']
        )
        summary_label.pack(pady=(0, 10))
        
        # Informations
        # Use a readable monospace/code font for details when possible
        try:
            code_font = ("Courier", max(10, int(self.scaled_font_ui[1]) if len(self.scaled_font_ui) > 1 else 10))
        except Exception:
            code_font = ("Courier", 10)

        info_text = scrolledtext.ScrolledText(frame, height=20, wrap=tk.WORD, font=code_font)
        info_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Construire un affichage clair et robuste des détails
        details_lines = []
        details_lines.append(f"Service détecté : {result.get('service_name')}")
        details_lines.append(f"Service (cmd): {result.get('service_cmd') or 'Inconnu'}")
        details_lines.append(f"Cible: {result.get('target_ip')}")
        details_lines.append("")

        # Banner : afficher en repr si non-printable ou trop long
        banner = result.get('banner') or ''
        if banner:
            safe_banner = banner if all(32 <= ord(c) <= 126 for c in banner) else repr(banner)
            if len(safe_banner) > 100:
                safe_banner = safe_banner[:100] + "..."
            details_lines.append("Banner:")
            details_lines.append(safe_banner)
            details_lines.append("")

        # Si la cible n'est pas locale, indiquer que l'on ne peut pas récupérer les PID locaux
        local = is_local_target_strict(result.get('target_ip'))
        details_lines.append(f"Cible locale: {'Oui' if local else 'Non'}")
        details_lines.append("")

        # Récupérer et afficher les PIDs (rafraîchir au moment de l'ouverture)
        pid_infos = []
        if local:
            try:
                pid_infos = get_pids_for_port(result['port'])
            except Exception:
                pid_infos = result.get('pid_infos', []) or []
        else:
            pid_infos = []

        if pid_infos:
            details_lines.append("Processus trouvés :")
            for pid_info in pid_infos:
                cmdline = pid_info.get('cmd') or ''
                # Si cmdline est trop long, afficher complet sur une ligne séparée
                details_lines.append(f"  PID: {pid_info.get('pid')} | Nom: {pid_info.get('name')} | Utilisateur: {pid_info.get('user')}")
                details_lines.append(f"    CMD: {cmdline}")
                details_lines.append("")
        else:
            details_lines.append("Aucun PID trouvé localement pour ce port.")
            if not local:
                details_lines.append("(Cible distante — impossible de récupérer les PID locaux)")
            else:
                details_lines.append("(Exécutez l'application en mode administrateur/sudo pour obtenir plus d'informations sur les processus)")
            details_lines.append("")

        # Instructions utiles
        details_lines.append("Actions recommandées :")
        if result.get('service_cmd'):
            details_lines.append(f"  - Arrêter proprement le service: sudo systemctl stop {result.get('service_cmd')}")
        details_lines.append(f"  - Vérifier les PIDs via: sudo lsof -i :{result.get('port')} || sudo ss -ltnp | grep :{result.get('port')}")

        details = "\n".join(details_lines)
        info_text.insert(tk.END, details)
        # Mettre à jour l'affichage
        details_window.update()
        
        # Boutons d'action (utiliser polices mises à l'échelle)
        buttons_frame = tk.Frame(frame)
        buttons_frame.pack(fill=tk.X, pady=(10, 0))

        btn_font = self.scaled_font_ui

        # Bouton arrêter service
        stop_state = tk.NORMAL if self.is_admin and result['service_cmd'] else tk.DISABLED
        tk.Button(
            buttons_frame,
            text=f"🔧 Arrêter {result['service_cmd'] or 'service'}",
            command=lambda: self.stop_service_action(result, details_window),
            state=stop_state,
            font=btn_font
        ).pack(side=tk.LEFT, padx=(0, 5))

        # Bouton tuer processus
        kill_state = tk.NORMAL if self.is_admin and result['pid_infos'] else tk.DISABLED
        tk.Button(
            buttons_frame,
            text="💀 Tuer les processus",
            command=lambda: self.kill_process_action(result, details_window),
            state=kill_state,
            font=btn_font
        ).pack(side=tk.LEFT, padx=(0, 5))

        tk.Button(
            buttons_frame,
            text="📋 Copier",
            command=lambda: self.copy_to_clipboard(details),
            font=btn_font
        ).pack(side=tk.LEFT, padx=(0, 5))

        tk.Button(
            buttons_frame,
            text="Fermer",
            command=details_window.destroy,
            font=btn_font
        ).pack(side=tk.RIGHT)
        
        # Mettre à jour l'affichage and ensure focus so buttons are clickable
        try:
            details_window.update_idletasks()
            details_window.wait_visibility()
            details_window.lift()
            details_window.focus_force()
            details_window.grab_set()
        except Exception:
            # If grab_set fails (non-graphical X session), continue without modal grab
            pass
    
    def stop_service_action(self, result, parent_window):
        """Arrête un service"""
        if not self.is_admin:
            messagebox.showerror("Erreur", "Privilèges administrateur requis")
            return
        
        service_cmd = result['service_cmd']
        if not service_cmd:
            messagebox.showerror("Erreur", "Nom du service inconnu")
            return
        
        response = messagebox.askyesno(
            "Confirmation",
            f"Êtes-vous sûr de vouloir arrêter le service '{service_cmd}' ?"
        )
        
        if not response:
            return
        
        try:
            subprocess.check_output(["systemctl", "stop", service_cmd], stderr=subprocess.STDOUT)
            messagebox.showinfo("Succès", f"Service '{service_cmd}' arrêté avec succès")
            parent_window.destroy()
            # Rafraîchir la vue
            self.refresh_results()
        except subprocess.CalledProcessError as e:
            error = e.output.decode(errors="ignore") if hasattr(e, "output") else str(e)
            messagebox.showerror("Erreur", f"Impossible d'arrêter le service:\n{error}")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur: {e}")
    
    def kill_process_action(self, result, parent_window):
        """Tue les processus d'un port"""
        if not self.is_admin:
            messagebox.showerror("Erreur", "Privilèges administrateur requis")
            return
        
        if not result['pid_infos']:
            messagebox.showerror("Erreur", "Aucun PID trouvé")
            return
        
        pids = [info['pid'] for info in result['pid_infos']]
        response = messagebox.askyesno(
            "Confirmation",
            f"Êtes-vous sûr de vouloir tuer les processus {pids} ?\n"
            "⚠️ Attention: Cela peut causer une corruption de données!"
        )
        
        if not response:
            return
        
        try:
            results = kill_pids(pids, result['port'])
            success_count = sum(1 for ok, _ in results.values() if ok)
            total = len(results)
            
            if success_count == total:
                messagebox.showinfo("Succès", f"Tous les processus ({success_count}) ont été tués")
            else:
                messagebox.showwarning("Partiel", f"{success_count}/{total} processus tués avec succès")
            
            parent_window.destroy()
            self.refresh_results()
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'arrêt des processus: {e}")
    
    def refresh_results(self):
        """Rafraîchit les résultats après une action"""
        # Re-vérifie les PIDs et le statut des ports déjà affichés.
        # Pour chaque port affiché :
        # - si des PIDs existent, met à jour la colonne PID/Processus
        # - si aucun PID et le port est fermé, supprime la ligne
        # - si aucun PID mais le port reste ouvert, affiche "Inconnu" pour PID
        try:
            # Faire une copie car on peut modifier self.scan_results pendant l'itération
            for res in list(self.scan_results):
                port = res.get('port')
                target_ip = res.get('target_ip')

                # Récupérer les PIDs actuels (best-effort)
                try:
                    pids = get_pids_for_port(port)
                except Exception:
                    pids = []

                if pids:
                    pid_display = ", ".join(str(x['pid']) for x in pids)
                    process_display = ", ".join(x['name'] for x in pids)
                    # Recalculer l'étiquette de sécurité via la fonction centralisée
                    security, _ = self.classify_port(
                        port,
                        (res.get('service_name') or get_service_info(port)[0]),
                        pids,
                        res.get('banner'),
                        res.get('target_ip')
                    )

                    # Mettre à jour l'item tree
                    try:
                        self.tree.item(res['item_id'], values=(
                            port,
                            res.get('service_name') or get_service_info(port)[0],
                            pid_display,
                            (process_display[:30] + '...') if len(process_display) > 30 else process_display,
                            security,
                            'Double-clic'
                        ))
                    except Exception:
                        # si l'item n'existe plus, ignorer
                        pass
                    # Mettre à jour la structure mémoire
                    res['pid_infos'] = pids
                else:
                    # Aucun PID trouvé : vérifier si le port est toujours ouvert
                    try:
                        _, status, _ = scan_port(target_ip, port, DEFAULT_TIMEOUT)
                    except Exception:
                        status = 'filtered'

                    if status == 'open':
                        # Port ouvert mais PID inconnu
                        try:
                            self.tree.item(res['item_id'], values=(
                                port,
                                res.get('service_name') or get_service_info(port)[0],
                                'Inconnu',
                                'Inconnu',
                                '🟡 Service',
                                'Double-clic'
                            ))
                        except Exception:
                            pass
                        res['pid_infos'] = []
                    else:
                        # Port fermé -> supprimer la ligne
                        try:
                            self.tree.delete(res['item_id'])
                        except Exception:
                            pass
                        try:
                            self.scan_results.remove(res)
                        except ValueError:
                            pass

            # Mettre à jour le texte de statut
            remaining = len(self.scan_results)
            if remaining == 0:
                self.progress_label.config(text="Aucun port ouvert détecté")
                self.progress_var.set(0)
            else:
                self.progress_label.config(text=f"{remaining} port(s) restant(s)")
        except Exception as e:
            # Ne pas faire planter l'UI ; log pour debug
            print(f"Erreur lors du rafraîchissement des résultats: {e}")
    
    def stop_service(self):
        """Action menu contextuel - arrêter service"""
        result = self.get_selected_result()
        if result:
            self.show_port_details(result)
    
    def kill_process(self):
        """Action menu contextuel - tuer processus"""
        result = self.get_selected_result()
        if result:
            self.show_port_details(result)
    
    def copy_details(self):
        """Copie les détails dans le presse-papier"""
        result = self.get_selected_result()
        if result:
            details = f"Port {result['port']} ({result['service_name']})"
            self.copy_to_clipboard(details)
    
    def copy_to_clipboard(self, text):
        """Copie du texte dans le presse-papier"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copié", "Informations copiées dans le presse-papier")

    def show_help_window(self):
        """Affiche la fenêtre d'aide avec choix de langue."""
        # Language picker
        lang_choice = {"value": "fr"}
        picker = tk.Toplevel(self.root)
        picker.title("Choisir la langue / Choose language")
        picker.transient(self.root)
        # Taille proportionnelle pour éviter le texte tronqué
        try:
            sw = int(self.root.winfo_screenwidth() or 1200)
            sh = int(self.root.winfo_screenheight() or 800)
            w = max(520, int(sw * 0.45))
            h = max(220, int(sh * 0.25))
            picker.geometry(f"{w}x{h}")
        except Exception:
            picker.geometry("520x220")
        picker.minsize(520, 200)
        picker.columnconfigure(0, weight=1)
        picker.rowconfigure(1, weight=1)

        label = ttk.Label(
            picker,
            text="Choisissez la langue de l'aide / Choose help language:",
            anchor="center",
            justify="center",
            wraplength=max(420, int((w if 'w' in locals() else 520) * 0.9))
        )
        label.grid(row=0, column=0, sticky="ew", padx=16, pady=(18, 12))
        btn_frame = ttk.Frame(picker)
        btn_frame.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        # Center buttons
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=0)
        btn_frame.columnconfigure(2, weight=0)
        btn_frame.columnconfigure(3, weight=1)

        def pick(lang):
            lang_choice["value"] = lang
            picker.destroy()

        ttk.Button(btn_frame, text="Français", command=lambda: pick("fr"), style="Accent.TButton").grid(row=0, column=1, padx=8)
        ttk.Button(btn_frame, text="English", command=lambda: pick("en"), style="TButton").grid(row=0, column=2, padx=8)

        try:
            picker.grab_set()
        except Exception:
            pass
        picker.wait_window()

        help_text = HELP_TEXT if lang_choice["value"] == "fr" else HELP_TEXT_EN
        title = "Aide - Exemples et utilisation" if lang_choice["value"] == "fr" else "Help - Examples & usage"

        help_win = tk.Toplevel(self.root)
        help_win.title(title)
        help_win.transient(self.root)
        # Taille proportionnelle à l'écran
        try:
            sw = int(self.root.winfo_screenwidth() or 1200)
            sh = int(self.root.winfo_screenheight() or 800)
            w = max(720, int(sw * 0.6))
            h = max(520, int(sh * 0.6))
            help_win.geometry(f"{w}x{h}")
        except Exception:
            help_win.geometry("820x620")
        help_win.minsize(700, 500)
        help_win.columnconfigure(0, weight=1)
        help_win.rowconfigure(0, weight=1)
        help_win.rowconfigure(1, weight=0)

        txt = scrolledtext.ScrolledText(help_win, wrap=tk.WORD, font=("Courier", max(10, int(self.scaled_font_ui[1]) if len(self.scaled_font_ui) > 1 else 10)))
        txt.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)

        # Tags et styles pour le texte coloré
        heading_font = tkfont.Font(txt, txt.cget("font"))
        try:
            heading_font.configure(weight="bold", size=max(10, int(self.scaled_font_sub[1]) if len(self.scaled_font_sub) > 1 else 11))
        except Exception:
            heading_font.configure(weight="bold", size=11)
        try:
            code_font = tkfont.Font(family="Courier", size=max(10, int(self.scaled_font_ui[1]) if len(self.scaled_font_ui) > 1 else 10))
        except Exception:
            code_font = tkfont.Font(family="Courier", size=10)

        txt.tag_configure("heading", foreground="#1f4e79", font=heading_font)
        txt.tag_configure("code", background="#f5f5f5", font=code_font, foreground="#222222")
        txt.tag_configure("important", foreground="#b22222", font=heading_font)
        txt.tag_configure("bullet", foreground="#333333")

        # Insérer le HELP_TEXT ligne par ligne et appliquer des tags simples
        try:
            txt.config(state=tk.NORMAL)
            for line in help_text.splitlines():
                stripped = line.strip()
                start_index = txt.index(tk.INSERT)
                txt.insert(tk.END, line + "\n")

                # Heuristiques simples pour le style
                if not stripped:
                    continue
                if stripped.startswith(("Guide", "1)", "2)", "3)", "4)", "5)", "6)", "7)", "8)", "Questions")) or stripped.isupper():
                    txt.tag_add("heading", start_index, f"{start_index} lineend")
                elif stripped.startswith("sudo") or "python3" in stripped or line.startswith("    "):
                    txt.tag_add("code", start_index, f"{start_index} lineend")
                elif "Attention" in stripped or "Attention :" in stripped:
                    txt.tag_add("important", start_index, f"{start_index} lineend")
                elif stripped.startswith(('-', '*')):
                    txt.tag_add("bullet", start_index, f"{start_index} lineend")

            txt.config(state=tk.DISABLED)
        except Exception:
            txt.config(state=tk.NORMAL)
            txt.insert(tk.END, "Aide non disponible.")
            txt.config(state=tk.DISABLED)

        # Place the close button in a small bottom frame so it's always visible
        btn_frame = ttk.Frame(help_win)
        btn_frame.grid(row=1, column=0, sticky="ew")
        btn_frame.columnconfigure(0, weight=1)
        ttk.Button(btn_frame, text="Fermer", command=help_win.destroy).grid(row=0, column=0, sticky="e", padx=6, pady=6)

        # Ensure the help window is visible and raised (avoid grab_set which can be blocked)
        try:
            help_win.deiconify()
            help_win.lift()
            # Temporarily set topmost to ensure window manager raises it
            try:
                help_win.attributes("-topmost", True)
                help_win.update()
                help_win.attributes("-topmost", False)
            except Exception:
                # attributes may not be supported on some WMs
                pass
            help_win.focus_force()
        except Exception:
            pass

def main():
    """Point d'entrée principal"""
    try:
        root = tk.Tk()
        app = PortScannerGUI(root)
        root.mainloop()
    except KeyboardInterrupt:
        print("\nArrêt du programme")
    except Exception as e:
        import traceback
        print(f"Erreur: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    main()
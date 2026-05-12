#!/usr/bin/env python3
# Interface graphique Tkinter pour le scanner de ports avec privilèges admin

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import tkinter.font as tkfont
import sys
import os
import platform
import subprocess
import shutil
import threading
import time
import shlex
import tempfile
import csv
import json
from concurrent.futures import ThreadPoolExecutor
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
- "Scan UDP" : active un scan UDP (plus lent, résultats best-effort).

3) Contrôles principaux
- 🚀 Démarrer le Scan : lance le scan en arrière-plan et affiche la progression.
- ⏹️ Arrêter : stoppe le scan en cours (les résultats déjà trouvés restent affichés).
- 🗑️ Effacer : supprime toutes les lignes de résultats affichées.
- 📤 Export CSV/JSON : exporter les résultats.
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
- "UDP scan": enables UDP scan (slower, best-effort results).

3) Main controls
- 🚀 Start Scan: runs the scan in background and shows progress.
- ⏹️ Stop: stops the current scan (results already found stay visible).
- 🗑️ Clear: clears all results.
- 📤 Export CSV/JSON: export results.
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

def _system_font():
    import platform as _plat
    s = _plat.system().lower()
    if s.startswith("darwin"):
        return "SF Pro Text"
    if s.startswith("win"):
        return "Segoe UI"
    for name in ("Ubuntu", "Cantarell", "Noto Sans", "DejaVu Sans"):
        try:
            import tkinter as _tk, tkinter.font as _tf
            _r = _tk.Tk()
            _r.withdraw()
            families = _tf.families(_r)
            _r.destroy()
            if name in families:
                return name
        except Exception:
            pass
    return "TkDefaultFont"

_FF = _system_font()

PALETTE = {
    "bg":           "#f1f5f9",   # slate-100 window background
    "card":         "#ffffff",   # white panel
    "border":       "#e2e8f0",   # slate-200 subtle border
    "accent":       "#3b82f6",   # blue-500 primary action
    "accent_dark":  "#2563eb",   # blue-600 hover
    "accent_light": "#eff6ff",   # blue-50 selection bg
    "success":      "#10b981",   # emerald-500
    "success_bg":   "#ecfdf5",
    "warning":      "#f59e0b",   # amber-500
    "warning_bg":   "#fffbeb",
    "danger":       "#ef4444",   # red-500
    "text":         "#1e293b",   # slate-800
    "muted":        "#64748b",   # slate-500
    "light":        "#94a3b8",   # slate-400
    "header_bg":    "#0f172a",   # slate-900
    "header_fg":    "#f8fafc",   # slate-50
    "header_sub":   "#475569",   # slate-600
    "row_alt":      "#f8fafc",   # zebra stripe
}

FONT_TITLE = (_FF, 17, "bold")
FONT_SUB   = (_FF, 11, "bold")
FONT_UI    = (_FF, 10)


# Import des fonctions du scanner principal
try:
    from check_port import (
        parse_ports, scan_port, get_service_info, get_pids_for_port,
        kill_pids, is_local_target_strict,
        DEFAULT_TARGET, DEFAULT_TIMEOUT, DEFAULT_WORKERS
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
        self.scan_udp_var = tk.BooleanVar(value=False)

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

        def _terminate_self():
            try:
                self.root.after(0, self.root.destroy)
            except Exception:
                pass
            try:
                os._exit(0)
            except Exception:
                pass

        # If running as a PyInstaller executable, do not pass script_path
        frozen = getattr(sys, "frozen", False)

        try:
            # macOS / Linux flow: prefer graphical helpers, then terminal fallback, then sudo exec
            if "linux" in plat or "darwin" in plat:
                # Try macOS AppleScript first
                if "darwin" in plat:
                    try:
                        # Use osascript to run the script with administrator privileges (will show password prompt)
                        osa_cmd = f"do shell script \"{exe} '{script_path}'\" with administrator privileges"
                        subprocess.Popen(["osascript", "-e", osa_cmd])
                        _terminate_self()
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

                        if frozen:
                            exec_cmd = ' '.join(parts + [f'exec {shlex.quote(exe)}'])
                        else:
                            exec_cmd = ' '.join(parts + [f'exec {shlex.quote(exe)} {shlex.quote(script_path)}'])
                        shell_runner = ['/bin/sh', '-c', exec_cmd]
                        cmd = [pkexec_path] + shell_runner
                        subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
                        _terminate_self()
                        return
                    except Exception as e:
                        print(f"pkexec invocation error: {e}")

                # Try gksudo / kdesudo if available (older GUI sudo wrappers)
                for helper in ("gksudo", "kdesudo"):
                    helper_path = shutil.which(helper)
                    if helper_path:
                        try:
                            if frozen:
                                subprocess.Popen([helper_path, exe])
                            else:
                                subprocess.Popen([helper_path, exe, script_path])
                            _terminate_self()
                            return
                        except Exception:
                            continue

                # Fallback: open a terminal emulator that runs sudo so the user sees a password prompt
                def launch_terminal_sudo(exe, script_path):
                    marker = os.path.join(tempfile.gettempdir(), f"scan_port_admin_ready_{os.getpid()}")
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

                    if frozen:
                        sudo_cmd = f"sudo -k SCAN_PORT_ADMIN_READY={marker} SCAN_PORT_PARENT_PID={os.getpid()} {shlex.quote(exe)}"
                    else:
                        sudo_cmd = f"sudo -k SCAN_PORT_ADMIN_READY={marker} SCAN_PORT_PARENT_PID={os.getpid()} {shlex.quote(exe)} '{script_path}'"
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
                                # Fallback: close parent shortly after launching
                                try:
                                    self.root.after(500, _terminate_self)
                                except Exception:
                                    pass
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
                _terminate_self()
                if frozen:
                    os.execvp('sudo', ['sudo', exe])
                else:
                    os.execvp('sudo', ['sudo', exe, script_path])

            elif "windows" in plat:
                import ctypes
                # Use ShellExecute 'runas' to trigger UAC; pass the script path as parameter
                params = f'"{script_path}"'
                try:
                    ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
                    if int(ret) > 32:
                        # launched successfully; exit current GUI
                        _terminate_self()
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

    def _make_card(self, parent, padx=12, pady=8):
        """White card with a 1-px border, returns the inner frame."""
        outer = tk.Frame(parent, bg=PALETTE["border"])
        inner = tk.Frame(outer, bg=PALETTE["card"], padx=padx, pady=pady)
        inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        return outer, inner

    def _add_hover(self, widget, style_normal, style_active):
        widget.bind("<Enter>", lambda _: widget.configure(style=style_active))
        widget.bind("<Leave>", lambda _: widget.configure(style=style_normal))

    def setup_ui(self):
        """Configure l'interface utilisateur"""
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass

        ff = self.scaled_font_ui[0]
        fs = self.scaled_font_ui[1] if len(self.scaled_font_ui) > 1 else 10

        # ── Base ──────────────────────────────────────────────────────────────
        style.configure("TFrame",    background=PALETTE["bg"])
        style.configure("TLabel",    background=PALETTE["bg"],   foreground=PALETTE["text"],  font=self.scaled_font_ui)
        style.configure("Card.TFrame", background=PALETTE["card"])
        style.configure("Card.TLabel", background=PALETTE["card"], foreground=PALETTE["text"], font=self.scaled_font_ui)
        style.configure("Muted.TLabel", background=PALETTE["card"], foreground=PALETTE["muted"], font=(ff, max(9, fs-1)))

        # ── Buttons ───────────────────────────────────────────────────────────
        btn_pad = (14, 7)
        style.configure("TButton",
            background=PALETTE["card"], foreground=PALETTE["text"],
            font=self.scaled_font_ui, padding=btn_pad,
            relief="flat", borderwidth=1, focusthickness=0,
        )
        style.map("TButton",
            background=[("active", PALETTE["bg"]), ("pressed", PALETTE["border"]), ("disabled", PALETTE["border"])],
            foreground=[("disabled", PALETTE["light"])],
            relief=[("pressed", "flat")],
        )

        style.configure("Primary.TButton",
            background=PALETTE["accent"], foreground="#ffffff",
            font=(ff, fs, "bold"), padding=btn_pad,
            relief="flat", borderwidth=0, focusthickness=0,
        )
        style.map("Primary.TButton",
            background=[("active", PALETTE["accent_dark"]), ("pressed", PALETTE["accent_dark"]), ("disabled", PALETTE["border"])],
            foreground=[("disabled", PALETTE["light"])],
        )

        style.configure("Stop.TButton",
            background="#fef2f2", foreground=PALETTE["danger"],
            font=self.scaled_font_ui, padding=btn_pad,
            relief="flat", borderwidth=1, focusthickness=0,
        )
        style.map("Stop.TButton",
            background=[("active", "#fee2e2"), ("pressed", "#fecaca"), ("disabled", PALETTE["border"])],
            foreground=[("disabled", PALETTE["light"])],
        )

        # ── Inputs ────────────────────────────────────────────────────────────
        style.configure("TEntry",
            fieldbackground=PALETTE["card"], foreground=PALETTE["text"],
            background=PALETTE["card"], insertcolor=PALETTE["text"],
            borderwidth=1, padding=(6, 4),
        )
        style.configure("TCombobox",
            fieldbackground=PALETTE["card"], foreground=PALETTE["text"],
            background=PALETTE["card"], arrowsize=12, borderwidth=1,
        )
        style.configure("TCheckbutton",
            background=PALETTE["card"], foreground=PALETTE["text"],
            font=self.scaled_font_ui,
        )
        style.map("TCheckbutton", background=[("active", PALETTE["card"])])

        # ── Treeview ──────────────────────────────────────────────────────────
        style.configure("Treeview",
            background=PALETTE["card"], fieldbackground=PALETTE["card"],
            foreground=PALETTE["text"], rowheight=28,
            font=self.scaled_font_ui, borderwidth=0, relief="flat",
        )
        style.configure("Treeview.Heading",
            background=PALETTE["bg"], foreground=PALETTE["muted"],
            font=(ff, max(9, fs), "bold"), relief="flat", padding=(8, 6),
        )
        style.map("Treeview",
            background=[("selected", PALETTE["accent_light"])],
            foreground=[("selected", PALETTE["accent_dark"])],
        )
        style.map("Treeview.Heading",
            background=[("active", PALETTE["border"])],
        )

        # ── Scrollbar ─────────────────────────────────────────────────────────
        style.configure("TScrollbar",
            background=PALETTE["bg"], troughcolor=PALETTE["bg"],
            borderwidth=0, arrowsize=12,
        )
        style.map("TScrollbar", background=[("active", PALETTE["border"])])

        # ── Progressbar ───────────────────────────────────────────────────────
        style.configure("Modern.Horizontal.TProgressbar",
            troughcolor=PALETTE["border"], background=PALETTE["accent"],
            borderwidth=0, thickness=6,
        )

        # ─────────────────────────────────────────────────────────────────────
        # Root setup
        # ─────────────────────────────────────────────────────────────────────
        try:
            self.root.configure(bg=PALETTE["bg"])
        except Exception:
            pass
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        wrap = ttk.Frame(self.root, style="TFrame")
        wrap.grid(row=0, column=0, sticky="nsew")
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(3, weight=1)

        # ─────────────────────────────────────────────────────────────────────
        # Header — dark navy bar
        # ─────────────────────────────────────────────────────────────────────
        header = tk.Frame(wrap, bg=PALETTE["header_bg"], height=70)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        header.columnconfigure(1, weight=1)

        left_pad = tk.Frame(header, bg=PALETTE["header_bg"])
        left_pad.grid(row=0, column=0, sticky="ns", padx=(18, 0))

        dot = tk.Label(left_pad, text="●", font=(ff, 22), bg=PALETTE["header_bg"], fg=PALETTE["accent"])
        dot.pack(side=tk.LEFT, padx=(0, 10), pady=16)

        title_stack = tk.Frame(left_pad, bg=PALETTE["header_bg"])
        title_stack.pack(side=tk.LEFT, pady=14)
        tk.Label(title_stack, text="Port Scanner", font=self.scaled_font_title,
                 bg=PALETTE["header_bg"], fg=PALETTE["header_fg"]).pack(anchor="w")
        tk.Label(title_stack, text="Analyse & Diagnostic Réseau",
                 font=(ff, max(9, fs - 1)), bg=PALETTE["header_bg"], fg=PALETTE["header_sub"]).pack(anchor="w")

        # Admin status badge on the right
        if self.is_admin:
            badge_bg, badge_fg, badge_txt = PALETTE["success"], "#ffffff", " ✓ Administrateur "
        else:
            badge_bg, badge_fg, badge_txt = "#92400e", "#fef3c7", " ⚠ Mode limité "
        self.status_label = tk.Label(
            header, text=badge_txt,
            bg=badge_bg, fg=badge_fg,
            font=(ff, max(9, fs - 1), "bold"),
            padx=2, pady=2, relief="flat",
        )
        self.status_label.grid(row=0, column=2, sticky="e", padx=18)

        # ─────────────────────────────────────────────────────────────────────
        # Configuration card
        # ─────────────────────────────────────────────────────────────────────
        cfg_outer, cfg_card = self._make_card(wrap, padx=14, pady=12)
        cfg_outer.grid(row=1, column=0, sticky="ew", padx=12, pady=(10, 0))
        cfg_card.columnconfigure(1, weight=1)
        cfg_card.columnconfigure(5, weight=1)

        # Section label
        tk.Label(cfg_card, text="CONFIGURATION DU SCAN",
                 bg=PALETTE["card"], fg=PALETTE["muted"],
                 font=(ff, max(8, fs - 2), "bold")).grid(
            row=0, column=0, columnspan=6, sticky="w", pady=(0, 8))

        # Cible
        tk.Label(cfg_card, text="Cible", bg=PALETTE["card"], fg=PALETTE["muted"],
                 font=(ff, max(9, fs - 1), "bold")).grid(row=1, column=0, sticky="w", padx=(0, 6))
        self.target_var = tk.StringVar(value=DEFAULT_TARGET)
        self.target_entry = ttk.Entry(cfg_card, textvariable=self.target_var, width=22)
        self.target_entry.grid(row=1, column=1, sticky="ew", padx=(0, 18))

        # Ports
        tk.Label(cfg_card, text="Ports", bg=PALETTE["card"], fg=PALETTE["muted"],
                 font=(ff, max(9, fs - 1), "bold")).grid(row=1, column=2, sticky="w", padx=(0, 6))
        self.ports_var = tk.StringVar(value="common")
        self.ports_var.trace_add("write", lambda *args: self.update_udp_availability())
        self.ports_combo = ttk.Combobox(
            cfg_card, textvariable=self.ports_var, width=16,
            values=["common", "top1000", "top5000", "all", "1-1024", "22,80,443,3306"],
        )
        self.ports_combo.grid(row=1, column=3, sticky="w", padx=(0, 18))

        # Options row
        opts = tk.Frame(cfg_card, bg=PALETTE["card"])
        opts.grid(row=2, column=0, columnspan=6, sticky="w", pady=(10, 0))

        self.show_dynamic_var = tk.BooleanVar(value=False)
        self.show_dynamic_check = ttk.Checkbutton(
            opts, text="Afficher les ports dynamiques",
            variable=self.show_dynamic_var, style="TCheckbutton",
        )
        self.show_dynamic_check.pack(side=tk.LEFT)

        self.scan_udp_check = ttk.Checkbutton(
            opts, text="Scan UDP  (plus lent)",
            variable=self.scan_udp_var, style="TCheckbutton",
        )
        self.scan_udp_check.pack(side=tk.LEFT, padx=(20, 0))

        self.udp_hint = tk.Label(
            opts, text="— auto-désactivé sur les gros scans",
            bg=PALETTE["card"], fg=PALETTE["light"],
            font=(ff, max(9, fs - 1)),
        )
        self.udp_hint.pack(side=tk.LEFT, padx=(6, 0))

        # ─────────────────────────────────────────────────────────────────────
        # Action toolbar
        # ─────────────────────────────────────────────────────────────────────
        toolbar = tk.Frame(wrap, bg=PALETTE["bg"])
        toolbar.grid(row=2, column=0, sticky="ew", padx=12, pady=(6, 4))

        self.scan_button = ttk.Button(
            toolbar, text="▶  Démarrer le Scan",
            command=self.start_scan, style="Primary.TButton",
        )
        self.scan_button.pack(side=tk.LEFT, padx=(0, 6))

        self.stop_button = ttk.Button(
            toolbar, text="■  Arrêter",
            command=self.stop_scan, state=tk.DISABLED, style="Stop.TButton",
        )
        self.stop_button.pack(side=tk.LEFT, padx=(0, 6))

        self.clear_button = ttk.Button(
            toolbar, text="✕  Effacer",
            command=self.clear_results, style="TButton",
        )
        self.clear_button.pack(side=tk.LEFT, padx=(0, 18))

        # Separator
        sep = tk.Frame(toolbar, bg=PALETTE["border"], width=1, height=28)
        sep.pack(side=tk.LEFT, padx=(0, 18), pady=4)

        self.export_csv_button = ttk.Button(
            toolbar, text="↑  CSV",
            command=lambda: self.export_results("csv"), style="TButton",
        )
        self.export_csv_button.pack(side=tk.LEFT, padx=(0, 6))

        self.export_json_button = ttk.Button(
            toolbar, text="↑  JSON",
            command=lambda: self.export_results("json"), style="TButton",
        )
        self.export_json_button.pack(side=tk.LEFT, padx=(0, 18))

        sep2 = tk.Frame(toolbar, bg=PALETTE["border"], width=1, height=28)
        sep2.pack(side=tk.LEFT, padx=(0, 18), pady=4)

        self.help_button = ttk.Button(
            toolbar, text="?  Aide",
            command=self.show_help_window, style="TButton",
        )
        self.help_button.pack(side=tk.LEFT)

        # ─────────────────────────────────────────────────────────────────────
        # Results card
        # ─────────────────────────────────────────────────────────────────────
        res_outer, res_card = self._make_card(wrap, padx=0, pady=0)
        res_outer.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 4))
        res_card.columnconfigure(0, weight=1)
        res_card.rowconfigure(1, weight=1)

        # Results header bar
        res_header = tk.Frame(res_card, bg=PALETTE["bg"])
        res_header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=0, pady=0)
        tk.Label(res_header, text="RÉSULTATS DU SCAN",
                 bg=PALETTE["bg"], fg=PALETTE["muted"],
                 font=(ff, max(8, fs - 2), "bold")).pack(
            side=tk.LEFT, padx=12, pady=6)

        # Treeview
        self.tree = ttk.Treeview(
            res_card,
            columns=("Proto", "Port", "Service", "PID", "Processus", "Sécurité", "Actions"),
            show="headings", selectmode="browse",
        )
        col_defs = [
            ("Proto",     64,  tk.CENTER),
            ("Port",      72,  tk.CENTER),
            ("Service",   130, tk.W),
            ("PID",       80,  tk.CENTER),
            ("Processus", 200, tk.W),
            ("Sécurité",  220, tk.W),
            ("Actions",   90,  tk.CENTER),
        ]
        for col, w, anchor in col_defs:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor=anchor, minwidth=w // 2)

        # Zebra stripe tags
        self.tree.tag_configure("row_even", background=PALETTE["card"])
        self.tree.tag_configure("row_odd",  background=PALETTE["row_alt"])

        v_sb = ttk.Scrollbar(res_card, orient=tk.VERTICAL,   command=self.tree.yview)
        h_sb = ttk.Scrollbar(res_card, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_sb.set, xscrollcommand=h_sb.set)

        self.tree.grid(row=1, column=0, sticky="nsew")
        v_sb.grid(row=1, column=1, sticky="ns")
        h_sb.grid(row=2, column=0, sticky="ew")

        self.tree.bind("<Double-1>", self.on_port_double_click)

        # Context menu
        self.context_menu = tk.Menu(self.root, tearoff=0,
            bg=PALETTE["card"], fg=PALETTE["text"],
            activebackground=PALETTE["accent_light"],
            activeforeground=PALETTE["accent_dark"],
            font=self.scaled_font_ui,
        )
        self.context_menu.add_command(label="🔧  Arrêter le service",  command=self.stop_service)
        self.context_menu.add_command(label="💀  Tuer le processus",   command=self.kill_process)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📋  Copier les détails",  command=self.copy_details)
        self.tree.bind("<Button-3>", self.show_context_menu)

        # ─────────────────────────────────────────────────────────────────────
        # Progress footer
        # ─────────────────────────────────────────────────────────────────────
        footer = tk.Frame(wrap, bg=PALETTE["bg"])
        footer.grid(row=4, column=0, sticky="ew", padx=12, pady=(0, 10))
        footer.columnconfigure(0, weight=1)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            footer, variable=self.progress_var, maximum=100,
            style="Modern.Horizontal.TProgressbar",
        )
        self.progress_bar.grid(row=0, column=0, sticky="ew", padx=(0, 12))

        self.progress_label = tk.Label(
            footer, text="Prêt",
            bg=PALETTE["bg"], fg=PALETTE["muted"],
            font=(ff, max(9, fs - 1)),
        )
        self.progress_label.grid(row=0, column=1, sticky="e")

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
    
        def should_disable_udp(num_ports):
            # Disable UDP on very large scans to prevent UI freeze
            return num_ports >= 50000

    def update_udp_availability(self):
        try:
            ports_arg = (self.ports_var.get() or '').strip()
            is_all = ports_arg.lower() == 'all'
            ports_preview = parse_ports(ports_arg) if ports_arg else []
            too_big = len(ports_preview) >= 50000
            if is_all or too_big:
                self.scan_udp_var.set(False)
                self.scan_udp_check.state(['disabled'])
            else:
                self.scan_udp_check.state(['!disabled'])
        except Exception:
            pass

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

        # Auto-disable UDP on huge scans to avoid freezing
        try:
            ports_preview = parse_ports(ports_arg)
            if self.should_disable_udp(len(ports_preview)) and self.scan_udp_var.get():
                self.scan_udp_var.set(False)
                messagebox.showinfo(
                    "UDP désactivé",
                    "Le scan UDP est désactivé automatiquement pour les très gros scans (>= 50 000 ports).\n"
                    "Pour éviter les blocages, choisissez un preset plus petit."
                )
        except Exception:
            pass
        
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
                self.root.after(0, lambda e=e: messagebox.showerror("Erreur DNS", f"Impossible de résoudre {target}: {e}"))
                return
            
            # Parse des ports
            try:
                ports = parse_ports(ports_arg)
            except Exception as e:
                self.root.after(0, lambda e=e: messagebox.showerror("Erreur Ports", f"Format de ports invalide: {e}"))
                return
            
            num_ports = len(ports)
            proto_note = "TCP" + (" + UDP" if self.scan_udp_var.get() else "")
            self.root.after(0, lambda: self.progress_label.config(text=f"Scan de {num_ports} ports ({proto_note}) sur {target_ip}..."))
            
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

            if self.scan_udp_var.get():
                timeout = min(timeout, 0.2)
                workers = min(workers, 300)
            
            # Scan
            scanned_count = 0
            open_ports = []

            protocols = ["tcp"] + (["udp"] if self.scan_udp_var.get() else [])
            total_tasks = len(ports) * len(protocols)

            stall_limit = 30  # seconds without progress before cancel
            last_progress = time.time()
            
            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_map = {executor.submit(scan_port, target_ip, p, timeout, proto): (p, proto) for proto in protocols for p in ports}
                pending = set(future_map.keys())

                while pending:
                    if not self.scan_running:
                        break

                    done, pending = set(), pending
                    try:
                        from concurrent.futures import wait, FIRST_COMPLETED
                        done, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                    except Exception:
                        done = set()

                    if not done:
                        # no progress
                        if time.time() - last_progress > stall_limit:
                            for f in list(pending):
                                f.cancel()
                            break
                        continue

                    last_progress = time.time()
                    for future in done:
                        try:
                            port, status, banner = future.result()
                        except Exception:
                            continue
                        _, proto = future_map.get(future, (None, "tcp"))
                        scanned_count += 1

                        if status == "open":
                            open_ports.append((port, banner, proto))

                        # Mise à jour de la progression
                        progress = (scanned_count / total_tasks) * 100
                        self.root.after(0, lambda p=progress: self.progress_var.set(p))

                        if scanned_count % max(1, total_tasks // 20) == 0:
                            self.root.after(0, lambda c=scanned_count, t=total_tasks: 
                                           self.progress_label.config(text=f"Scanné {c}/{t} tâches..."))
            
            if not self.scan_running:
                self.root.after(0, lambda: self.progress_label.config(text="Scan arrêté"))
                return
            
            # Filtrage des ports dynamiques
            show_dynamic = self.show_dynamic_var.get()
            if not show_dynamic:
                display_ports = [(p, b, proto) for (p, b, proto) in open_ports if get_service_info(p)[0] != "Port-Dynamique"]
            else:
                display_ports = open_ports[:]
            
            # Ajout des résultats à l'interface
            self.root.after(0, lambda: self.populate_results(display_ports, target_ip))
            
        except Exception as e:
            self.root.after(0, lambda e=e: messagebox.showerror("Erreur de Scan", f"Erreur durant le scan: {e}"))
        finally:
            self.root.after(0, self.scan_finished)
    
    def populate_results(self, open_ports, target_ip):
        """Remplit le tableau avec les résultats"""
        self.scan_results = []
        row_idx = 0

        for port, banner, proto in sorted(open_ports, key=lambda x: (x[2], x[0])):
            service_name, service_cmd, _ = get_service_info(port)

            pid_infos = get_pids_for_port(port)
            if pid_infos:
                pid_display = ", ".join(f"{x['pid']}" for x in pid_infos)
                process_display = ", ".join(f"{x['name']}" for x in pid_infos)
            else:
                pid_display = "—"
                process_display = "—" if not self.is_admin else "Aucun"

            security, _ = self.classify_port(port, service_name, pid_infos, banner, target_ip)

            row_tag = "row_even" if row_idx % 2 == 0 else "row_odd"
            item_id = self.tree.insert("", tk.END, tags=(row_tag,), values=(
                proto.upper(),
                port,
                service_name,
                pid_display,
                process_display[:32] + "…" if len(process_display) > 32 else process_display,
                security,
                "↗ Détails",
            ))
            row_idx += 1

            self.scan_results.append({
                "item_id": item_id,
                "protocol": proto,
                "port": port,
                "service_name": service_name,
                "service_cmd": service_cmd,
                "banner": banner,
                "pid_infos": pid_infos,
                "target_ip": target_ip,
            })

        num_results = len(open_ports)
        if num_results == 0:
            status_text = "Aucun port ouvert"
            if not self.show_dynamic_var.get():
                status_text += " (ports dynamiques masqués)"
        else:
            status_text = f"Scan terminé — {num_results} port(s) ouvert(s)"

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

    def export_results(self, fmt="csv"):
        """Exporte les résultats en CSV ou JSON"""
        if not self.scan_results:
            messagebox.showinfo("Export", "Aucun résultat à exporter")
            return

        ts = time.strftime("%Y%m%d_%H%M%S")
        default_name = f"scan_results_{ts}.{fmt}"
        filetypes = [(f"{fmt.upper()} files", f"*.{fmt}")]

        path = filedialog.asksaveasfilename(defaultextension=f".{fmt}", filetypes=filetypes, initialfile=default_name)
        if not path:
            return

        try:
            rows = []
            for r in self.scan_results:
                rows.append({
                    "protocol": r.get("protocol", "tcp"),
                    "port": r.get("port"),
                    "service_name": r.get("service_name"),
                    "service_cmd": r.get("service_cmd"),
                    "banner": r.get("banner"),
                    "pid_infos": r.get("pid_infos", []),
                    "target_ip": r.get("target_ip"),
                })

            if fmt == "json":
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(rows, f, ensure_ascii=False, indent=2)
            else:
                with open(path, "w", encoding="utf-8", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=["protocol", "port", "service_name", "service_cmd", "banner", "pid_infos", "target_ip"])
                    writer.writeheader()
                    for row in rows:
                        row = row.copy()
                        row["pid_infos"] = "; ".join([f"{p.get('pid')}:{p.get('name')}" for p in row.get("pid_infos", [])])
                        writer.writerow(row)

            messagebox.showinfo("Export", f"Export réussi: {path}")
        except Exception as e:
            messagebox.showerror("Export", f"Erreur export: {e}")
    
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
        dw = tk.Toplevel(self.root)
        dw.title(f"Port {result['port']} — {result.get('service_name', '')}")
        dw.transient(self.root)
        dw.configure(bg=PALETTE["bg"])
        try:
            sw = int(self.root.winfo_screenwidth() or 1200)
            sh = int(self.root.winfo_screenheight() or 800)
            w = max(640, int(sw * 0.55))
            h = max(440, int(sh * 0.55))
            dw.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
            dw.minsize(560, 380)
        except Exception:
            dw.geometry("720x520")
        dw.resizable(True, True)

        # Header
        hdr = tk.Frame(dw, bg=PALETTE["header_bg"], height=52)
        hdr.pack(fill=tk.X)
        hdr.pack_propagate(False)
        proto = (result.get('protocol') or 'tcp').upper()
        tk.Label(hdr,
                 text=f"{proto}  :{result['port']}  —  {result.get('service_name','?')}  @  {result.get('target_ip','')}",
                 bg=PALETTE["header_bg"], fg=PALETTE["header_fg"],
                 font=self.scaled_font_sub).pack(side=tk.LEFT, padx=16, pady=12)

        # Body
        body = tk.Frame(dw, bg=PALETTE["bg"], padx=12, pady=8)
        body.pack(fill=tk.BOTH, expand=True)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)

        ff = self.scaled_font_ui[0]
        fs = self.scaled_font_ui[1] if len(self.scaled_font_ui) > 1 else 10
        mono = "Consolas" if platform.system().lower().startswith("win") else "Monaco" if platform.system().lower().startswith("dar") else "DejaVu Sans Mono"
        code_font = (mono, max(9, fs - 1))

        info_text = scrolledtext.ScrolledText(
            body, wrap=tk.WORD, font=code_font,
            bg=PALETTE["card"], fg=PALETTE["text"],
            selectbackground=PALETTE["accent_light"],
            relief="flat", borderwidth=0, padx=10, pady=8,
        )
        info_text.grid(row=0, column=0, sticky="nsew", pady=(0, 8))

        # Build details text
        local = is_local_target_strict(result.get('target_ip'))
        pid_infos = []
        if local:
            try:
                pid_infos = get_pids_for_port(result['port'])
            except Exception:
                pid_infos = result.get('pid_infos', []) or []

        lines = [
            f"Service   : {result.get('service_name')}",
            f"Commande  : {result.get('service_cmd') or '—'}",
            f"Protocole : {proto}",
            f"Cible     : {result.get('target_ip')}  ({'locale' if local else 'distante'})",
            "",
        ]
        banner = result.get('banner') or ''
        if banner:
            safe = banner if all(32 <= ord(c) <= 126 for c in banner) else repr(banner)
            lines += ["Banner :", f"  {safe[:120]}{'…' if len(safe) > 120 else ''}", ""]

        if pid_infos:
            lines.append("Processus :")
            for p in pid_infos:
                lines.append(f"  PID {p.get('pid')}  {p.get('name')}  [{p.get('user')}]")
                if p.get('cmd'):
                    lines.append(f"    {p.get('cmd')}")
            lines.append("")
        else:
            msg = "(cible distante)" if not local else "(relancer en sudo pour voir les PIDs)"
            lines += [f"Aucun PID trouvé {msg}", ""]

        lines += [
            "Commandes utiles :",
            f"  sudo ss -ltnp | grep :{result.get('port')}",
            f"  sudo lsof -i :{result.get('port')}",
        ]
        if result.get('service_cmd'):
            lines.append(f"  sudo systemctl stop {result.get('service_cmd')}")

        details = "\n".join(lines)
        info_text.insert(tk.END, details)
        info_text.config(state=tk.DISABLED)

        # Action buttons
        btn_bar = tk.Frame(body, bg=PALETTE["bg"])
        btn_bar.grid(row=1, column=0, sticky="ew")

        stop_state  = tk.NORMAL if self.is_admin and result.get('service_cmd') else tk.DISABLED
        kill_state  = tk.NORMAL if self.is_admin and result.get('pid_infos') else tk.DISABLED

        ttk.Button(btn_bar, text="🔧 Arrêter service",
                   command=lambda: self.stop_service_action(result, dw),
                   state=stop_state, style="TButton").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_bar, text="💀 Tuer processus",
                   command=lambda: self.kill_process_action(result, dw),
                   state=kill_state, style="Stop.TButton").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_bar, text="📋 Copier",
                   command=lambda: self.copy_to_clipboard(details),
                   style="TButton").pack(side=tk.LEFT)
        ttk.Button(btn_bar, text="Fermer",
                   command=dw.destroy,
                   style="Primary.TButton").pack(side=tk.RIGHT)

        try:
            dw.update_idletasks()
            dw.wait_visibility()
            dw.lift()
            dw.focus_force()
            dw.grab_set()
        except Exception:
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
            proto = (result.get('protocol') or 'tcp').upper()
            details = f"{proto} Port {result['port']} ({result['service_name']})"
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
        PortScannerGUI(root)
        root.mainloop()
    except KeyboardInterrupt:
        print("\nArrêt du programme")
    except Exception as e:
        import traceback
        print(f"Erreur: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    main()
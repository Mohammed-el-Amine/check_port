#!/usr/bin/env python3
"""Interface graphique moderne (PySide6) — scanner asyncio + enrichissement."""
from __future__ import annotations

import asyncio
import csv
import json
import os
import shutil
import subprocess
import sys
import socket
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal, QSortFilterProxyModel
from PySide6.QtGui import QFont, QColor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QComboBox, QCheckBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QProgressBar, QFileDialog, QMessageBox,
    QFrame, QTextEdit, QDialog, QStatusBar, QMenu, QTabWidget, QPlainTextEdit,
)

from check_port import parse_ports, is_local_target_strict, kill_pids, DEFAULT_TARGET
from async_scanner import scan as async_scan
from enrich import enrich_port


# ------------------------------ Theme (macOS-like) ------------------------- #
QSS = """
* { font-family: -apple-system, "SF Pro Text", "Helvetica Neue", "Inter", "Segoe UI", system-ui, sans-serif; font-size: 13px; color: #1d1d1f; }
QMainWindow, QDialog { background: #ececec; }
#Header { background: transparent; }
#HeaderTitle { color: #1d1d1f; font-size: 19px; font-weight: 600; letter-spacing: -0.2px; }
#HeaderSub   { color: #6e6e73; font-size: 12px; }
#BadgePill { padding: 3px 10px; border-radius: 10px; background: #e8f5ee; color: #1f7a3f; font-size: 11px; font-weight: 600; }
#BadgePillWarn { padding: 3px 10px; border-radius: 10px; background: #fff3e0; color: #9a4a00; font-size: 11px; font-weight: 600; }
#Card { background: #ffffff; border: 1px solid rgba(0,0,0,0.10); border-radius: 10px; }
#SectionTitle { color: #1d1d1f; font-weight: 600; font-size: 13px; }
#Muted { color: #86868b; font-size: 11px; }
QLineEdit, QComboBox { background: #fff; color: #1d1d1f; border: 1px solid rgba(0,0,0,0.15); border-radius: 6px; padding: 5px 9px; selection-background-color: #0a84ff; selection-color: #fff; min-height: 20px; }
QLineEdit:focus, QComboBox:focus { border: 1px solid #0a84ff; }
QComboBox::drop-down { border: none; width: 18px; } QComboBox::down-arrow { image: none; width: 0; height: 0; }
QComboBox QAbstractItemView { background: #fff; color: #1d1d1f; border: 1px solid rgba(0,0,0,0.12); selection-background-color: #0a84ff; selection-color: #fff; outline: 0; padding: 2px; }
QCheckBox { color: #1d1d1f; spacing: 6px; }
QCheckBox::indicator { width: 14px; height: 14px; border-radius: 4px; border: 1px solid rgba(0,0,0,0.25); background: #fff; }
QCheckBox::indicator:checked { background: #0a84ff; border: 1px solid #0a84ff; }
QPushButton { background: #fff; color: #1d1d1f; border: 1px solid rgba(0,0,0,0.15); border-radius: 6px; padding: 5px 14px; min-height: 22px; font-weight: 500; }
QPushButton:hover { background: #f5f5f7; } QPushButton:pressed { background: #e8e8ed; }
QPushButton:disabled { background: #f5f5f7; color: #b0b0b5; border-color: rgba(0,0,0,0.08); }
QPushButton#Primary { background: #0a84ff; color: #fff; border: 1px solid #0a84ff; }
QPushButton#Primary:hover { background: #0070e0; border-color: #0070e0; }
QPushButton#Primary:pressed { background: #005ec4; border-color: #005ec4; }
QPushButton#Danger { background: #fff; color: #d70015; border: 1px solid rgba(215,0,21,0.35); }
QPushButton#Danger:hover { background: #fff1f2; } QPushButton#Danger:disabled { color: #d4a0a4; border-color: rgba(0,0,0,0.08); }
QTableWidget { background: #fff; alternate-background-color: #fafafa; color: #1d1d1f; gridline-color: transparent; border: 1px solid rgba(0,0,0,0.10); border-radius: 8px; selection-background-color: #0a84ff; selection-color: #fff; outline: 0; }
QTableWidget::item { padding: 5px 6px; border: none; }
QHeaderView::section { background: #f5f5f7; color: #6e6e73; padding: 6px 8px; border: none; border-bottom: 1px solid rgba(0,0,0,0.08); border-right: 1px solid rgba(0,0,0,0.05); font-weight: 600; font-size: 11px; }
QTableCornerButton::section { background: #f5f5f7; border: none; border-bottom: 1px solid rgba(0,0,0,0.08); }
QProgressBar { background: #e8e8ed; border: none; border-radius: 3px; text-align: center; color: transparent; height: 6px; }
QProgressBar::chunk { background: #0a84ff; border-radius: 3px; }
QStatusBar { background: transparent; color: #6e6e73; border-top: 1px solid rgba(0,0,0,0.08); }
QStatusBar::item { border: none; }
QTextEdit, QPlainTextEdit { background: #fff; color: #1d1d1f; border: 1px solid rgba(0,0,0,0.10); border-radius: 8px; padding: 6px; }
QScrollBar:vertical { background: transparent; width: 12px; margin: 4px 2px; }
QScrollBar::handle:vertical { background: rgba(0,0,0,0.22); border-radius: 4px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: rgba(0,0,0,0.35); }
QScrollBar:horizontal { background: transparent; height: 12px; margin: 2px 4px; }
QScrollBar::handle:horizontal { background: rgba(0,0,0,0.22); border-radius: 4px; min-width: 30px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }
QMenu { background: #fff; color: #1d1d1f; border: 1px solid rgba(0,0,0,0.12); border-radius: 8px; padding: 4px; }
QMenu::item { padding: 5px 14px; border-radius: 4px; } QMenu::item:selected { background: #0a84ff; color: #fff; }
QTabBar::tab { background: transparent; color: #6e6e73; padding: 6px 14px; border: none; }
QTabBar::tab:selected { color: #1d1d1f; border-bottom: 2px solid #0a84ff; }
QTabWidget::pane { border: none; }
"""


# ------------------------------ Scan thread ------------------------------- #
class ScanWorker(QThread):
    found = Signal(dict)
    progress = Signal(int, int)
    finished_scan = Signal(int)
    error = Signal(str)

    def __init__(self, target: str, ports: list[int], do_udp: bool, parent=None):
        super().__init__(parent)
        self.target = target
        self.ports = ports
        self.do_udp = do_udp
        self._stop = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def stop(self):
        self._stop = True

    def run(self):
        try:
            target_ip = socket.gethostbyname(self.target)
        except Exception as e:
            self.error.emit(f"Résolution impossible : {e}")
            return
        is_local = is_local_target_strict(target_ip)

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._run_scan(is_local))
        finally:
            self._loop.close()

    async def _run_scan(self, is_local: bool):
        total = len(self.ports) * (2 if self.do_udp else 1)
        done = 0
        found_count = 0

        try:
            async for res in async_scan(self.target, self.ports,
                                        udp=self.do_udp, is_local=is_local):
                if self._stop:
                    break
                found_count += 1
                self.found.emit(res)
                done = min(total, done + max(1, total // 60))
                self.progress.emit(done, total)
        except Exception as e:
            self.error.emit(str(e))
            return

        self.progress.emit(total, total)
        self.finished_scan.emit(found_count)


# ------------------------------ Details dialog ---------------------------- #
class DetailsDialog(QDialog):
    def __init__(self, data: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Port {data.get('port')} — détails")
        self.resize(720, 560)
        v = QVBoxLayout(self); v.setContentsMargins(16, 16, 16, 16); v.setSpacing(10)

        # Résumé
        head = QFrame(); head.setObjectName("Card")
        h = QGridLayout(head); h.setContentsMargins(14, 12, 14, 12); h.setHorizontalSpacing(14)
        h.addWidget(QLabel("<b>Port</b>"), 0, 0); h.addWidget(QLabel(f"{data.get('port')} / {data.get('proto','tcp').upper()}"), 0, 1)
        h.addWidget(QLabel("<b>Service</b>"), 1, 0); h.addWidget(QLabel(data.get("service") or data.get("product") or "—"), 1, 1)
        if data.get("product"):
            h.addWidget(QLabel("<b>Produit</b>"), 2, 0); h.addWidget(QLabel(data["product"]), 2, 1)
        if data.get("title"):
            h.addWidget(QLabel("<b>Titre HTTP</b>"), 3, 0); h.addWidget(QLabel(data["title"]), 3, 1)
        if data.get("http_status"):
            h.addWidget(QLabel("<b>HTTP</b>"), 4, 0); h.addWidget(QLabel(data["http_status"]), 4, 1)

        enrich = data.get("enrich") or {}
        if enrich.get("listen_addr"):
            r = h.rowCount(); h.addWidget(QLabel("<b>Écoute sur</b>"), r, 0); h.addWidget(QLabel(enrich["listen_addr"]), r, 1)
        if enrich.get("summary"):
            r = h.rowCount(); h.addWidget(QLabel("<b>Owner</b>"), r, 0); h.addWidget(QLabel(enrich["summary"]), r, 1)
        v.addWidget(head)

        tabs = QTabWidget()

        # Onglet bannière (lisible + champs parsés)
        raw_banner = data.get("banner") or ""
        ban = QPlainTextEdit(); ban.setReadOnly(True)
        ban.setFont(QFont("Menlo", 10))
        lines = []
        # Champs structurés parsés par probes.py
        for k in ("service", "product", "version", "protocol", "auth_plugin",
                  "capabilities", "http_status", "title"):
            if data.get(k):
                lines.append(f"{k:14}: {data[k]}")
        if lines:
            lines.append("")
            lines.append("--- bannière nettoyée ---")
        cleaned = self._clean_text(raw_banner)
        lines.append(cleaned if cleaned.strip() else "(bannière binaire — voir onglet Hex)")
        ban.setPlainText("\n".join(lines))
        tabs.addTab(ban, "Bannière")

        # Onglet hex dump (utile pour binaires)
        if raw_banner:
            hx = QPlainTextEdit(); hx.setReadOnly(True)
            hx.setFont(QFont("Menlo", 9))
            hx.setPlainText(self._hexdump(raw_banner.encode("latin-1", errors="replace")))
            tabs.addTab(hx, "Hex dump")

        # Onglet TLS
        tls = data.get("tls")
        if tls:
            tw = QPlainTextEdit(); tw.setReadOnly(True)
            lines = [f"Version TLS  : {tls.get('tls_version')}",
                     f"CN           : {tls.get('cn')}",
                     f"Émetteur     : {tls.get('issuer')}",
                     f"Expire le    : {tls.get('not_after')}  ({tls.get('days_left')} j)",
                     f"SAN          : {', '.join(tls.get('san') or [])}"]
            tw.setPlainText("\n".join(lines))
            tabs.addTab(tw, "Certificat TLS")

        # Onglet processus / container
        pw = QPlainTextEdit(); pw.setReadOnly(True)
        pw.setPlainText(self._format_enrich(enrich) if enrich else
                        "Pas d'info processus (cible distante ou privilèges insuffisants).")
        tabs.addTab(pw, "Processus / Container")

        # Onglet brut
        raw = QPlainTextEdit(); raw.setReadOnly(True)
        raw.setPlainText(json.dumps(data, indent=2, ensure_ascii=False, default=str))
        tabs.addTab(raw, "JSON brut")

        v.addWidget(tabs, 1)

        # Actions
        row = QHBoxLayout()
        pids = [p.get("pid") for p in enrich.get("processes", []) if p.get("pid")]
        if pids:
            kb = QPushButton(f"Tuer PID {','.join(str(p) for p in pids)}"); kb.setObjectName("Danger")
            kb.clicked.connect(lambda: self._do_kill(pids, data.get("port")))
            row.addWidget(kb)
        cb = QPushButton("Copier JSON"); cb.clicked.connect(
            lambda: QApplication.clipboard().setText(json.dumps(data, indent=2, default=str)))
        row.addWidget(cb); row.addStretch(1)
        ok = QPushButton("Fermer"); ok.setObjectName("Primary"); ok.clicked.connect(self.accept)
        row.addWidget(ok)
        v.addLayout(row)

    @staticmethod
    def _clean_text(s: str) -> str:
        """Rend une bannière potentiellement binaire lisible (remplace les non-imprimables)."""
        out = []
        for ch in s:
            o = ord(ch)
            if ch in "\r\n\t" or 32 <= o < 127:
                out.append(ch)
            else:
                out.append("·")
        # collapse runs of dots to a single one
        import re as _re
        return _re.sub(r"·{2,}", " · ", "".join(out))

    @staticmethod
    def _hexdump(data: bytes, width: int = 16) -> str:
        lines = []
        for off in range(0, len(data), width):
            chunk = data[off:off + width]
            hexs = " ".join(f"{b:02x}" for b in chunk)
            ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{off:08x}  {hexs:<{width*3}}  {ascii_}")
        return "\n".join(lines)

    @staticmethod
    def _format_enrich(en: dict) -> str:
        lines = []
        c = en.get("container")
        if c:
            lines.append(f"=== Container ({c.get('runtime')}) ===")
            for k in ("name", "image", "id", "status", "ports", "command"):
                if c.get(k):
                    lines.append(f"  {k:10}: {c[k]}")
            lines.append("")
        for proc in en.get("processes", []):
            lines.append(f"=== PID {proc.get('pid')} ===")
            for k in ("name", "user", "exe", "cwd", "cmdline", "ppid", "state",
                      "systemd_unit", "packaging", "cpu_percent", "memory_mb",
                      "fds", "connections"):
                if proc.get(k) is not None:
                    lines.append(f"  {k:14}: {proc[k]}")
            if proc.get("container"):
                lines.append(f"  container     : {proc['container']}")
            lines.append("")
        return "\n".join(lines) if lines else "(rien)"

    def _do_kill(self, pids, port):
        if QMessageBox.question(self, "Confirmer",
                                f"Tuer PID {pids} sur port {port} ?") != QMessageBox.Yes:
            return
        try:
            kill_pids(pids, port=port)
        except Exception as e:
            QMessageBox.critical(self, "Erreur", str(e)); return

        # Vérifie réellement la disparition des PID
        import time
        time.sleep(0.4)
        still_alive = [p for p in pids if self._pid_alive(p)]
        if still_alive:
            QMessageBox.warning(self, "Partiel",
                f"PID encore vivant(s) : {still_alive}\n"
                "Tente en root, ou utilise un signal plus fort.")
            return
        # tout est mort → ferme la fenêtre et signale au parent
        if self.parent() and hasattr(self.parent(), "_on_kill_success"):
            self.parent()._on_kill_success(port)
        self.accept()

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        """Cross-platform : safe sur Windows (ne kill pas), via psutil."""
        try:
            import psutil
            return psutil.pid_exists(pid)
        except ImportError:
            pass
        if sys.platform == "win32":
            # Sans psutil, on appelle tasklist (sûr).
            try:
                out = subprocess.check_output(
                    ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                    stderr=subprocess.DEVNULL, text=True, timeout=2,
                )
                return str(pid) in out
            except Exception:
                return False
        # Unix : signal 0 ne tue pas
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, OSError):
            return False
        except PermissionError:
            return True  # existe mais sans accès


# ------------------------------ Main window ------------------------------- #
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Scanner de Ports")
        self.resize(1180, 780)
        self.results: list[dict] = []
        self.worker: Optional[ScanWorker] = None
        self._build_ui()
        self._update_admin_badge()

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QVBoxLayout(central); root.setContentsMargins(22, 18, 22, 10); root.setSpacing(12)
        root.addWidget(self._build_header())
        root.addWidget(self._build_config_card())
        root.addWidget(self._build_actions_row())
        root.addWidget(self._build_filter_row())
        root.addWidget(self._build_results_card(), 1)
        self.progress = QProgressBar(); self.progress.setValue(0)
        root.addWidget(self.progress)
        sb = QStatusBar(); sb.showMessage("Prêt")
        self.setStatusBar(sb)

    def _build_header(self):
        w = QFrame(); w.setObjectName("Header")
        lay = QHBoxLayout(w); lay.setContentsMargins(4, 2, 4, 2); lay.setSpacing(12)
        left = QVBoxLayout(); left.setSpacing(2)
        left.addWidget(self._lab("Scanner de Ports", "HeaderTitle"))
        left.addWidget(self._lab("Inspection réseau, sondes intelligentes, détection container", "HeaderSub"))
        lay.addLayout(left, 1)
        self.admin_badge = QLabel("…"); self.admin_badge.setObjectName("BadgePill")
        self.admin_badge.setAlignment(Qt.AlignCenter)
        lay.addWidget(self.admin_badge, 0, Qt.AlignVCenter)
        self.btn_elevate = QPushButton("Relancer en admin")
        self.btn_elevate.setCursor(Qt.PointingHandCursor)
        self.btn_elevate.clicked.connect(self._elevate)
        lay.addWidget(self.btn_elevate, 0, Qt.AlignVCenter)
        return w

    def _build_config_card(self):
        card = QFrame(); card.setObjectName("Card")
        g = QGridLayout(card); g.setContentsMargins(16, 14, 16, 14)
        g.setHorizontalSpacing(12); g.setVerticalSpacing(10)
        g.addWidget(self._lab("Configuration", "SectionTitle"), 0, 0, 1, 4)
        g.addWidget(QLabel("Cible"), 1, 0)
        self.target_edit = QLineEdit(DEFAULT_TARGET)
        self.target_edit.setPlaceholderText("IP ou nom d'hôte")
        g.addWidget(self.target_edit, 1, 1)
        g.addWidget(QLabel("Ports"), 1, 2)
        self.ports_combo = QComboBox(); self.ports_combo.setEditable(True)
        self.ports_combo.addItems(["common", "top1000", "top5000", "1-1024", "all", "22,80,443,3306,8080"])
        g.addWidget(self.ports_combo, 1, 3)
        self.cb_dynamic = QCheckBox("Ports dynamiques (32768-65535)")
        self.cb_udp = QCheckBox("Scan UDP (avec sondes DNS/NTP/SNMP)")
        opts = QHBoxLayout(); opts.addWidget(self.cb_dynamic); opts.addWidget(self.cb_udp); opts.addStretch(1)
        wrap = QWidget(); wrap.setLayout(opts)
        g.addWidget(wrap, 2, 0, 1, 4)
        g.addWidget(self._lab("Double-clic sur un résultat pour les détails complets (PID, container, TLS…).",
                              "Muted"), 3, 0, 1, 4)
        g.setColumnStretch(1, 3); g.setColumnStretch(3, 2)
        return card

    def _build_actions_row(self):
        row = QFrame()
        h = QHBoxLayout(row); h.setContentsMargins(0, 0, 0, 0); h.setSpacing(10)
        self.btn_start = QPushButton("Démarrer"); self.btn_start.setObjectName("Primary")
        self.btn_stop = QPushButton("Arrêter"); self.btn_stop.setObjectName("Danger"); self.btn_stop.setEnabled(False)
        self.btn_clear = QPushButton("Effacer")
        self.btn_csv = QPushButton("Exporter CSV")
        self.btn_json = QPushButton("Exporter JSON")
        self.btn_help = QPushButton("Aide")
        for b in (self.btn_start, self.btn_stop, self.btn_clear, self.btn_csv, self.btn_json, self.btn_help):
            b.setCursor(Qt.PointingHandCursor); h.addWidget(b)
        h.addStretch(1)
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_clear.clicked.connect(self.clear_results)
        self.btn_csv.clicked.connect(lambda: self.export("csv"))
        self.btn_json.clicked.connect(lambda: self.export("json"))
        self.btn_help.clicked.connect(self.show_help)
        return row

    def _build_filter_row(self):
        row = QFrame()
        h = QHBoxLayout(row); h.setContentsMargins(0, 0, 0, 0); h.setSpacing(8)
        h.addWidget(QLabel("Filtrer :"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("port, service, produit, container, PID…")
        self.filter_edit.textChanged.connect(self._apply_filter)
        h.addWidget(self.filter_edit, 1)
        return row

    def _build_results_card(self):
        card = QFrame(); card.setObjectName("Card")
        v = QVBoxLayout(card); v.setContentsMargins(14, 12, 14, 12); v.setSpacing(8)
        head = QHBoxLayout()
        head.addWidget(self._lab("Résultats", "SectionTitle"))
        self.count_label = self._lab("0 port(s) ouvert(s)", "Muted")
        head.addStretch(1); head.addWidget(self.count_label)
        v.addLayout(head)

        cols = ["Proto", "Port", "Service", "Produit", "Owner / Container", "TLS"]
        self.table = QTableWidget(0, len(cols))
        self.table.setHorizontalHeaderLabels(cols)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setVisible(False)
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(3, QHeaderView.Stretch)
        h.setSectionResizeMode(4, QHeaderView.Stretch)
        h.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._row_menu)
        self.table.doubleClicked.connect(self._show_details)
        v.addWidget(self.table, 1)
        return card

    # ---- helpers UI ---- #
    def _lab(self, text: str, obj: str = "") -> QLabel:
        l = QLabel(text)
        if obj: l.setObjectName(obj)
        return l

    def _update_admin_badge(self):
        is_admin = False
        try: is_admin = (os.geteuid() == 0)
        except AttributeError:
            try:
                import ctypes
                is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                pass
        if is_admin:
            self.admin_badge.setText("Administrateur"); self.admin_badge.setObjectName("BadgePill")
            self.btn_elevate.setVisible(False)
        else:
            self.admin_badge.setText("Utilisateur standard"); self.admin_badge.setObjectName("BadgePillWarn")
            self.btn_elevate.setVisible(sys.platform != "win32" or True)
        self.admin_badge.style().unpolish(self.admin_badge); self.admin_badge.style().polish(self.admin_badge)

    def _elevate(self):
        """Relance l'application en admin. N'arrête pas l'instance actuelle
        tant que la nouvelle n'est pas confirmée comme lancée (handshake via fichier marqueur)."""
        import tempfile, time

        script = os.path.abspath(sys.argv[0])
        python = sys.executable

        # Windows — UAC
        if sys.platform == "win32":
            try:
                import ctypes
                ret = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", python, f'"{script}"', None, 1
                )
                if ret <= 32:
                    raise RuntimeError(f"UAC refusé (code {ret})")
            except Exception as e:
                QMessageBox.critical(self, "Erreur", f"Élévation impossible : {e}")
                return
            QApplication.quit(); return

        # Linux / macOS — handshake via fichier marqueur
        marker = tempfile.NamedTemporaryFile(prefix="scan_port_admin_", delete=False)
        marker_path = marker.name; marker.close()
        os.remove(marker_path)  # le child le créera

        env_pass = ["DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY",
                    "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "HOME"]
        env_args = [f"SCAN_PORT_ADMIN_READY={marker_path}",
                    f"SCAN_PORT_PARENT_PID={os.getpid()}"]
        for k in env_pass:
            v = os.environ.get(k)
            if v: env_args.append(f"{k}={v}")

        cmd = None; using = None
        # macOS — popup natif via AppleScript
        if sys.platform == "darwin" and shutil.which("osascript"):
            shell_cmd = " ".join([f"{a}" for a in env_args]) + f" {python} {script}"
            cmd = ["osascript", "-e",
                   f'do shell script "{shell_cmd}" with administrator privileges']
            using = "osascript"
        elif shutil.which("pkexec"):
            cmd = ["pkexec", "env", *env_args, python, script]
            using = "pkexec"
        elif shutil.which("sudo"):
            term = next((t for t in ("x-terminal-emulator", "gnome-terminal",
                                     "konsole", "xfce4-terminal", "xterm")
                         if shutil.which(t)), None)
            if not term:
                QMessageBox.warning(self, "Élévation",
                    f"Ni pkexec ni terminal. Lance manuellement :\nsudo {python} {script}")
                return
            cmd = [term, "-e", "sudo", "env", *env_args, python, script]
            using = "sudo+terminal"
        else:
            QMessageBox.warning(self, "Élévation",
                f"Ni pkexec ni sudo. Lance manuellement :\nsudo {python} {script}")
            return

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, start_new_session=True)
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Lancement échoué : {e}")
            return

        self.statusBar().showMessage(f"Élévation via {using} — saisis ton mot de passe…")
        QApplication.processEvents()

        # Poll : on attend le marqueur (succès) OU la sortie du process (échec)
        deadline = time.time() + 60
        while time.time() < deadline:
            if os.path.exists(marker_path):
                try: os.remove(marker_path)
                except OSError: pass
                QApplication.quit(); return
            rc = proc.poll()
            if rc is not None:
                err = (proc.stderr.read() or b"").decode(errors="ignore")[:400]
                QMessageBox.critical(self, "Élévation échouée",
                    f"{using} a quitté avec le code {rc}.\n\n{err or '(pas de message)'}\n\n"
                    f"Astuce : sur Wayland, root n'a pas toujours accès à l'écran. "
                    f"Essaie depuis un terminal :\nsudo {python} {script}")
                self.statusBar().showMessage("Élévation annulée")
                return
            time.sleep(0.2); QApplication.processEvents()

        QMessageBox.warning(self, "Timeout",
            "La nouvelle instance n'a pas confirmé son démarrage en 60s. "
            "Si une fenêtre admin est visible, ferme celle-ci manuellement.")
        self.statusBar().showMessage("Élévation : timeout")

    def _resolve_ports(self) -> list[int]:
        raw = self.ports_combo.currentText().strip()
        try:
            ports = parse_ports(raw)
        except Exception as e:
            QMessageBox.warning(self, "Ports invalides", f"Impossible de parser '{raw}': {e}")
            return []
        if not self.cb_dynamic.isChecked():
            ports = [p for p in ports if not (32768 <= p <= 65535)]
        return ports

    # ---- actions ---- #
    def start_scan(self):
        target = self.target_edit.text().strip() or DEFAULT_TARGET
        ports = self._resolve_ports()
        if not ports: return
        if len(ports) > 5000 and self.cb_udp.isChecked():
            self.cb_udp.setChecked(False)
            QMessageBox.information(self, "UDP désactivé",
                                    "Trop de ports pour UDP — désactivé automatiquement.")
        self.clear_results()
        self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True)
        self.statusBar().showMessage(f"Scan de {target} sur {len(ports)} port(s)…")
        self.progress.setValue(0)
        self.worker = ScanWorker(target, ports, self.cb_udp.isChecked())
        self.worker.found.connect(self._add_row)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished_scan.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
            self.statusBar().showMessage("Arrêt en cours…")

    def _on_progress(self, done: int, total: int):
        self.progress.setValue(int(done * 100 / max(1, total)))

    def _on_finished(self, opened: int):
        self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)
        self.statusBar().showMessage(f"Terminé — {opened} port(s) ouvert(s)")
        self.progress.setValue(100)

    def _on_error(self, msg: str):
        self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)
        QMessageBox.critical(self, "Erreur", msg)
        self.statusBar().showMessage("Erreur")

    def _add_row(self, data: dict):
        self.results.append(data)
        self.table.setSortingEnabled(False)
        r = self.table.rowCount(); self.table.insertRow(r)
        enrich = data.get("enrich") or {}
        owner = enrich.get("summary") or "—"
        tls = data.get("tls") or {}
        tls_str = ""
        if tls:
            v = tls.get("tls_version") or "TLS"
            d = tls.get("days_left")
            tls_str = f"✓ {v}" + (f" ({d}j)" if d is not None else "")

        vals = [
            data.get("proto", "tcp").upper(),
            data.get("port"),
            data.get("service") or "?",
            data.get("product") or "",
            owner,
            tls_str,
        ]
        for c, v in enumerate(vals):
            if c == 1:
                it = QTableWidgetItem()
                it.setData(Qt.DisplayRole, int(v))  # tri numérique
            else:
                it = QTableWidgetItem(str(v))
            if c == 4 and enrich.get("container"):
                it.setForeground(QColor("#0a84ff"))
            self.table.setItem(r, c, it)
        self.table.setSortingEnabled(True)
        self.count_label.setText(f"{len(self.results)} port(s) ouvert(s)")
        self._apply_filter(self.filter_edit.text())

    def _apply_filter(self, text: str):
        text = (text or "").lower().strip()
        for r in range(self.table.rowCount()):
            if not text:
                self.table.setRowHidden(r, False); continue
            hit = False
            for c in range(self.table.columnCount()):
                it = self.table.item(r, c)
                if it and text in it.text().lower():
                    hit = True; break
            self.table.setRowHidden(r, not hit)

    def clear_results(self):
        self.results.clear(); self.table.setRowCount(0)
        self.count_label.setText("0 port(s) ouvert(s)")

    def export(self, fmt: str):
        if not self.results:
            QMessageBox.information(self, "Export", "Aucun résultat."); return
        if fmt == "csv":
            path, _ = QFileDialog.getSaveFileName(self, "Exporter CSV", "scan.csv", "CSV (*.csv)")
            if not path: return
            with open(path, "w", newline="") as f:
                flat = [self._flat(d) for d in self.results]
                keys = sorted({k for d in flat for k in d})
                w = csv.DictWriter(f, fieldnames=keys); w.writeheader()
                for d in flat: w.writerow(d)
        else:
            path, _ = QFileDialog.getSaveFileName(self, "Exporter JSON", "scan.json", "JSON (*.json)")
            if not path: return
            with open(path, "w") as f:
                json.dump(self.results, f, indent=2, default=str, ensure_ascii=False)
        self.statusBar().showMessage(f"Exporté : {path}")

    @staticmethod
    def _flat(d: dict) -> dict:
        out = {k: v for k, v in d.items() if not isinstance(v, (dict, list))}
        en = d.get("enrich") or {}
        out["owner"] = en.get("summary")
        if en.get("container"):
            out["container_name"] = en["container"].get("name")
            out["container_image"] = en["container"].get("image")
        return out

    def _row_menu(self, pos):
        row = self.table.rowAt(pos.y())
        if row < 0: return
        data = self.results[row]
        m = QMenu(self)
        a_det = m.addAction("Détails…")
        a_copy = m.addAction("Copier JSON")
        a_kill = None
        en = data.get("enrich") or {}
        pids = [p.get("pid") for p in en.get("processes", []) if p.get("pid")]
        if pids:
            a_kill = m.addAction(f"Tuer PID {pids}")
        act = m.exec(self.table.viewport().mapToGlobal(pos))
        if act == a_det: DetailsDialog(data, self).exec()
        elif act == a_copy:
            QApplication.clipboard().setText(json.dumps(data, indent=2, default=str))
        elif a_kill and act == a_kill:
            if QMessageBox.question(self, "Confirmer", f"Tuer {pids} ?") != QMessageBox.Yes:
                return
            try:
                kill_pids(pids, port=data["port"])
            except Exception as e:
                QMessageBox.critical(self, "Erreur", str(e)); return
            import time; time.sleep(0.4)
            still = [p for p in pids if DetailsDialog._pid_alive(p)]
            if still:
                QMessageBox.warning(self, "Partiel", f"PID encore vivant(s) : {still}")
            else:
                self._on_kill_success(data["port"])

    def _on_kill_success(self, port: int):
        """Appelé après un kill réussi : retire la ligne du tableau."""
        for r in range(self.table.rowCount()):
            it = self.table.item(r, 1)
            if it and it.data(Qt.DisplayRole) == port:
                self.table.removeRow(r); break
        self.results = [d for d in self.results if d.get("port") != port]
        self.count_label.setText(f"{len(self.results)} port(s) ouvert(s)")
        self.statusBar().showMessage(f"Port {port} libéré")

    def _show_details(self, idx):
        row = idx.row()
        if 0 <= row < len(self.results):
            DetailsDialog(self.results[row], self).exec()

    def show_help(self):
        dlg = QDialog(self); dlg.setWindowTitle("Aide"); dlg.resize(700, 520)
        v = QVBoxLayout(dlg); t = QTextEdit(); t.setReadOnly(True)
        t.setMarkdown(
            "# Scanner de Ports\n\n"
            "## Nouveautés\n"
            "- **Scanner asynchrone** (asyncio) avec timeout adaptatif au RTT.\n"
            "- **Sondes intelligentes** : HTTP (Server, titre), TLS (cert, expiration), SSH, SMTP, FTP, Redis, MySQL, Memcached, VNC…\n"
            "- **UDP** réel pour DNS, NTP, SNMP, NetBIOS.\n"
            "- **Détection container** : Docker, Podman, Kubernetes, LXC + lookup `docker ps` quand le port est mappé via `docker-proxy`.\n"
            "- **Détails par port** : double-clic → bannière, cert TLS, processus, container, JSON brut.\n\n"
            "## Astuces\n"
            "- Filtre live : tape `docker`, `nginx`, `22`, etc.\n"
            "- Tri cliquable par colonne.\n"
            "- Lance en `sudo` pour récupérer les PID et tuer les processus.\n"
        )
        v.addWidget(t)
        b = QPushButton("Fermer"); b.setObjectName("Primary"); b.clicked.connect(dlg.accept)
        v.addWidget(b, 0, Qt.AlignRight); dlg.exec()


def _configure_event_loop():
    """Sur Windows, asyncio utilise par défaut ProactorEventLoop ; ça marche pour
    open_connection mais pose des soucis avec le sous-processus ssl quand on
    crée beaucoup de connexions. On force la version Selector qui est plus
    prévisible pour le scan."""
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass


def _signal_parent_ready():
    """Si on a été lancé en mode élévation, prévient l'instance parente."""
    marker = os.environ.get("SCAN_PORT_ADMIN_READY")
    if marker:
        try:
            with open(marker, "w") as f:
                f.write("ok")
        except Exception:
            pass


def main():
    _configure_event_loop()
    _signal_parent_ready()
    app = QApplication(sys.argv)
    for fam in ("SF Pro Text", "Helvetica Neue", "Inter", "Segoe UI"):
        f = QFont(fam, 10)
        if f.exactMatch() or fam == "Inter":
            app.setFont(f); break
    app.setStyleSheet(QSS)
    w = MainWindow(); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

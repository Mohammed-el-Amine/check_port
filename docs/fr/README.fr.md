# 🛠️ Scan Port GUI & CLI
Scanner de ports avancé avec **interface graphique Tkinter** et **CLI**. Détection intelligente des services, options de scan flexibles, arrêt propre des services (avec privilèges admin).

---
## ✅ Fonctionnalités
- **CLI + GUI** (Tkinter)
- **Scans rapides** (common, top1000, top5000)
- **Plages personnalisées** (`1-1024`, `8000-9000`)
- **Ports spécifiques** (`22,80,443`)
- **Option UDP** (best‑effort)
- **Export CSV/JSON** des résultats (GUI)
- **Arrêt intelligent** des services (systemctl quand possible)
- **Affichage PID / process** (avec droits admin)

---
## 📦 Prérequis
- Python **3.8+**
- Linux/macOS : `python3-tk` (Tkinter)

### Linux (Ubuntu/Debian)
```bash
sudo apt install python3-tk
```

---
## 🚀 Utilisation CLI
```bash
python3 check_port.py <cible> [ports] [options]
```

### Aide CLI (disponible)
```bash
python3 check_port.py --help
```

Exemples :
```bash
python3 check_port.py localhost
python3 check_port.py 192.168.1.1 top1000
python3 check_port.py 192.168.1.1 1-1024
python3 check_port.py 192.168.1.1 22,80,443
python3 check_port.py 192.168.1.1 all
# TCP + UDP
python3 check_port.py 192.168.1.1 top1000 --udp
```

---
## 🖥️ Interface Graphique (GUI)
Lancer l’interface :
```bash
python3 gui_port_scanner.py
```

### Avec privilèges admin (pour PID/actions)
```bash
sudo python3 gui_port_scanner.py
```

✅ L’UI propose un bouton **Relancer avec sudo** (Linux/macOS). Si besoin : relance manuelle ci‑dessus.

### Options GUI
- **Scan UDP** : active un scan UDP (plus lent, best‑effort)
- **Export CSV/JSON** : boutons dédiés

---
## 🔐 Permissions
- **Sans sudo** : scan OK, mais infos PID limitées
- **Avec sudo** : accès complet (PID + kill/stop)

---
## ⚙️ Ports dynamiques
Par défaut, les ports éphémères sont masqués. Pour les afficher :
```bash
python3 check_port.py --show-dynamic localhost all
```

---
## 📦 Build & Packaging (PyInstaller)
Scripts fournis :
- `build_linux.sh`
- `build_windows.ps1`
- `build_macos.sh`
- `build_all.sh`
- `scan_port_gui.spec`

### Build Linux rapide
```bash
./build_linux.sh
```

### CI GitHub Actions
Workflow prêt : `.github/workflows/build.yml`

---
## 🎨 Icône / Logo
Les icônes sont dans `assets/` :
- `icon.ico` (Windows)
- `icon.icns` (macOS)
- `icon.png` (Linux)

Le `scan_port_gui.spec` choisit l’icône selon l’OS.

**Linux** : l’icône du binaire ne s’affiche pas directement → utilisez un `.desktop`.

---
## 📁 Structure du projet
- `gui_port_scanner.py` : interface graphique
- `check_port.py` : moteur de scan
- `scan_port_gui.spec` : spec PyInstaller
- `assets/` : icônes
- `build_*.sh` / `build_windows.ps1` : scripts build
- `.github/workflows/build.yml` : CI

---
## ⚠️ Bonnes pratiques
- Ne scannez que vos propres machines / réseaux autorisés
- Évitez `all` si ce n’est pas nécessaire (long et lourd)
- Préférez `top1000` pour un bon compromis

---
## ❓ FAQ (rapide)
**Q: Je ne vois pas l’icône sous Linux ?**
R: Sous Linux, l’icône se gère via un fichier `.desktop`, pas dans le binaire.

**Q: Le scan UDP est lent / bloque ?**
R: UDP est best‑effort. Utilise `top1000` plutôt que `all`.

**Q: Comment avoir les PID/processus ?**
R: Lance en sudo (Linux/macOS) ou en Administrateur (Windows).

---
## 📄 Licence
Ce projet est sous licence **MIT** (voir `LICENSE`).

---
## ✅ Versions
- v1.0 : scan de base
- v2.0 : optimisations
- v2.1 : détection services & arrêt intelligent
- v2.2 : GUI + packaging + CI

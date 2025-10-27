BUILD INSTRUCTIONS
==================

Objectif
--------
Ce document décrit comment produire des exécutables pour l'application GUI `gui_port_scanner.py` (Linux et Windows).

Fichiers et scripts fournis
---------------------------
- `build_linux.sh` : script Bash pour créer un virtualenv, vérifier/install tkinter (si vous acceptez) et construire avec PyInstaller.
- `build_windows.ps1` : script PowerShell pour Windows (détecte `winget`/`choco` et propose d'installer Python/tk si nécessaire).
- `scan_port_gui.spec` : spec PyInstaller utilisé pour un build reproductible (fichier ajouté au dépôt).

Pré-requis
----------
- Python 3.8+ installé sur la machine de build.
- Paquets système pour tkinter (Debian/Ubuntu: `sudo apt install python3-tk`).

Build local (rapide) — utiliser le script Linux
---------------------------------------------
Exécuter le script fourni qui s'occupe du virtualenv et de PyInstaller :

```bash
chmod +x build_linux.sh
./build_linux.sh
```

Le script vérifie la présence de `tkinter` et propose, si vous l'autorisez, d'installer le paquet système nécessaire via `sudo`. Par défaut il construit un binaire `--onefile` pour test rapide ; modifiez le script si vous préférez `--onedir`.

Build Windows (local)
---------------------
Exécutez le script PowerShell sur une machine Windows :

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\build_windows.ps1
```

Utiliser le spec (recommandé pour CI)
------------------------------------
Pour des builds reproductibles et pour ajouter des fichiers de données, utilisez le spec :

```bash
pyinstaller scan_port_gui.spec
```

Le fichier `scan_port_gui.spec` contient une entrée `datas` où vous pouvez ajouter des fichiers (icônes, exemples, assets) à embarquer.

Accéder aux fichiers embarqués dans un onefile
-------------------------------------------
Si vous produisez un exécutable `--onefile`, utilisez le helper `resource_path` dans votre code :

```python
import sys, os
def resource_path(*parts):
    base = getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(__file__)))
    return os.path.join(base, *parts)

# Exemple d'utilisation:
# help_file = resource_path('examples.sh')
# with open(help_file, 'r', encoding='utf-8') as f:
#     HELP_TEXT = f.read()
```

CI / GitHub Actions
--------------------
Le dépôt contient un workflow GitHub Actions (`.github/workflows/build.yml`). Il installe les dépendances, installe `python3-tk` sur Ubuntu runners, et lance PyInstaller en utilisant `scan_port_gui.spec`. Les artéfacts sont uploadés comme artefacts de workflow.

Conseils et dépannage
----------------------
- Pour le développement privilégiez `--onedir` (one-folder) : plus simple à déboguer.
- Si PyInstaller oublie des imports, ajoutez-les dans `hiddenimports` du spec ou utilisez `--hidden-import`.
- Si tkinter pose problème à l'exécution, installez le paquet système `tk` / `python3-tk` et réessayez.

Voulez-vous que j'ajoute une option non-interactive (`--yes`) aux scripts de build pour les exécutions CI ?

Fin


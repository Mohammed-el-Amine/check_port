#!/usr/bin/env bash
# build_linux.sh
# Script rapide pour construire un exécutable Linux pour gui_port_scanner.py
# Usage:
#   chmod +x build_linux.sh
#   ./build_linux.sh

set -euo pipefail
PY=python3
VENV_DIR=.venv_build
DIST_NAME=scan_port_gui
SRC=gui_port_scanner.py

echo "==> Vérification de Python..."
if ! command -v $PY >/dev/null 2>&1; then
  echo "python3 introuvable. Installez Python 3 et réessayez." >&2
  exit 1
fi

# Vérifier que tkinter est disponible (module Python côté runtime)
echo "==> Vérification de tkinter (module GUI) dans l'environnement hôte..."
if ! $PY -c "import tkinter" >/dev/null 2>&1; then
  echo "tkinter (module graphique) introuvable pour Python."
  # Détecter le gestionnaire de paquets
  PKG_MANAGER=""
  if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
  elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"
  elif command -v zypper >/dev/null 2>&1; then
    PKG_MANAGER="zypper"
  elif command -v apk >/dev/null 2>&1; then
    PKG_MANAGER="apk"
  fi

  echo
  case "$PKG_MANAGER" in
    apt)
      echo "Suggestion d'installation: sudo apt-get install python3-tk"
      pkg_cmd="sudo apt-get update && sudo apt-get install -y python3-tk"
      ;;
    dnf)
      echo "Suggestion d'installation: sudo dnf install python3-tkinter"
      pkg_cmd="sudo dnf install -y python3-tkinter"
      ;;
    yum)
      echo "Suggestion d'installation: sudo yum install python3-tkinter"
      pkg_cmd="sudo yum install -y python3-tkinter"
      ;;
    pacman)
      echo "Suggestion d'installation: sudo pacman -S --noconfirm tk"
      pkg_cmd="sudo pacman -S --noconfirm tk"
      ;;
    zypper)
      echo "Suggestion d'installation: sudo zypper install -y python3-tk"
      pkg_cmd="sudo zypper install -y python3-tk"
      ;;
    apk)
      echo "Suggestion d'installation: sudo apk add tk"
      pkg_cmd="sudo apk add tk"
      ;;
    *)
      echo "Impossible de détecter le gestionnaire de paquets. Installez manuellement 'tk' / 'python3-tk'."
      exit 1
      ;;
  esac

  read -r -p "Voulez-vous que le script tente d'installer le paquet nécessaire automatiquement ? [y/N] " resp
  resp=${resp:-N}
  if [[ "$resp" =~ ^[Yy]$ ]]; then
  echo "==> Exécution de la commande d'installation (nécessite sudo)."
  # Exécuter la commande construite dans un sous-shell via bash -c
  bash -c "$pkg_cmd"
    echo "==> Réessai d'import tkinter..."
    if ! $PY -c "import tkinter" >/dev/null 2>&1; then
      echo "Echec de l'import tkinter après installation. Vérifiez les paquets système et réessayez." >&2
      exit 1
    fi
  else
    echo "Abandon car tkinter est requis pour l'interface graphique. Installez le paquet puis relancez." >&2
    exit 1
  fi
fi

# Créer/mettre à jour l'environnement virtuel
if [ ! -d "$VENV_DIR" ]; then
  echo "==> Création d'un virtualenv dans $VENV_DIR"
  $PY -m venv "$VENV_DIR"
fi

# Active le venv
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

echo "==> Mise à jour pip et installation de PyInstaller"
pip install --upgrade pip setuptools wheel
pip install pyinstaller

# Construire (onefile par défaut pour test rapide)
echo "==> Construction PyInstaller (onefile)..."
# Si vous préférez one-folder, remplacez --onefile par --onedir
pyinstaller --noconfirm --name "$DIST_NAME" --onefile "$SRC"

echo "==> Construction terminée. Fichiers générés dans dist/"
if [ -f "dist/$DIST_NAME" ]; then
  echo "Executable: dist/$DIST_NAME"
  echo "Vous pouvez lancer: ./dist/$DIST_NAME"
else
  echo "Executable introuvable. Vérifiez la sortie de pyinstaller." >&2
  exit 1
fi

# Déactiver le venv
deactivate || true

echo "==> Fini"

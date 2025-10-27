#!/bin/bash
# Script de lancement pour l'interface graphique du scanner de ports

echo "🔍 Lancement de l'Interface Graphique du Scanner de Ports"
echo "========================================================="
echo

# Vérifier si Python3 est installé
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 n'est pas installé"
    echo "installation de Python3 en cours..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y python3
    else
        echo "Veuillez installer Python3 manuellement pour votre distribution."
    fi
    exit 1
fi

# Vérifier si Tkinter est installé
if ! python3 -c "import tkinter" &> /dev/null; then
    echo "❌ Tkinter n'est pas installé"
    echo "Installation de Tkinter en cours..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y python3-tk
    else
        echo "Veuillez installer Tkinter manuellement pour votre distribution."
    fi
    exit 1
fi

# Vérifier si le fichier check_port.py existe
if [ ! -f "check_port.py" ]; then
    echo "❌ Le fichier check_port.py est introuvable"
    echo "Assurez-vous d'être dans le bon répertoire"
    exit 1
fi

# Vérifier si le fichier GUI existe
if [ ! -f "gui_port_scanner.py" ]; then
    echo "❌ Le fichier gui_port_scanner.py est introuvable"
    exit 1
fi

echo "✅ Fichiers trouvés"
echo "📝 Note: Pour accéder aux fonctionnalités complètes (PID, arrêt services),"
echo "   l'interface vous proposera de relancer avec des privilèges administrateur"
echo

# Lancer l'interface graphique
echo "🚀 Lancement de l'interface graphique..."
python3 gui_port_scanner.py

echo "👋 Interface fermée"
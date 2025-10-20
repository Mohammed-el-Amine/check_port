#!/bin/bash
# Exemples d'utilisation du scanner de ports amélioré

echo "🔍 EXEMPLES D'UTILISATION DU SCANNER DE PORTS"
echo "============================================="
echo

echo "📖 Afficher l'aide:"
echo "python3 check_port.py --help"
echo

echo "🏠 Scanner les ports communs sur localhost:"
echo "python3 check_port.py localhost"
echo

echo "🌐 Scanner TOUS les ports sur une cible (⚠️ très long!):"
echo "python3 check_port.py 192.168.1.1 all"
echo

echo "⚡ Scanner les 1000 premiers ports (recommandé):"
echo "python3 check_port.py 192.168.1.1 top1000"
echo

echo "🎯 Scanner les ports privilégiés (1-1024):"
echo "python3 check_port.py 192.168.1.1 1-1024"
echo

echo "🔧 Scanner des ports spécifiques:"
echo "python3 check_port.py 192.168.1.1 22,80,443,8080"
echo

echo "🚀 Scanner une plage personnalisée:"
echo "python3 check_port.py 192.168.1.1 8000-9000"
echo

echo "💡 CONSEILS:"
echo "- Utilisez 'top1000' pour un bon compromis vitesse/couverture"
echo "- 'all' peut prendre plusieurs heures selon la cible"
echo "- Le script s'optimise automatiquement selon le nombre de ports"
echo "- Utilisez sudo pour pouvoir tuer les processus locaux"
echo

echo "🧪 Pour tester le script:"
echo "python3 test_scan.py"
echo "🟢 Masquer les ports dynamiques (par défaut)"
echo "python3 check_port.py localhost all"
echo
echo "🔵 Afficher aussi les ports dynamiques (flag)"
echo "python3 check_port.py --show-dynamic localhost all"
echo "# ou avec sudo pour voir les PID complets"
echo "sudo python3 check_port.py --show-dynamic localhost all"
echo
echo "💡 CONSEILS:"
echo "- Utilisez 'top1000' pour un bon compromis vitesse/couverture"
echo "- 'all' peut prendre plusieurs heures selon la cible"
echo "- Le script s'optimise automatiquement selon le nombre de ports"
echo "- Exécutez avec sudo pour voir les PID et le nom des processus"
echo "- Les ports dynamiques sont généralement temporaires et sans risque"
echo
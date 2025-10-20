# 📖 DOCUMENTATION - SCANNER DE PORTS AVANCÉ

## 🎯 Description
Script Python avancé pour scanner et fermer des ports réseau avec détection intelligente des services et gestion optimisée des performances.

## 🚀 Fonctionnalités principales

### 📊 **Scan flexible**
- **Ports communs** : Scan rapide des ports les plus utilisés
- **Scan complet** : Tous les ports 1-65535 (mode `all`)
- **Scan par plages** : `1-1024`, `8000-9000`, etc.
- **Ports spécifiques** : `22,80,443,8080`
- **Modes prédéfinis** : `top1000`, `top5000`

### ⚡ **Optimisations automatiques**
- **Timeout adaptatif** selon le nombre de ports
- **Workers dynamiques** (jusqu'à 1000 threads)
- **Affichage du progrès** pour les gros scans
- **Vitesse temps réel** en ports/seconde

### 🔧 **Fermeture intelligente**
- **Détection automatique** des services (MySQL, Apache, SSH, etc.)
- **Arrêt propre** via `systemctl` pour les services système
- **Kill forcé** en dernier recours
- **Commandes firewall** pour les machines distantes

## 📋 Utilisation

### Syntaxe de base
```bash
python3 check_port.py [cible] [ports]
```

### Exemples pratiques

#### Scan des ports communs
```bash
python3 check_port.py localhost
python3 check_port.py 192.168.1.1 common
```

#### Scan rapide recommandé
```bash
python3 check_port.py 192.168.1.1 top1000
```

#### Scan de plages spécifiques
```bash
python3 check_port.py 192.168.1.1 1-1024      # Ports privilégiés
python3 check_port.py 192.168.1.1 8000-9000   # Plage personnalisée
```

#### Scan de ports spécifiques
```bash
python3 check_port.py 192.168.1.1 22,80,443,8080
```

#### Scan complet (⚠️ très long!)
```bash
python3 check_port.py 192.168.1.1 all
```

## 🛠️ Options de ports

| Option | Description | Nombre de ports | Temps estimé |
|--------|-------------|-----------------|--------------|
| `(vide)` | Ports communs | ~30 | < 1 seconde |
| `common` | Ports communs | ~30 | < 1 seconde |
| `top100` | Premiers 100 ports | 100 | ~2 secondes |
| `top1000` | Premiers 1000 ports | 1000 | ~10 secondes |
| `top5000` | Premiers 5000 ports | 5000 | ~1 minute |
| `1-1024` | Ports privilégiés | 1024 | ~10 secondes |
| `all` | Tous les ports | 65535 | 2-6 heures |

## 🔐 Gestion des permissions

### Linux/macOS
```bash
# Scan simple (aucun privilège requis)
python3 check_port.py 192.168.1.1

# Fermeture de services (privilèges root requis)
sudo python3 check_port.py localhost 3306
```

### Windows
```cmd
# Exécuter en tant qu'Administrateur pour fermer les services
python check_port.py localhost 3306
```

## 🎯 Services supportés

Le script détecte automatiquement ces services et propose un arrêt propre :

| Port | Service | Commande d'arrêt |
|------|---------|------------------|
| 21 | FTP | `systemctl stop vsftpd` |
| 22 | SSH | `systemctl stop ssh` |
| 25 | SMTP | `systemctl stop postfix` |
| 53 | DNS | `systemctl stop bind9` |
| 80 | HTTP | `systemctl stop apache2` |
| 443 | HTTPS | `systemctl stop apache2` |
| 3306 | MySQL | `systemctl stop mysql` |
| 5432 | PostgreSQL | `systemctl stop postgresql` |
| 6379 | Redis | `systemctl stop redis-server` |

## 📈 Optimisations par taille

### Petits scans (< 1000 ports)
- Timeout : 0.8 secondes
- Workers : 50-500
- Pas d'affichage de progrès

### Scans moyens (1000-10000 ports)
- Timeout : 0.5 secondes
- Workers : 500-800
- Affichage du progrès

### Gros scans (> 10000 ports)
- Timeout : 0.3 secondes
- Workers : 800-1000
- Affichage du progrès et ETA

## ⚠️ Avertissements et bonnes pratiques

### 🚨 **Scan complet (`all`)**
- Peut prendre **plusieurs heures**
- Consomme beaucoup de ressources
- Peut déclencher des systèmes de détection
- Utilisez `top1000` pour un bon compromis

### 🛡️ **Sécurité**
- Ne scannez que vos propres machines
- Respectez les politiques réseau
- Attention aux services critiques (SSH, DNS)

### 💾 **Services système**
- Privilégiez l'arrêt via `systemctl`
- Évitez le `kill -9` sur les bases de données
- Vérifiez l'impact avant de fermer un service

## 🐛 Résolution des problèmes

### Erreur "Permission refusée"
```bash
# Solution : exécuter avec sudo
sudo python3 check_port.py localhost 3306
```

### Aucun PID trouvé
```bash
# Vérifier manuellement
sudo lsof -i :3306
sudo netstat -tlnp | grep :3306
```

## ⚙️ Ports dynamiques (masqués par défaut)

Le script masque par défaut les ports "dynamiques" (éphémères, généralement > ~32768) car ils sont souvent temporaires et n'indiquent pas un service permanent.

- Pour voir aussi ces ports, utilisez le flag `--show-dynamic` :

```bash
python3 check_port.py --show-dynamic localhost all
# ou avec sudo pour obtenir les PID complets
sudo python3 check_port.py --show-dynamic localhost all
```

- Pourquoi les masquer ? Parce que ces ports sont souvent utilisés pour des connexions sortantes temporaires ou des services de développement et n'ont pas besoin d'être examinés systématiquement.

- Si un port dynamique reste **toujours** à l'écoute ou expose un service sur `0.0.0.0`, il faut l'investiguer (voir section "Aucun PID trouvé" et commandes `ss`/`lsof`).


### Service ne s'arrête pas
```bash
# Forcer l'arrêt
sudo systemctl stop mysql
sudo systemctl disable mysql  # Désactiver au démarrage
```

## 📝 Fichiers du projet

- `check_port.py` : Script principal
- `test_scan.py` : Script de test interactif
- `examples.sh` : Exemples d'utilisation
- `DOCUMENTATION.md` : Ce fichier

## 🔄 Versions

- **v1.0** : Scan de base
- **v2.0** : Optimisations et interface améliorée
- **v2.1** : Détection de services et arrêt intelligent
- **v2.2** : Traduction française et documentation
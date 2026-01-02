#!/bin/bash
#===============================================================================
# Installation du panneau d'administration OSINT
# Tous les fichiers (app.py, templates/, static/, etc.) doivent être 
# dans le même dossier que ce script
#===============================================================================

set -e

INSTALL_DIR="/opt/osint"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_error() { echo -e "${RED}[ERREUR]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[ATTENTION]${NC} $1"; }

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🛡️  Installation du Panneau Admin DR5-OA5"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Vérifications
if [ "$EUID" -ne 0 ]; then
    log_error "Ce script doit être exécuté en root"
    exit 1
fi

if [ ! -d "$INSTALL_DIR" ]; then
    log_error "$INSTALL_DIR n'existe pas. Installez d'abord le serveur OSINT."
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/app.py" ]; then
    log_error "app.py non trouvé dans $SCRIPT_DIR"
    log_error "Assurez-vous que tous les fichiers sont extraits dans le même dossier"
    exit 1
fi

if [ ! -d "$SCRIPT_DIR/templates" ]; then
    log_error "Dossier templates/ non trouvé"
    exit 1
fi

# Copier les fichiers
log_info "Copie des fichiers vers $INSTALL_DIR/admin-panel/"
mkdir -p "$INSTALL_DIR/admin-panel"
cp -r "$SCRIPT_DIR/app.py" "$INSTALL_DIR/admin-panel/"
cp -r "$SCRIPT_DIR/Dockerfile" "$INSTALL_DIR/admin-panel/"
cp -r "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/admin-panel/"
cp -r "$SCRIPT_DIR/templates" "$INSTALL_DIR/admin-panel/"
cp -r "$SCRIPT_DIR/static" "$INSTALL_DIR/admin-panel/"
log_success "Fichiers copiés"

# Installer werkzeug si nécessaire
log_info "Installation de werkzeug pour générer le hash..."
pip3 install werkzeug --break-system-packages -q 2>/dev/null || pip3 install werkzeug -q

# Générer credentials
log_info "Génération des credentials..."
ADMIN_PASSWORD=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16)
ADMIN_PASSWORD_HASH=$(python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('$ADMIN_PASSWORD'))")
ADMIN_SECRET_KEY=$(openssl rand -hex 32)
log_success "Credentials générés"

# Récupérer TAILSCALE_IP depuis .env
source "$INSTALL_DIR/.env" 2>/dev/null || true
if [ -z "$TAILSCALE_IP" ]; then
    TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "127.0.0.1")
    log_warn "TAILSCALE_IP non trouvé dans .env, utilisation de: $TAILSCALE_IP"
fi

# Ajouter au .env
log_info "Mise à jour de .env..."
cat >> "$INSTALL_DIR/.env" << EOF

# Admin Panel
ADMIN_PASSWORD_HASH='$ADMIN_PASSWORD_HASH'
ADMIN_SECRET_KEY=$ADMIN_SECRET_KEY
EOF
log_success ".env mis à jour"

# Vérifier si le service existe déjà dans docker-compose
if grep -q "osint-admin" "$INSTALL_DIR/docker-compose.yml" 2>/dev/null; then
    log_warn "Le service osint-admin existe déjà dans docker-compose.yml"
else
    log_info "Ajout du service au docker-compose.yml..."
    cat >> "$INSTALL_DIR/docker-compose.yml" << EOF

  #=============================================================================
  # OSINT ADMIN PANEL - DR5-OA5
  #=============================================================================
  osint-admin:
    build: ./admin-panel
    container_name: osint-admin
    restart: unless-stopped
    networks:
      - osint_network
    environment:
      - INSTALL_DIR=/opt/osint
      - ADMIN_USERNAME=admin
      - ADMIN_PASSWORD_HASH=\${ADMIN_PASSWORD_HASH}
      - ADMIN_SECRET_KEY=\${ADMIN_SECRET_KEY}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc/wireguard:/etc/wireguard
      - /etc/amnezia:/etc/amnezia
      - \${INSTALL_DIR}/clients:/opt/osint/clients
    ports:
      - "10.10.0.1:5000:5000"
      - "${TAILSCALE_IP}:5000:5000"
EOF
    log_success "docker-compose.yml mis à jour"
fi

# Sauvegarder credentials
log_info "Sauvegarde des credentials..."
cat >> "$INSTALL_DIR/credentials.txt" << EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PANNEAU ADMIN DR5-OA5
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
URL (VPN)      : http://10.10.0.1:5000
URL (Tailscale): http://${TAILSCALE_IP}:5000
Username       : admin
Password       : $ADMIN_PASSWORD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
log_success "Credentials sauvegardés dans $INSTALL_DIR/credentials.txt"

# Build et start
log_info "Construction de l'image Docker..."
cd "$INSTALL_DIR"
docker compose build osint-admin
log_success "Image construite"

log_info "Démarrage du service..."
docker compose up -d osint-admin
log_success "Service démarré"

# Vérification
sleep 3
if docker ps | grep -q osint-admin; then
    log_success "Container osint-admin en cours d'exécution"
else
    log_error "Le container ne semble pas démarré. Vérifiez avec: docker logs osint-admin"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ Installation terminée !"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  📍 Accès au panneau admin:"
echo ""
echo "     Via VPN      : http://10.10.0.1:5000"
echo "     Via Tailscale: http://${TAILSCALE_IP}:5000"
echo ""
echo "  🔐 Identifiants:"
echo ""
echo "     Username : admin"
echo "     Password : $ADMIN_PASSWORD"
echo ""
echo "  📝 Credentials sauvegardés dans:"
echo "     $INSTALL_DIR/credentials.txt"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

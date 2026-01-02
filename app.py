#!/usr/bin/env python3
"""
OSINT Server Admin Panel
Panneau d'administration pour la gestion du serveur OSINT
"""

import os
import subprocess
import json
import secrets
import qrcode
import io
import base64
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('ADMIN_SECRET_KEY', secrets.token_hex(32))

# Configuration
INSTALL_DIR = os.environ.get('INSTALL_DIR', '/opt/osint')
WG_CONFIG = '/etc/wireguard/wg0.conf'
AMNEZIA_DIR = '/etc/amnezia/wireguard'
CLIENTS_DIR = f'{INSTALL_DIR}/clients'
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', generate_password_hash('changeme'))


# =============================================================================
# AUTHENTIFICATION
# =============================================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['logged_in'] = True
            session['username'] = username
            flash('Connexion réussie', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Identifiants incorrects', 'error')
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Déconnexion réussie', 'success')
    return redirect(url_for('login'))


# =============================================================================
# DASHBOARD
# =============================================================================

@app.route('/')
@login_required
def dashboard():
    # État des containers Docker
    containers = get_docker_status()
    
    # État WireGuard
    wg_status = get_wireguard_status()
    
    # Statistiques utilisateurs
    users = get_vpn_users()
    connected_users = sum(1 for u in users if u['status'] == 'connected')
    
    # Infos système
    system_info = get_system_info()
    
    return render_template('dashboard.html',
                         containers=containers,
                         wg_status=wg_status,
                         users=users,
                         connected_users=connected_users,
                         total_users=len(users),
                         system_info=system_info)


# =============================================================================
# GESTION UTILISATEURS VPN
# =============================================================================

@app.route('/users')
@login_required
def users():
    vpn_users = get_vpn_users()
    return render_template('users.html', users=vpn_users)


@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        
        # Validation
        if not username:
            flash('Le nom d\'utilisateur est requis', 'error')
            return redirect(url_for('add_user'))
        
        # Nettoyer le nom (alphanumérique + underscore)
        username = ''.join(c if c.isalnum() or c == '_' else '_' for c in username)
        
        # Vérifier si existe déjà
        user_dir = os.path.join(CLIENTS_DIR, username)
        if os.path.exists(user_dir):
            flash(f'L\'utilisateur {username} existe déjà', 'error')
            return redirect(url_for('add_user'))
        
        # Créer l'utilisateur
        success, message, qr_data = create_vpn_user(username)
        
        if success:
            flash(f'Utilisateur {username} créé avec succès', 'success')
            return redirect(url_for('user_detail', username=username))
        else:
            flash(f'Erreur: {message}', 'error')
            return redirect(url_for('add_user'))
    
    return render_template('add_user.html')


@app.route('/users/<username>')
@login_required
def user_detail(username):
    user_dir = os.path.join(CLIENTS_DIR, username)
    
    if not os.path.exists(user_dir):
        flash('Utilisateur non trouvé', 'error')
        return redirect(url_for('users'))
    
    # Lire la config
    config_file = os.path.join(user_dir, f'{username}.conf')
    config_content = ''
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config_content = f.read()
    
    # Générer QR code
    qr_base64 = generate_qr_base64(config_content)
    
    # Statut connexion
    users = get_vpn_users()
    user_info = next((u for u in users if u['name'] == username), None)
    
    return render_template('user_detail.html',
                         username=username,
                         config_content=config_content,
                         qr_base64=qr_base64,
                         user_info=user_info)


@app.route('/users/<username>/delete', methods=['POST'])
@login_required
def delete_user(username):
    success, message = remove_vpn_user(username)
    
    if success:
        flash(f'Utilisateur {username} supprimé', 'success')
    else:
        flash(f'Erreur: {message}', 'error')
    
    return redirect(url_for('users'))


@app.route('/users/<username>/download')
@login_required
def download_config(username):
    config_file = os.path.join(CLIENTS_DIR, username, f'{username}.conf')
    
    if not os.path.exists(config_file):
        flash('Fichier de configuration non trouvé', 'error')
        return redirect(url_for('users'))
    
    return send_file(config_file,
                    as_attachment=True,
                    download_name=f'{username}.conf',
                    mimetype='text/plain')


@app.route('/users/<username>/qr')
@login_required
def download_qr(username):
    config_file = os.path.join(CLIENTS_DIR, username, f'{username}.conf')
    
    if not os.path.exists(config_file):
        flash('Configuration non trouvée', 'error')
        return redirect(url_for('users'))
    
    with open(config_file, 'r') as f:
        config_content = f.read()
    
    # Générer QR code PNG
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(config_content)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    return send_file(img_io,
                    mimetype='image/png',
                    as_attachment=True,
                    download_name=f'{username}-qr.png')


# =============================================================================
# SERVICES DOCKER
# =============================================================================

@app.route('/services')
@login_required
def services():
    containers = get_docker_status()
    return render_template('services.html', containers=containers)


@app.route('/services/<container>/restart', methods=['POST'])
@login_required
def restart_service(container):
    try:
        subprocess.run(['docker', 'restart', container], check=True, capture_output=True)
        flash(f'Service {container} redémarré', 'success')
    except subprocess.CalledProcessError as e:
        flash(f'Erreur: {e.stderr.decode()}', 'error')
    
    return redirect(url_for('services'))


@app.route('/services/<container>/logs')
@login_required
def service_logs(container):
    try:
        result = subprocess.run(
            ['docker', 'logs', container, '--tail', '100'],
            capture_output=True,
            text=True
        )
        logs = result.stdout + result.stderr
    except Exception as e:
        logs = f"Erreur: {str(e)}"
    
    return render_template('logs.html', container=container, logs=logs)


# =============================================================================
# PASSBOLT
# =============================================================================

@app.route('/passbolt')
@login_required
def passbolt():
    users = get_passbolt_users()
    return render_template('passbolt.html', users=users)


@app.route('/passbolt/add', methods=['GET', 'POST'])
@login_required
def add_passbolt_user():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        firstname = request.form.get('firstname', '').strip()
        lastname = request.form.get('lastname', '').strip()
        role = request.form.get('role', 'user')
        
        if not all([email, firstname, lastname]):
            flash('Tous les champs sont requis', 'error')
            return redirect(url_for('add_passbolt_user'))
        
        success, message = create_passbolt_user(email, firstname, lastname, role)
        
        if success:
            flash(f'Utilisateur Passbolt créé. Lien d\'activation:\n{message}', 'success')
        else:
            flash(f'Erreur: {message}', 'error')
        
        return redirect(url_for('passbolt'))
    
    return render_template('add_passbolt_user.html')


# =============================================================================
# SYSTÈME
# =============================================================================

@app.route('/system')
@login_required
def system():
    system_info = get_system_info()
    wg_config = get_wireguard_config()
    return render_template('system.html', system_info=system_info, wg_config=wg_config)


@app.route('/system/restart-wireguard', methods=['POST'])
@login_required
def restart_wireguard():
    try:
        subprocess.run(['systemctl', 'restart', 'wg-quick@wg0'], check=True)
        flash('WireGuard redémarré', 'success')
    except subprocess.CalledProcessError as e:
        flash(f'Erreur: {str(e)}', 'error')
    
    return redirect(url_for('system'))


# =============================================================================
# API JSON
# =============================================================================

@app.route('/api/status')
@login_required
def api_status():
    return jsonify({
        'containers': get_docker_status(),
        'wireguard': get_wireguard_status(),
        'users': get_vpn_users(),
        'system': get_system_info()
    })


@app.route('/api/users')
@login_required
def api_users():
    return jsonify(get_vpn_users())


# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

def get_docker_status():
    """Récupère l'état des containers Docker"""
    containers = []
    try:
        result = subprocess.run(
            ['docker', 'ps', '-a', '--format', '{{.Names}}|{{.Status}}|{{.Ports}}'],
            capture_output=True,
            text=True
        )
        for line in result.stdout.strip().split('\n'):
            if line:
                parts = line.split('|')
                if len(parts) >= 2:
                    name = parts[0]
                    status = parts[1]
                    ports = parts[2] if len(parts) > 2 else ''
                    
                    is_running = 'Up' in status
                    containers.append({
                        'name': name,
                        'status': status,
                        'ports': ports,
                        'running': is_running
                    })
    except Exception as e:
        print(f"Erreur Docker: {e}")
    
    return containers


def get_wireguard_status():
    """Récupère l'état de WireGuard"""
    status = {'active': False, 'interface': 'wg0', 'peers': []}
    
    try:
        result = subprocess.run(
            ['wg', 'show', 'wg0'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            status['active'] = True
            status['raw'] = result.stdout
            
            # Parser les peers
            current_peer = None
            for line in result.stdout.split('\n'):
                if line.startswith('peer:'):
                    if current_peer:
                        status['peers'].append(current_peer)
                    current_peer = {'public_key': line.split(':')[1].strip()}
                elif current_peer and ':' in line:
                    key, value = line.strip().split(':', 1)
                    current_peer[key.strip().replace(' ', '_')] = value.strip()
            
            if current_peer:
                status['peers'].append(current_peer)
                
    except Exception as e:
        print(f"Erreur WireGuard: {e}")
    
    return status


def get_vpn_users():
    """Liste les utilisateurs VPN"""
    users = []
    
    if not os.path.exists(CLIENTS_DIR):
        return users
    
    # Récupérer les clés publiques connectées
    connected_keys = set()
    try:
        result = subprocess.run(['wg', 'show', 'wg0', 'peers'], capture_output=True, text=True)
        if result.returncode == 0:
            connected_keys = set(result.stdout.strip().split('\n'))
    except:
        pass
    
    # Récupérer les derniers handshakes
    handshakes = {}
    try:
        result = subprocess.run(['wg', 'show', 'wg0', 'latest-handshakes'], capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if '\t' in line:
                    key, timestamp = line.split('\t')
                    handshakes[key] = int(timestamp) if timestamp != '0' else 0
    except:
        pass
    
    for username in os.listdir(CLIENTS_DIR):
        user_dir = os.path.join(CLIENTS_DIR, username)
        if os.path.isdir(user_dir):
            public_key_file = os.path.join(user_dir, 'public.key')
            config_file = os.path.join(user_dir, f'{username}.conf')
            
            public_key = ''
            ip_address = ''
            
            if os.path.exists(public_key_file):
                with open(public_key_file, 'r') as f:
                    public_key = f.read().strip()
            
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    for line in f:
                        if line.startswith('Address'):
                            ip_address = line.split('=')[1].strip().split('/')[0]
                            break
            
            # Vérifier si connecté (handshake récent < 3 minutes)
            last_handshake = handshakes.get(public_key, 0)
            is_connected = (datetime.now().timestamp() - last_handshake) < 180 if last_handshake else False
            
            users.append({
                'name': username,
                'ip': ip_address,
                'public_key': public_key,
                'status': 'connected' if is_connected else 'offline',
                'last_handshake': datetime.fromtimestamp(last_handshake).strftime('%Y-%m-%d %H:%M:%S') if last_handshake else 'Jamais'
            })
    
    return sorted(users, key=lambda x: x['name'])


def create_vpn_user(username):
    """Crée un nouvel utilisateur VPN"""
    try:
        user_dir = os.path.join(CLIENTS_DIR, username)
        os.makedirs(user_dir, exist_ok=True)
        
        # Générer les clés
        private_key = subprocess.run(['wg', 'genkey'], capture_output=True, text=True).stdout.strip()
        public_key = subprocess.run(['wg', 'pubkey'], input=private_key, capture_output=True, text=True).stdout.strip()
        
        # Sauvegarder les clés
        with open(os.path.join(user_dir, 'private.key'), 'w') as f:
            f.write(private_key)
        os.chmod(os.path.join(user_dir, 'private.key'), 0o600)
        
        with open(os.path.join(user_dir, 'public.key'), 'w') as f:
            f.write(public_key)
        
        # Trouver la prochaine IP
        next_ip = get_next_ip()
        
        # Lire la clé publique du serveur
        server_public_key = ''
        with open(os.path.join(AMNEZIA_DIR, 'server_public.key'), 'r') as f:
            server_public_key = f.read().strip()
        
        # Récupérer l'IP publique
        public_ip = subprocess.run(['curl', '-4', '-s', 'ifconfig.me'], capture_output=True, text=True).stdout.strip()
        
        # Créer la config client
        config_content = f"""[Interface]
PrivateKey = {private_key}
Address = {next_ip}/32
DNS = 10.10.0.1

[Peer]
PublicKey = {server_public_key}
AllowedIPs = 10.10.0.0/24
Endpoint = {public_ip}:443
PersistentKeepalive = 25
"""
        
        config_file = os.path.join(user_dir, f'{username}.conf')
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        # Ajouter le peer au serveur
        with open(WG_CONFIG, 'a') as f:
            f.write(f"\n# {username} - {next_ip} - {datetime.now().strftime('%Y-%m-%d')}\n")
            f.write(f"[Peer]\n")
            f.write(f"PublicKey = {public_key}\n")
            f.write(f"AllowedIPs = {next_ip}/32\n")
        
        # Recharger WireGuard
        subprocess.run(['wg', 'syncconf', 'wg0', '/dev/stdin'], 
                      input=subprocess.run(['wg-quick', 'strip', 'wg0'], capture_output=True, text=True).stdout,
                      capture_output=True, text=True)
        
        # Générer QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(config_content)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(os.path.join(user_dir, f'{username}-qr.png'))
        
        return True, "Utilisateur créé", config_content
        
    except Exception as e:
        return False, str(e), None


def remove_vpn_user(username):
    """Supprime un utilisateur VPN"""
    try:
        user_dir = os.path.join(CLIENTS_DIR, username)
        
        if not os.path.exists(user_dir):
            return False, "Utilisateur non trouvé"
        
        # Lire la clé publique
        public_key_file = os.path.join(user_dir, 'public.key')
        public_key = ''
        if os.path.exists(public_key_file):
            with open(public_key_file, 'r') as f:
                public_key = f.read().strip()
        
        # Supprimer du fichier WireGuard
        if public_key:
            with open(WG_CONFIG, 'r') as f:
                lines = f.readlines()
            
            new_lines = []
            skip_until_next_peer = False
            
            for line in lines:
                if f'# {username}' in line:
                    skip_until_next_peer = True
                    continue
                if skip_until_next_peer:
                    if line.strip().startswith('[Peer]') or line.strip().startswith('[Interface]'):
                        if not line.strip().startswith(f'PublicKey = {public_key}'):
                            skip_until_next_peer = False
                            new_lines.append(line)
                    elif line.strip().startswith('PublicKey') or line.strip().startswith('AllowedIPs'):
                        continue
                    elif line.strip() == '':
                        skip_until_next_peer = False
                        continue
                else:
                    new_lines.append(line)
            
            with open(WG_CONFIG, 'w') as f:
                f.writelines(new_lines)
        
        # Recharger WireGuard
        subprocess.run(['wg', 'syncconf', 'wg0', '/dev/stdin'],
                      input=subprocess.run(['wg-quick', 'strip', 'wg0'], capture_output=True, text=True).stdout,
                      capture_output=True, text=True)
        
        # Supprimer le répertoire
        import shutil
        shutil.rmtree(user_dir)
        
        return True, "Utilisateur supprimé"
        
    except Exception as e:
        return False, str(e)


def get_next_ip():
    """Trouve la prochaine IP disponible"""
    used_ips = set()
    
    # Lire les IPs dans la config WireGuard
    if os.path.exists(WG_CONFIG):
        with open(WG_CONFIG, 'r') as f:
            for line in f:
                if 'AllowedIPs' in line:
                    ip = line.split('=')[1].strip().split('/')[0]
                    if ip.startswith('10.10.0.'):
                        used_ips.add(int(ip.split('.')[-1]))
    
    # Trouver la première IP libre (à partir de .2)
    for i in range(2, 255):
        if i not in used_ips:
            return f'10.10.0.{i}'
    
    raise Exception("Plus d'IP disponibles")


def generate_qr_base64(data):
    """Génère un QR code en base64"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    return base64.b64encode(img_io.getvalue()).decode()


def get_passbolt_users():
    """Liste les utilisateurs Passbolt"""
    users = []
    try:
        result = subprocess.run(
            ['docker', 'exec', 'passbolt', 'su', '-m', '-c',
             '/usr/share/php/passbolt/bin/cake passbolt get_users',
             '-s', '/bin/sh', 'www-data'],
            capture_output=True,
            text=True
        )
        # Parser la sortie
        for line in result.stdout.split('\n'):
            if '@' in line and '|' in line:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 4:
                    users.append({
                        'id': parts[0],
                        'name': parts[1],
                        'email': parts[2],
                        'role': parts[3] if len(parts) > 3 else 'user'
                    })
    except Exception as e:
        print(f"Erreur Passbolt: {e}")
    
    return users


def create_passbolt_user(email, firstname, lastname, role='user'):
    """Crée un utilisateur Passbolt"""
    try:
        result = subprocess.run(
            ['docker', 'exec', 'passbolt', 'su', '-m', '-c',
             f'/usr/share/php/passbolt/bin/cake passbolt register_user -u {email} -f {firstname} -l {lastname} -r {role}',
             '-s', '/bin/sh', 'www-data'],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            # Extraire le lien d'activation
            for line in result.stdout.split('\n'):
                if 'http' in line:
                    return True, line.strip()
            return True, result.stdout
        else:
            return False, result.stderr or result.stdout
            
    except Exception as e:
        return False, str(e)


def get_system_info():
    """Récupère les informations système"""
    info = {}
    
    try:
        # Uptime
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            info['uptime'] = f"{days}j {hours}h"
        
        # Mémoire
        with open('/proc/meminfo', 'r') as f:
            meminfo = {}
            for line in f:
                parts = line.split(':')
                if len(parts) == 2:
                    meminfo[parts[0].strip()] = int(parts[1].strip().split()[0])
            
            total = meminfo.get('MemTotal', 0) / 1024 / 1024
            available = meminfo.get('MemAvailable', 0) / 1024 / 1024
            used = total - available
            info['memory'] = f"{used:.1f} / {total:.1f} GB"
            info['memory_percent'] = int((used / total) * 100) if total else 0
        
        # Disque
        result = subprocess.run(['df', '-h', '/opt/osint'], capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                parts = lines[1].split()
                info['disk'] = f"{parts[2]} / {parts[1]}"
                info['disk_percent'] = int(parts[4].replace('%', ''))
        
        # Load average
        with open('/proc/loadavg', 'r') as f:
            load = f.readline().split()[:3]
            info['load'] = ' '.join(load)
            
    except Exception as e:
        print(f"Erreur système: {e}")
    
    return info


def get_wireguard_config():
    """Lit la configuration WireGuard"""
    if os.path.exists(WG_CONFIG):
        with open(WG_CONFIG, 'r') as f:
            return f.read()
    return "Configuration non trouvée"


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=os.environ.get('DEBUG', 'false').lower() == 'true')

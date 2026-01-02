FROM python:3.11-slim

WORKDIR /app

# Installer les dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copier les requirements et installer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier l'application
COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Variables d'environnement par défaut
ENV FLASK_APP=app.py
ENV INSTALL_DIR=/opt/osint
ENV ADMIN_USERNAME=admin

# Port
EXPOSE 5000

# Lancer avec gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]

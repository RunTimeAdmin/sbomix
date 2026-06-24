#!/usr/bin/env bash
# PackrAI VPS bootstrap — run as root on 76.13.101.31 (Ubuntu 22.04)
# Usage: bash /tmp/vps-setup.sh
set -euo pipefail

REPO_URL="https://github.com/RunTimeAdmin/PACKRAI.git"
INSTALL_DIR="/opt/packrai"
NGINX_CONF="/etc/nginx/sites-available/packrai-api"

echo "==> Checking Docker..."
if ! command -v docker &>/dev/null; then
    echo "==> Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
fi

if ! docker compose version &>/dev/null 2>&1; then
    echo "==> Installing Docker Compose plugin..."
    apt-get install -y docker-compose-plugin
fi

echo "==> Docker OK: $(docker --version)"
echo "==> Docker Compose OK: $(docker compose version)"

echo "==> Cloning/updating repo..."
if [ -d "$INSTALL_DIR/.git" ]; then
    git -C "$INSTALL_DIR" pull --ff-only
else
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

if [ ! -f "$INSTALL_DIR/.env" ]; then
    if [ -f /tmp/packrai.env ]; then
        mv /tmp/packrai.env "$INSTALL_DIR/.env"
        echo "==> .env installed from /tmp/packrai.env"
    else
        echo "ERROR: .env not found. Upload: scp deploy/vps.env root@76.13.101.31:/tmp/packrai.env"
        exit 1
    fi
fi

echo "==> Starting PackrAI stack (API + Postgres)..."
docker compose -f "$INSTALL_DIR/docker-compose.yml" --env-file "$INSTALL_DIR/.env" up -d --build

echo "==> Waiting for stack to come up..."
sleep 10
docker compose -f "$INSTALL_DIR/docker-compose.yml" ps

echo "==> Setting up nginx vhost (HTTP only)..."
cp /tmp/packrai-nginx.conf "$NGINX_CONF"
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/packrai-api
nginx -t && systemctl reload nginx

echo ""
echo "==> DONE."
echo "    API running at: http://76.13.101.31:3080  (Docker internal)"
echo "    Nginx proxying: http://api.packrai.xyz → localhost:3080  (after DNS)"
echo ""
echo "==> NEXT STEPS:"
echo "    1. Add DNS A record: api.packrai.xyz → 76.13.101.31"
echo "    2. After DNS propagates run: certbot --nginx -d api.packrai.xyz"

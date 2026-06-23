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

if ! docker compose version &>/dev/null; then
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
        echo ""
        echo "ERROR: .env file not found. Upload it first:"
        echo "  scp deploy/vps.env root@76.13.101.31:/tmp/packrai.env"
        exit 1
    fi
fi

echo "==> Starting PackrAI stack..."
docker compose -f "$INSTALL_DIR/docker-compose.yml" --env-file "$INSTALL_DIR/.env" up -d --build

echo "==> Waiting for API to be healthy..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:3080/health >/dev/null 2>&1; then
        echo "==> API is up!"
        break
    fi
    sleep 2
done

echo "==> Setting up nginx vhost..."
cp /tmp/packrai-nginx.conf "$NGINX_CONF"
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/packrai-api
nginx -t && systemctl reload nginx

echo ""
echo "==> DONE. API running at http://localhost:3080"
echo "==> Next: point api.packrai.xyz DNS A record at 76.13.101.31"
echo "==> Then run: certbot --nginx -d api.packrai.xyz"

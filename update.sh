#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="${APP_DIR:-/opt/antigravity-gateway}"
CONTAINER="${CONTAINER_NAME:-antigravity-gateway}"
REPO_URL="${REPO_URL:-https://github.com/qingan123/Antigravity-gateway.git}"
if [[ "$(id -u)" -ne 0 ]]; then echo "请使用 root 运行：sudo bash update.sh"; exit 1; fi
command -v docker >/dev/null || { echo "未检测到 Docker。"; exit 1; }
[[ -d "$APP_DIR/.git" ]] || { echo "未找到 Git 安装目录，请先运行 deploy.sh。"; exit 1; }
port="$(cat "$APP_DIR/.install-port" 2>/dev/null || true)"
port="${port:-8080}"
cp -a "$APP_DIR/.env" "/tmp/antigravity-env.$$"
cp -a "$APP_DIR/data" "/tmp/antigravity-data.$$"
git -C "$APP_DIR" fetch --depth=1 origin main
git -C "$APP_DIR" reset --hard origin/main
cp "/tmp/antigravity-env.$$" "$APP_DIR/.env"
rm -rf "$APP_DIR/data"
mv "/tmp/antigravity-data.$$" "$APP_DIR/data"
chmod 600 "$APP_DIR/.env"
docker build -t antigravity-gateway:latest "$APP_DIR"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" --restart unless-stopped --env-file "$APP_DIR/.env" --add-host host.docker.internal:host-gateway -p "${port}:8080" -v "$APP_DIR/data:/app/data" antigravity-gateway:latest >/dev/null
for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "http://127.0.0.1:${port}/healthz"; printf '\n更新完成，端口保持 %s。\n' "$port"

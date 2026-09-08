#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="${REPO_URL:-https://github.com/qingan123/Antigravity-gateway.git}"
APP_DIR="${APP_DIR:-/opt/antigravity-gateway}"
CONTAINER="${CONTAINER_NAME:-antigravity-gateway}"
DEFAULT_PORT="${PORT:-8080}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "请使用 root 运行：sudo bash deploy.sh"
  exit 1
fi

command -v docker >/dev/null || { echo "未检测到 Docker，请先安装 Docker。"; exit 1; }

read -r -p "宿主机端口 [${DEFAULT_PORT}]: " HOST_PORT
HOST_PORT="${HOST_PORT:-$DEFAULT_PORT}"
[[ "$HOST_PORT" =~ ^[0-9]+$ && "$HOST_PORT" -ge 1 && "$HOST_PORT" -le 65535 ]] || { echo "端口无效。"; exit 1; }

mkdir -p "$APP_DIR"
if [[ -d "$APP_DIR/.git" ]]; then
  git -C "$APP_DIR" fetch --depth=1 origin main
  git -C "$APP_DIR" reset --hard origin/main
else
  tmp="${APP_DIR}.new.$$"
  rm -rf "$tmp"
  git clone --depth=1 "$REPO_URL" "$tmp"
  if [[ -f "$APP_DIR/.env" ]]; then cp "$APP_DIR/.env" "$tmp/.env"; fi
  if [[ -d "$APP_DIR/data" ]]; then cp -a "$APP_DIR/data" "$tmp/data"; fi
  rm -rf "$APP_DIR"
  mv "$tmp" "$APP_DIR"
fi

mkdir -p "$APP_DIR/data"
ENV_FILE="$APP_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  cp "$APP_DIR/.env.example" "$ENV_FILE"
fi

ask_secret() {
  local name="$1" prompt="$2" current=""
  current="$(grep -E "^${name}=" "$ENV_FILE" 2>/dev/null | head -n1 | cut -d= -f2- || true)"
  if [[ -n "$current" && "$current" != *"change-me"* && "$current" != *"redacted"* && "$current" != "your-random-hmac-secret-at-least-16-bytes" ]]; then
    return
  fi
  read -r -s -p "$prompt: " value; echo
  [[ -n "$value" ]] || { echo "该值不能为空。"; exit 1; }
  sed -i "s|^${name}=.*|${name}=${value}|" "$ENV_FILE"
}

ask_value() {
  local name="$1" prompt="$2" default="$3" current="" value=""
  current="$(grep -E "^${name}=" "$ENV_FILE" 2>/dev/null | head -n1 | cut -d= -f2- || true)"
  if [[ -n "$current" && "$current" != *"api.openai.com"* && "$current" != *"redacted"* ]]; then return; fi
  read -r -p "$prompt [${default}]: " value
  value="${value:-$default}"
  sed -i "s|^${name}=.*|${name}=${value}|" "$ENV_FILE"
}

ask_value UPSTREAM_BASE_URL "上游 API 根地址" "https://api.openai.com"
ask_secret UPSTREAM_API_KEY "上游 API Key（输入不可见）"
ask_secret ADMIN_API_KEY "管理员密码/Key（输入不可见）"
ask_secret KEY_HMAC_SECRET "Key HMAC Secret（输入不可见，至少16位）"

sed -i "s|^PORT=.*|PORT=8080|" "$ENV_FILE"
sed -i "s|^HOST=.*|HOST=0.0.0.0|" "$ENV_FILE"
chmod 600 "$ENV_FILE"

docker build -t antigravity-gateway:latest "$APP_DIR"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" --restart unless-stopped \
  --env-file "$ENV_FILE" \
  --add-host host.docker.internal:host-gateway \
  -p "${HOST_PORT}:8080" \
  -v "$APP_DIR/data:/app/data" \
  antigravity-gateway:latest >/dev/null
printf '%s\n' "$HOST_PORT" > "$APP_DIR/.install-port"

for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${HOST_PORT}/healthz" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${HOST_PORT}/healthz"
printf '\n部署完成：管理页面 http://你的服务器IP:%s/admin\n' "$HOST_PORT"

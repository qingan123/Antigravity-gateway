#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="${APP_DIR:-/opt/antigravity-gateway}"
CONTAINER="${CONTAINER_NAME:-antigravity-gateway}"
if [[ "$(id -u)" -ne 0 ]]; then echo "请使用 root 运行：sudo bash uninstall.sh"; exit 1; fi
read -r -p "确认卸载容器和程序，但保留数据目录 ${APP_DIR}/data？输入 YES: " answer
[[ "$answer" == "YES" ]] || { echo "已取消。"; exit 0; }
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker rmi antigravity-gateway:latest >/dev/null 2>&1 || true
rm -rf "$APP_DIR/.git" "$APP_DIR/cmd" "$APP_DIR/internal" "$APP_DIR/Dockerfile" "$APP_DIR/go.mod" "$APP_DIR/go.sum" "$APP_DIR/README.md" "$APP_DIR/deploy.sh" "$APP_DIR/update.sh" "$APP_DIR/uninstall.sh" "$APP_DIR/.env.example"
printf '已卸载容器和程序文件；数据与 .env 保留在 %s。\n' "$APP_DIR"

#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CMD="$1"

# Self-signed certificate for local HTTPS; the key stays out of git (nginx/certs/ is ignored).
ensure_certs() {
  CERT_DIR="nginx/certs"
  if [ -f "$CERT_DIR/server.crt" ] && [ -f "$CERT_DIR/server.key" ]; then
    return
  fi
  mkdir -p "$CERT_DIR"
  echo "Generating self-signed TLS certificate in $CERT_DIR ..."
  MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
}

case "$CMD" in
  start)
    ensure_certs
    docker compose up --build
    ;;
  stop)
    docker compose down
    ;;
  reset)
    docker compose down -v
    ensure_certs
    docker compose up --build
    ;;
  rebuild)
    ensure_certs
    docker compose pull --ignore-pull-failures
    docker compose build --no-cache
    docker compose up -d --force-recreate --remove-orphans
    echo "Stack running in the background: https://localhost:18443"
    ;;
  logs)
    docker compose logs -f
    ;;
  *)
    echo "Usage: ./dat250.sh {start|stop|reset|rebuild|logs}"
    echo "  start   — foreground: compose up --build"
    echo "  stop    — compose down"
    echo "  reset   — remove volumes (fresh DB), then up --build (foreground)"
    echo "  rebuild — pull bases, rebuild backend image (--no-cache), recreate containers (-d)"
    echo "  logs    — follow compose logs"
    exit 1
    ;;
esac

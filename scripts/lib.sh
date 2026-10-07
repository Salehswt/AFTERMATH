#!/usr/bin/env bash
# lib.sh — shared logging + helpers, sourced by install.sh and lab.sh
# Convention: color-coded log levels INFO / STEP / OK / WARN / ERR

set -o errexit
set -o nounset
set -o pipefail

# ---- colors (disabled when not a tty or NO_COLOR set) -----------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\033[0m'; C_BLUE=$'\033[34m'; C_CYAN=$'\033[36m'
  C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_DIM=$'\033[2m'
else
  C_RESET=""; C_BLUE=""; C_CYAN=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_DIM=""
fi

log_info() { printf '%s[INFO]%s %s\n' "$C_BLUE"   "$C_RESET" "$*"; }
log_step() { printf '%s[STEP]%s %s\n' "$C_CYAN"   "$C_RESET" "$*"; }
log_ok()   { printf '%s[ OK ]%s %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
log_warn() { printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
log_err()  { printf '%s[ERR ]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; }
die()      { log_err "$*"; exit 1; }

# ---- paths ------------------------------------------------------------------
LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${LAB_ROOT}/.env"

# ---- host / prereq helpers --------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

detect_os() {
  case "$(uname -s)" in
    Linux)  echo "linux" ;;
    Darwin) echo "macos" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) echo "unknown" ;;
  esac
}

# Cross-platform "install package X" — best effort, asks before touching host.
pkg_install() {
  local pkg="$1" os; os="$(detect_os)"
  log_warn "$pkg not found."
  if [[ "${LAB_AUTO:-0}" != "1" ]]; then
    read -r -p "    Install $pkg now? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || die "$pkg is required. Aborting."
  fi
  case "$os" in
    linux)   sudo apt-get update -qq && sudo apt-get install -y "$pkg" ;;
    macos)   brew install "$pkg" ;;
    windows) winget install --silent "$pkg" || choco install -y "$pkg" ;;
    *) die "Unsupported OS for auto-install; install $pkg manually." ;;
  esac
}

# Generate a random secret (used for .env passwords/tokens)
gen_secret() { openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24; }

# Load .env if present
load_env() { [[ -f "$ENV_FILE" ]] && set -a && source "$ENV_FILE" && set +a || true; }

# Poll a URL until it returns HTTP 200 (or timeout). Args: url, timeout_s
wait_http() {
  local url="$1" timeout="${2:-180}" waited=0
  log_step "Waiting for ${url} (max ${timeout}s)"
  until curl -ksf -o /dev/null "$url"; do
    sleep 5; waited=$((waited+5))
    (( waited >= timeout )) && die "Timed out waiting for ${url}"
    printf '%s  ...%ss%s\r' "$C_DIM" "$waited" "$C_RESET"
  done
  echo; log_ok "${url} is up"
}

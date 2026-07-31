#!/usr/bin/env bash
#
# install.sh — one-shot installer for ORION on Arch Linux.
#
# Installs: system deps (go, python, masscan, libpcap) via pacman, the Go-based
# recon/vuln tools via `go install`, ORION's Python deps into a venv, and the
# nuclei template set. Idempotent — safe to re-run. Individual tool failures are
# reported at the end rather than aborting the whole run.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
set -uo pipefail

# ---------- pretty output ---------------------------------------------------- #
c_orange=$'\e[38;5;208m'; c_grey=$'\e[38;5;245m'; c_red=$'\e[31m'
c_green=$'\e[32m'; c_bold=$'\e[1m'; c_reset=$'\e[0m'
log()  { printf "%s[*]%s %s\n"  "$c_orange" "$c_reset" "$*"; }
ok()   { printf "%s[+]%s %s\n"  "$c_green"  "$c_reset" "$*"; }
warn() { printf "%s[!]%s %s\n"  "$c_orange" "$c_reset" "$*"; }
err()  { printf "%s[x]%s %s\n"  "$c_red"    "$c_reset" "$*" >&2; }
hr()   { printf "%s%s%s\n" "$c_grey" "────────────────────────────────────────────────────────" "$c_reset"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
declare -A RESULT   # tool -> ok|fail

banner() {
  printf "%s%s" "$c_bold" "$c_orange"
  cat <<'EOF'

  ██████  █████   ██████  ██████  ██   ██   ORION installer
  ██  ██  ██  ██    ██    ██  ██  ███  ██   Arch Linux
  ██  ██  █████     ██    ██  ██  ████ ██
  ██  ██  ██ ██     ██    ██  ██  ██ ████   recon · fuzzing
  ██████  ██  ██  ██████  ██████  ██   ██   mcp-ai · leaks
EOF
  printf "%s\n" "$c_reset"
}

# ---------- preflight -------------------------------------------------------- #
preflight() {
  if [[ $EUID -eq 0 ]]; then
    err "Don't run this as root. It uses sudo only where needed."
    exit 1
  fi
  if ! command -v pacman >/dev/null 2>&1; then
    err "pacman not found — this installer targets Arch Linux."
    err "On another distro, install the deps listed in README.md manually."
    exit 1
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    err "sudo is required. Install it first: pacman -S sudo (as root)."
    exit 1
  fi
  # Arch keyring can be stale on fresh installs; a light sync avoids 404s.
  log "Refreshing pacman databases..."
  sudo pacman -Sy --noconfirm >/dev/null 2>&1 || warn "pacman -Sy had warnings; continuing."
}

# ---------- system packages -------------------------------------------------- #
install_system() {
  hr; log "Installing system packages (go, python, masscan, libpcap, git)..."
  local pkgs=(go python python-pip git libpcap base-devel)
  if sudo pacman -S --needed --noconfirm "${pkgs[@]}"; then
    ok "Core system packages present."
  else
    warn "Some core packages failed; check output above."
  fi

  # masscan lives in the official repos on most mirrors; fall back to AUR note.
  if sudo pacman -S --needed --noconfirm masscan 2>/dev/null; then
    RESULT[masscan]=ok; ok "masscan installed."
  else
    RESULT[masscan]=fail
    warn "masscan not in your repos. Install from AUR, e.g.:  yay -S masscan"
  fi
}

# ---------- Go environment --------------------------------------------------- #
setup_go_env() {
  hr; log "Configuring Go environment..."
  export GOPATH="${GOPATH:-$HOME/go}"
  export GOBIN="$GOPATH/bin"
  export PATH="$PATH:$GOBIN"
  mkdir -p "$GOBIN"

  local goversion
  goversion="$(go version 2>/dev/null | grep -oP 'go\K[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)"
  log "Detected Go ${goversion:-unknown}. (nuclei needs >= 1.24.2)"

  # Persist GOBIN on PATH for future shells.
  local rc="$HOME/.bashrc"; [[ -n "${ZSH_VERSION:-}" || "$SHELL" == *zsh ]] && rc="$HOME/.zshrc"
  if ! grep -qs 'go/bin' "$rc" 2>/dev/null; then
    {
      echo ''
      echo '# added by ORION install.sh'
      echo 'export GOPATH="$HOME/go"'
      echo 'export PATH="$PATH:$HOME/go/bin"'
    } >> "$rc"
    ok "Added \$HOME/go/bin to PATH in $rc (restart shell or 'source $rc')."
  else
    log "PATH already contains go/bin in $rc."
  fi
}

# ---------- Go tools --------------------------------------------------------- #
install_go_tools() {
  hr; log "Installing Go security tools (this can take a few minutes)..."
  declare -A tools=(
    [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    [ffuf]="github.com/ffuf/ffuf/v2@latest"
    [dalfox]="github.com/hahwul/dalfox/v2@latest"
  )
  local t
  for t in subfinder httpx nuclei ffuf dalfox; do
    log "go install ${t}..."
    if go install -v "${tools[$t]}" 2>&1 | tail -1; then
      if command -v "$t" >/dev/null 2>&1 || [[ -x "$GOBIN/$t" ]]; then
        RESULT[$t]=ok; ok "${t} installed."
      else
        RESULT[$t]=fail; warn "${t} built but not found on PATH."
      fi
    else
      RESULT[$t]=fail; err "${t} failed to install."
    fi
  done
}

# ---------- nuclei templates ------------------------------------------------- #
update_templates() {
  hr
  if command -v nuclei >/dev/null 2>&1 || [[ -x "$GOBIN/nuclei" ]]; then
    log "Updating nuclei templates..."
    "${GOBIN}/nuclei" -update-templates 2>&1 | tail -2 || warn "template update had warnings."
    ok "nuclei templates ready (~/nuclei-templates/)."
  else
    warn "Skipping template update — nuclei not installed."
  fi
}

# ---------- Python venv ------------------------------------------------------ #
setup_python() {
  hr; log "Setting up Python virtual environment..."
  cd "$SCRIPT_DIR"
  if [[ ! -f requirements.txt ]]; then
    err "requirements.txt not found in $SCRIPT_DIR."
    err "Run this script from the ORION project root (where requirements.txt lives)."
    RESULT[python-venv]=fail; return
  fi
  if [[ ! -d .venv ]]; then
    python -m venv .venv || { err "venv creation failed."; RESULT[python-venv]=fail; return; }
  fi
  # shellcheck disable=SC1091
  source .venv/bin/activate
  python -m pip install --upgrade pip >/dev/null 2>&1
  if python -m pip install -r requirements.txt; then
    RESULT[python-venv]=ok; ok "Python deps installed into .venv"
  else
    RESULT[python-venv]=fail; err "pip install failed."
  fi
}

# ---------- report ----------------------------------------------------------- #
report() {
  hr; printf "%s%sINSTALL SUMMARY%s\n" "$c_bold" "$c_orange" "$c_reset"; hr
  local key status mark
  for key in subfinder httpx nuclei ffuf dalfox masscan python-venv; do
    status="${RESULT[$key]:-skipped}"
    if [[ "$status" == ok ]]; then mark="${c_green}✓${c_reset}"; else mark="${c_red}✗${c_reset}"; fi
    printf "  %s  %-14s %s\n" "$mark" "$key" "$c_grey$status$c_reset"
  done
  hr
  cat <<EOF
${c_bold}Next steps:${c_reset}
  1. Reload PATH:        ${c_orange}source ~/.bashrc${c_reset}   (or restart the terminal)
  2. Activate the venv:  ${c_orange}source .venv/bin/activate${c_reset}
  3. Define your scope:  ${c_orange}cp scope.example.json scope.json${c_reset}  then edit in-scope targets
  4. Smoke-test banner:  ${c_orange}python -m orion.ui.banner${c_reset}
  5. First run:          ${c_orange}python -m orion.main --target <in-scope-domain> --scope scope.json${c_reset}

${c_grey}Reminder: only run ORION against assets you own or are explicitly authorized
to test. The scope guard will refuse anything not listed in scope.json.${c_reset}
EOF
}

main() {
  banner
  preflight
  install_system
  setup_go_env
  install_go_tools
  update_templates
  setup_python
  report
}

main "$@"

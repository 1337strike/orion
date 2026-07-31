#!/usr/bin/env bash
# scripts/check_secrets.sh
#
# Run this before EVERY git push.  Blocks the push if real secrets are staged.
# Hook it up automatically:
#   cp scripts/check_secrets.sh .git/hooks/pre-push && chmod +x .git/hooks/pre-push
#
set -euo pipefail

RED=$'\e[31m'; GREEN=$'\e[32m'; ORANGE=$'\e[38;5;208m'; RESET=$'\e[0m'

PATTERNS=(
    "discord\.com/api/webhooks/[0-9]{10,}"
    "api\.telegram\.org/bot[0-9]"
    "['\"][0-9a-zA-Z\-_]{20,}['\"].*secret\|secret.*['\"][0-9a-zA-Z\-_]{20,}['\"]"
    "AKIA[0-9A-Z]{16}"
    "-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY"
    "sk-[a-zA-Z0-9]{40,}"
    "(api_key|api-key|apikey)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
    "(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]"
    "Authorization:\s*Bearer\s+[a-zA-Z0-9\-._~+/]{20,}"
)

BLOCKED_FILES=(
    ".env"
    "scope.json"
    "*.db"
    "*.pem"
    "*.key"
)

echo "${ORANGE}[check_secrets] scanning staged files...${RESET}"

staged=$(git diff --cached --name-only 2>/dev/null || true)
if [[ -z "$staged" ]]; then
    echo "${GREEN}[ok] nothing staged — nothing to check.${RESET}"
    exit 0
fi

found=0

# 1. Block known-sensitive filenames.
for f in $staged; do
    fname=$(basename "$f")
    for blocked in "${BLOCKED_FILES[@]}"; do
        # shellcheck disable=SC2053
        if [[ "$fname" == $blocked ]]; then
            echo "${RED}[!!] BLOCKED FILE: $f matches '$blocked'${RESET}"
            found=1
        fi
    done
done

# 2. Scan file contents for secret patterns.
for f in $staged; do
    [[ -f "$f" ]] || continue
    for pat in "${PATTERNS[@]}"; do
        if grep -qiEe "$pat" "$f" 2>/dev/null; then
            echo "${RED}[!!] POSSIBLE SECRET in $f${RESET}"
            echo "     pattern: $pat"
            grep -niEe "$pat" "$f" 2>/dev/null | head -2 | sed 's/^/     /'
            found=1
        fi
    done
done

# 3. Make sure .gitignore hasn't shrunk (all critical paths still ignored).
MUST_IGNORE=(".env" "scope.json" "*.db" ".venv/" "__pycache__/")
for entry in "${MUST_IGNORE[@]}"; do
    if ! grep -qF "$entry" .gitignore 2>/dev/null; then
        echo "${RED}[!!] .gitignore is missing: $entry — add it before pushing!${RESET}"
        found=1
    fi
done

if [[ $found -eq 1 ]]; then
    echo ""
    echo "${RED}[BLOCKED] Push cancelled — fix the issues above before retrying.${RESET}"
    exit 1
fi

echo "${GREEN}[ok] no secrets detected in staged files.${RESET}"
exit 0

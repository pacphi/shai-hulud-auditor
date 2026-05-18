#!/usr/bin/env bash
# remediate-repo.sh — repo-level Mini Shai-Hulud cleanup helper.
#
# What this does (in order):
#   1. Refuses to run if persistence IOCs are present on the host.
#   2. Asks for confirmation, then snapshots if it can (APFS / git stash).
#   3. Removes node_modules and lockfiles in the target repo.
#   4. Tells you which deps to bump in package.json (does NOT edit it for you).
#   5. Optionally runs `pnpm|npm install --ignore-scripts`.
#   6. Re-runs audit.js against the repo.
#
# What this deliberately does NOT do:
#   - It will not edit your package.json. Version pinning is a human decision.
#   - It will not stop systemd / launchd units (use the triage scripts + docs).
#   - It will not rotate credentials.
#
# Usage:  scripts/remediate-repo.sh <repo-path> [--install]

set -euo pipefail

repo="${1:-}"
install_flag="${2:-}"

if [[ -z "$repo" ]]; then
  echo "usage: $0 <repo-path> [--install]"
  exit 2
fi
if [[ ! -d "$repo" ]]; then
  echo "ERROR: not a directory: $repo" >&2
  exit 2
fi
if [[ ! -f "$repo/package.json" ]]; then
  echo "ERROR: no package.json at $repo" >&2
  exit 2
fi

here="$(cd "$(dirname "$0")/.." && pwd)"
audit="$here/audit.js"
if [[ ! -f "$audit" ]]; then
  echo "ERROR: cannot find audit.js next to this script" >&2
  exit 2
fi

bold=$'\033[1m'; red=$'\033[31m'; yel=$'\033[33m'; grn=$'\033[32m'; rst=$'\033[0m'

echo "${bold}Step 1/6: Verify host has no persistence IOCs${rst}"
if node "$audit" "$HOME" 2>&1 | grep -E 'PRESENT:' >/dev/null; then
  echo "${red}${bold}REFUSING:${rst} persistence hooks detected on this host."
  echo "Run scripts/triage-$(uname -s | tr '[:upper:]' '[:lower:]' | sed 's/darwin/macos/').sh"
  echo "and follow the MACOS.md or LINUX.md remediation order BEFORE touching repos."
  exit 1
fi
echo "  ${grn}OK: no persistence hooks present on host.${rst}"

echo
echo "${bold}Step 2/6: Show what audit.js says about $repo${rst}"
node "$audit" "$repo" || true

echo
read -r -p "${yel}Proceed with destructive cleanup of $repo? [y/N] ${rst}" answer
case "$answer" in
  y|Y|yes|YES) ;;
  *) echo "Aborted."; exit 0 ;;
esac

echo
echo "${bold}Step 3/6: Snapshot${rst}"
if [[ "$(uname -s)" == "Darwin" ]]; then
  if tmutil localsnapshot >/dev/null 2>&1; then
    echo "  APFS local snapshot created."
  else
    echo "  ${yel}WARN: tmutil localsnapshot failed; continuing.${rst}"
  fi
fi
if (cd "$repo" && git rev-parse --is-inside-work-tree >/dev/null 2>&1); then
  (cd "$repo" && git stash push -u -m "shai-hulud-remediate-$(date -u +%FT%TZ)" >/dev/null 2>&1 || true)
  echo "  git stash saved (untracked included). 'git stash list' to inspect."
fi

echo
echo "${bold}Step 4/6: Remove node_modules and lockfiles${rst}"
for d in node_modules .next .turbo .nuxt dist build .cache .parcel-cache .svelte-kit; do
  if [[ -e "$repo/$d" ]]; then
    rm -rf "$repo/$d"
    echo "  rm -rf $repo/$d"
  fi
done
for f in package-lock.json pnpm-lock.yaml yarn.lock npm-shrinkwrap.json; do
  if [[ -e "$repo/$f" ]]; then
    rm -f "$repo/$f"
    echo "  rm     $repo/$f"
  fi
done

echo
echo "${bold}Step 5/6: Manual step — pin deps past the IOC versions${rst}"
echo "  Re-running audit to show which names to bump in package.json:"
node "$audit" "$repo" 2>&1 | grep -E 'package-json:|compromised versions' | sed 's/^/    /' || true
cat <<'EOF'

  For each name listed above, edit package.json to use a version above the
  highest compromised version. Examples (verify against `npm view <pkg> versions`):

    "@tanstack/react-router":      "^1.170.4"
    "@tanstack/router-plugin":     "^1.168.6"
    "@tanstack/router-core":       "^1.171.2"   (transitive; usually no edit needed)

  When the package.json is bumped, return here to run the install.
EOF

if [[ "$install_flag" != "--install" ]]; then
  echo
  echo "${bold}Step 6/6: SKIPPED.${rst} Re-run with --install once you've bumped package.json:"
  echo "    $0 $repo --install"
  exit 0
fi

echo
echo "${bold}Step 6/6: Install with lifecycle scripts disabled${rst}"
manager=""
if   [[ -f "$repo/pnpm-workspace.yaml" || -f "$repo/.pnpmfile.cjs" ]]; then manager="pnpm"
elif command -v pnpm >/dev/null 2>&1 && grep -q '"packageManager": "pnpm' "$repo/package.json" 2>/dev/null; then manager="pnpm"
elif [[ -f "$repo/package-lock.json" ]]; then manager="npm"
elif [[ -f "$repo/yarn.lock"        ]]; then manager="yarn"
else
  # default to pnpm if it exists, else npm
  if command -v pnpm >/dev/null 2>&1; then manager="pnpm"; else manager="npm"; fi
fi

echo "  using: $manager"
(
  cd "$repo"
  case "$manager" in
    pnpm) pnpm install --ignore-scripts ;;
    yarn) yarn install --ignore-scripts ;;
    npm)  npm  install --ignore-scripts ;;
  esac
)

echo
echo "${bold}Final: re-audit $repo${rst}"
if node "$audit" "$repo"; then
  echo "${grn}${bold}DONE.${rst} Repo is clean. Drop --ignore-scripts for normal day-to-day installs."
else
  echo "${red}${bold}STILL HAS FINDINGS.${rst} Re-check package.json pins and re-run."
  exit 1
fi

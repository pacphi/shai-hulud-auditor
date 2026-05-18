#!/usr/bin/env bash
# triage-macos.sh — READ-ONLY Shai-Hulud / Mini Shai-Hulud persistence inventory for macOS.
#
# This script never deletes, never stops services, never modifies anything.
# It prints what was found and what the human should do next. See MACOS.md
# for the destructive steps.
#
# Exit codes:
#   0  nothing found
#   1  one or more IOCs present
#   2  script error (e.g. not running on macOS)

set -u

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: this script is for macOS. Use triage-linux.sh on Linux." >&2
  exit 2
fi

bold=$'\033[1m'; red=$'\033[31m'; yel=$'\033[33m'; grn=$'\033[32m'; rst=$'\033[0m'
hits=0

note()  { printf '  %s%s%s\n' "$yel" "$*" "$rst"; }
bad()   { printf '  %s%sFOUND:%s %s\n' "$bold" "$red" "$rst" "$*"; hits=$((hits+1)); }
ok()    { printf '  %sclear:%s %s\n' "$grn" "$rst" "$*"; }
header(){ printf '\n%s%s%s\n' "$bold" "$*" "$rst"; printf '%s\n' "${*//?/-}"; }

check_file() {
  local p="$1"
  if [[ -e "$p" ]]; then bad "$p"; else ok "$p"; fi
}

header "Mini Shai-Hulud triage (macOS, read-only)"
echo "Host: $(hostname)   User: $USER   Date: $(date -u +%FT%TZ)"

header "1. LaunchAgents / LaunchDaemons"
for p in \
  "$HOME/Library/LaunchAgents/com.user.gh-token-monitor.plist" \
  "$HOME/Library/LaunchAgents/com.github.token-monitor.plist" \
  "/Library/LaunchAgents/com.user.gh-token-monitor.plist" \
  "/Library/LaunchDaemons/com.user.gh-token-monitor.plist"
do
  check_file "$p"
done

echo "  Scanning all LaunchAgent plists for token-monitor labels..."
for dir in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
  [[ -d "$dir" ]] || continue
  while IFS= read -r match; do
    [[ -n "$match" ]] && bad "$match (label contains token-monitor)"
  done < <(grep -l -E 'token-monitor|gh-token|TanStack' "$dir"/*.plist 2>/dev/null)
done

echo "  launchctl list output filtered for worm markers:"
# Match worm-style labels only. Exclude Apple's own CryptoTokenKit/iTunes etc.
worm_re='gh-token-monitor|github\.token-monitor|tanstack|router_init|router_runtime'
if launchctl list 2>/dev/null | grep -vE '^[0-9-]+\s+[0-9-]+\s+com\.apple\.' \
                                 | grep -Ei "$worm_re" >/dev/null; then
  launchctl list 2>/dev/null | grep -Ei "$worm_re" | sed 's/^/    /'
  bad "launchctl shows live worm-style process(es) above"
else
  ok "no worm-style processes in launchctl list"
fi

header "2. IDE / agent persistence directories"
for p in \
  "$HOME/.claude/setup.mjs" \
  "$HOME/.claude/router_runtime.js" \
  "$HOME/.claude/setup_bun.js" \
  "$HOME/.claude/bun_environment.js" \
  "$HOME/.vscode/setup.mjs"
do
  check_file "$p"
done

if [[ -f "$HOME/.vscode/tasks.json" ]]; then
  if grep -Eq 'router_runtime|router_init|folderOpen.*setup\.mjs' "$HOME/.vscode/tasks.json" 2>/dev/null; then
    bad "$HOME/.vscode/tasks.json (contains worm-style task)"
  else
    ok "$HOME/.vscode/tasks.json (no worm task patterns)"
  fi
fi

header "3. Worm payload on disk (Spotlight)"
for name in router_init.js router_runtime.js; do
  while IFS= read -r f; do
    [[ -n "$f" ]] && bad "$f"
  done < <(mdfind -name "$name" 2>/dev/null | head -20)
done

header "4. cron / login items"
if crontab -l 2>/dev/null | grep -Eq 'token|gh-token|router_init'; then
  bad "user crontab contains suspicious entries"
  crontab -l 2>/dev/null | grep -E 'token|gh-token|router_init' | sed 's/^/    /'
else
  ok "user crontab clean"
fi

if osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null \
   | tr ',' '\n' | grep -Eqi 'token|github-monitor'; then
  bad "GUI login items contain suspicious entry"
else
  ok "GUI login items clean"
fi

header "5. npm cache anomalies (informational)"
cache_tmp="$HOME/.npm/_cacache/tmp"
if [[ -d "$cache_tmp" ]]; then
  n=$(find "$cache_tmp" -maxdepth 1 -type d -name 'git-clone*' 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$n" -gt 0 ]]; then
    note "$n git-clone tmp dir(s) in $cache_tmp — inspect for orphan refs like tanstack/router#79ac49ee..."
  else
    ok "$cache_tmp has no git-clone tmp dirs"
  fi
fi

header "Summary"
if [[ "$hits" -eq 0 ]]; then
  printf '  %sNo persistence IOCs detected.%s Re-run after every npm install.\n' "$grn$bold" "$rst"
  exit 0
fi

printf '  %s%d IOC(s) detected.%s\n\n' "$red$bold" "$hits" "$rst"
cat <<'EOF'
  DO NOT revoke npm/GitHub tokens yet. The watchdog wipes $HOME on revoke.
  Next steps (see MACOS.md sections 1d → 2 → 3):

    1. Take an APFS snapshot:
         tmutil localsnapshot

    2. Disconnect from the network:
         networksetup -setairportpower en0 off
         (and unplug Ethernet)

    3. Stop the LaunchAgent BEFORE deleting it:
         launchctl bootout gui/$(id -u) <path-from-above>
       or, on older macOS:
         launchctl unload <path-from-above>

    4. Quarantine the artefacts (don't shred — IR may need them):
         mkdir -p ~/quarantine-shai-hulud
         mv <plist>      ~/quarantine-shai-hulud/
         mv ~/.claude    ~/quarantine-shai-hulud/dot-claude

    5. Re-run:   node audit.js ~
       Expect "Persistence hits: 0" before rotating any credentials.

    6. Rotate credentials from a DIFFERENT, clean machine (MACOS.md §2).

    7. Reinstall macOS (Recovery → Erase All Content and Settings).
EOF
exit 1

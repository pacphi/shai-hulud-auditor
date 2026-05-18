#!/usr/bin/env bash
# triage-linux.sh — READ-ONLY Shai-Hulud / Mini Shai-Hulud persistence inventory for Linux.
#
# This script never deletes, never stops services, never modifies anything.
# It prints what was found and what the human should do next. See LINUX.md
# for the destructive steps.
#
# Exit codes:
#   0  nothing found
#   1  one or more IOCs present
#   2  script error (e.g. not running on Linux)

set -u

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ERROR: this script is for Linux. Use triage-macos.sh on macOS." >&2
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

header "Mini Shai-Hulud triage (Linux, read-only)"
echo "Host: $(hostname)   User: $USER   Date: $(date -u +%FT%TZ)"

header "1. systemd units (user + system)"
for p in \
  "$HOME/.config/systemd/user/gh-token-monitor.service" \
  "$HOME/.config/systemd/user/token-monitor.service" \
  "$HOME/.local/bin/gh-token-monitor.sh" \
  "/etc/systemd/system/gh-token-monitor.service" \
  "/etc/systemd/user/gh-token-monitor.service" \
  "/usr/local/bin/gh-token-monitor.sh"
do
  check_file "$p"
done

echo "  systemctl --user list-unit-files (filtered for worm markers):"
worm_re='gh-token-monitor|token-monitor\.service|router_init|router_runtime'
if systemctl --user list-unit-files 2>/dev/null | grep -Ei "$worm_re" >/dev/null; then
  systemctl --user list-unit-files 2>/dev/null | grep -Ei "$worm_re" | sed 's/^/    /'
  bad "user systemd has worm-style unit(s) above"
else
  ok "user systemd: no worm-style units"
fi

echo "  systemctl (system) list-unit-files (filtered):"
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -Ei 'gh-token|token-monitor' >/dev/null; then
  systemctl list-unit-files 2>/dev/null | grep -Ei 'gh-token|token-monitor' | sed 's/^/    /'
  bad "system systemd has token-monitor unit(s) above"
else
  ok "system systemd: no token-monitor units"
fi

echo "  Scanning unit files for token-monitor exec strings..."
for dir in "$HOME/.config/systemd/user" "/etc/systemd/system" "/etc/systemd/user"; do
  [[ -d "$dir" ]] || continue
  while IFS= read -r match; do
    [[ -n "$match" ]] && bad "$match (unit references token-monitor)"
  done < <(grep -l -E 'gh-token-monitor|token-monitor|router_init' "$dir"/*.service 2>/dev/null)
done

header "2. cron / autostart"
if crontab -l 2>/dev/null | grep -Eq 'token|gh-token|router_init'; then
  bad "user crontab contains suspicious entries"
  crontab -l 2>/dev/null | grep -E 'token|gh-token|router_init' | sed 's/^/    /'
else
  ok "user crontab clean"
fi

for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron/crontabs; do
  if [[ -d "$d" ]] && grep -rlE 'gh-token|token-monitor|router_init' "$d" 2>/dev/null | head -5 | while read -r f; do bad "$f"; done; then :; fi
done

if [[ -d "$HOME/.config/autostart" ]]; then
  while IFS= read -r f; do
    [[ -n "$f" ]] && bad "$f"
  done < <(grep -lE 'gh-token|token-monitor|router_init' "$HOME/.config/autostart"/*.desktop 2>/dev/null)
fi

header "3. shell rc tampering"
rc_hit=0
for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.bash_profile" "$HOME/.config/fish/config.fish"; do
  [[ -f "$rc" ]] || continue
  if grep -Eq 'gh-token|token-monitor|router_init|router_runtime' "$rc"; then
    bad "$rc (worm marker present)"
    rc_hit=1
  fi
done
[[ "$rc_hit" -eq 0 ]] && ok "shell rc files clean"

header "4. IDE / agent persistence directories"
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

header "5. Worm payload on disk (bounded find, current FS only)"
echo "  (using -xdev to avoid wandering into /proc, /sys, NFS, etc.)"
for name in router_init.js router_runtime.js; do
  while IFS= read -r f; do
    [[ -n "$f" ]] && bad "$f"
  done < <(find / -xdev -name "$name" 2>/dev/null | head -20)
done
while IFS= read -r f; do
  [[ -n "$f" ]] && bad "$f"
done < <(find / -xdev \( -path '*/.claude/setup.mjs' -o -path '*/.vscode/setup.mjs' \) 2>/dev/null | head -20)

header "6. Live processes / outbound connections"
if pgrep -af 'token-monitor|router_runtime|router_init' >/dev/null 2>&1; then
  bad "live process matching worm name patterns:"
  pgrep -af 'token-monitor|router_runtime|router_init' | sed 's/^/    /'
else
  ok "no live worm-named processes"
fi

if command -v ss >/dev/null 2>&1; then
  if ss -ntp 2>/dev/null | grep -E 'node|bun' | grep -Eq 'getsession|tanstack-?\.com|83\.142\.209\.194'; then
    bad "outbound connection to known C2 detected (via ss)"
    ss -ntp 2>/dev/null | grep -E 'node|bun' | sed 's/^/    /'
  fi
fi

header "7. npm cache anomalies (informational)"
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
  Next steps (see LINUX.md sections 1d → 2 → 3):

    1. Take a filesystem snapshot:
         btrfs:  sudo btrfs subvolume snapshot -r / /snap-pre-rem-$(date +%F)
         LVM:    sudo lvcreate --size 5G --snapshot --name shai_snap /dev/mapper/vg0-root
         ZFS:    sudo zfs snapshot rpool/ROOT/default@pre-rem

    2. Block egress (keep loopback only):
         sudo iptables -P OUTPUT DROP
         sudo iptables -A OUTPUT -o lo -j ACCEPT
         sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    3. Stop the unit BEFORE deleting it:
         systemctl --user stop gh-token-monitor.service
         systemctl --user disable gh-token-monitor.service
         systemctl --user mask gh-token-monitor.service
       (and the system-level equivalents with sudo)

    4. Quarantine the artefacts (don't shred — IR may need them):
         mkdir -p ~/quarantine-shai-hulud
         mv ~/.config/systemd/user/gh-token-monitor.service ~/quarantine-shai-hulud/
         mv ~/.local/bin/gh-token-monitor.sh                ~/quarantine-shai-hulud/
         sudo mv /etc/systemd/system/gh-token-monitor.service ~/quarantine-shai-hulud/
         mv ~/.claude                                        ~/quarantine-shai-hulud/dot-claude

    5. Re-run:   node audit.js ~
       Expect "Persistence hits: 0" before rotating any credentials.

    6. Rotate credentials from a DIFFERENT, clean machine (LINUX.md §2).

    7. Reimage / rebuild the host (LINUX.md §3).
EOF
exit 1

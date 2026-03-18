#!/bin/bash
# =============================================================================
#  ids_monitor.sh — Linux Intrusion Detection Monitor (Terminal / SSH)
#
#  Usage:
#    sudo bash ids_monitor.sh            # single scan + report
#    sudo bash ids_monitor.sh --watch    # continuous mode (runs every 60s)
#    sudo bash ids_monitor.sh --baseline # create/refresh file integrity baseline
#    sudo bash ids_monitor.sh --help
#
#  Logs:  /var/log/ids_monitor.log   (all events)
#         /var/log/ids_alerts.log    (alerts only)
# =============================================================================

# Do NOT use set -e or pipefail — many checks legitimately return non-zero
# and we never want the script to silently exit mid-scan.

# ── Configuration ─────────────────────────────────────────────────────────────
LOG_FILE="/var/log/ids_monitor.log"
ALERT_FILE="/var/log/ids_alerts.log"
BASELINE_FILE="/var/lib/ids_monitor/baseline.md5"
WATCH_DIRS="/etc /usr/bin /usr/sbin /bin /sbin"   # dirs for file integrity check
MAX_FAILED_LOGINS=5       # alert if more failed logins than this
MAX_CONNECTIONS=80         # alert if open connections exceed this
SCAN_INTERVAL=60           # seconds between scans in --watch mode
# Ports that should never appear listening on your system — adjust as needed
SUSPICIOUS_PORTS="4444 1337 31337 6666 9999 5554 7777"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
WHT='\033[1;37m'
DIM='\033[2m'
RST='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
ts()    { date '+%Y-%m-%d %H:%M:%S'; }
log()   { echo "[$(ts)] $*" >> "$LOG_FILE"; }

# alert() writes to the full log every time, but only appends to the alert
# file when the message is NEW — stripping the timestamp before comparison
# so the same alert from two different scans counts as a duplicate.
alert() {
  local msg="$*"
  echo "[$(ts)] [ALERT] $msg" >> "$LOG_FILE"
  if ! grep -qF "[ALERT] $msg" "$ALERT_FILE" 2>/dev/null; then
    echo "[$(ts)] [ALERT] $msg" >> "$ALERT_FILE"
  fi
  echo -e "${RED}[ALERT]${RST} $msg"
}

warn()  { echo "[$(ts)] [WARN]  $*" >> "$LOG_FILE"
          echo -e "${YEL}[WARN] ${RST} $*"; }
info()  { echo "[$(ts)] [INFO]  $*" >> "$LOG_FILE"
          echo -e "${CYN}[INFO] ${RST} $*"; }
ok()    { echo "[$(ts)] [OK]    $*" >> "$LOG_FILE"
          echo -e "${GRN}[ OK ] ${RST} $*"; }

header() {
  echo ""
  echo -e "${WHT}══════════════════════════════════════════════════════${RST}"
  echo -e "${WHT}  $*${RST}"
  echo -e "${WHT}══════════════════════════════════════════════════════${RST}"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo -e "${RED}Error: run as root.  Try:  sudo bash ids_monitor.sh${RST}"
    exit 1
  fi
}

init() {
  mkdir -p /var/lib/ids_monitor 2>/dev/null || true
  touch "$LOG_FILE" "$ALERT_FILE" 2>/dev/null || {
    # Fallback to /tmp if /var/log is not writable
    LOG_FILE="/tmp/ids_monitor.log"
    ALERT_FILE="/tmp/ids_alerts.log"
    touch "$LOG_FILE" "$ALERT_FILE"
    echo -e "${YEL}[WARN]  Cannot write to /var/log — using /tmp instead${RST}"
  }
  chmod 600 "$LOG_FILE" "$ALERT_FILE" 2>/dev/null || true
}

# ── 1. Failed login attempts ───────────────────────────────────────────────────
check_failed_logins() {
  header "1. Failed Login Attempts (last 60 minutes)"

  local auth_log=""
  for f in /var/log/auth.log /var/log/secure; do
    [[ -f "$f" ]] && auth_log="$f" && break
  done

  if [[ -z "$auth_log" ]]; then
    warn "No auth log found (/var/log/auth.log or /var/log/secure)"
    return
  fi

  echo -e "  ${DIM}Window : last 60 minutes   Threshold : $MAX_FAILED_LOGINS${RST}"
  echo -e "  ${DIM}Auth log: $auth_log${RST}"
  echo ""

  # ── Extract lines from the last 60 minutes using awk ─────────────────────
  # auth.log format:  "Mar 18 14:05:32 hostname sshd[...]: Failed password..."
  # awk converts the log timestamp to epoch and compares against (now - 3600).
  # Works on GNU awk (gawk) which is standard on Linux.
  local cutoff=$(( $(date +%s) - 3600 ))
  local current_year
  current_year=$(date +%Y)

  local recent_lines
  recent_lines=$(awk -v cutoff="$cutoff" -v year="$current_year" '
    /Failed password/ {
      # Build a timestamp string the system can parse: "YYYY Mon DD HH:MM:SS"
      ts = year " " $1 " " $2 " " $3
      # Use mktime — requires "YYYY MM DD HH MM SS" with numeric month
      cmd = "date -d \"" ts "\" +%s 2>/dev/null"
      cmd | getline epoch
      close(cmd)
      if (epoch != "" && epoch+0 >= cutoff+0) {
        print $0
      }
    }
  ' "$auth_log" 2>/dev/null || true)

  local total=0
  if [[ -n "$recent_lines" ]]; then
    total=$(echo "$recent_lines" | wc -l) || total=0
  fi

  if (( total > MAX_FAILED_LOGINS )); then
    alert "Failed SSH logins in last hour: $total (threshold: $MAX_FAILED_LOGINS)"
    log "ALERT: $total failed logins in last 60 min"
  else
    ok "Failed logins in last hour: $total — within threshold ($MAX_FAILED_LOGINS)"
  fi

  # Per-IP breakdown for the last hour
  echo -e "${DIM}  Top offending IPs (last hour):${RST}"
  local ip_summary
  ip_summary=$(echo "$recent_lines" \
    | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | sort | uniq -c | sort -rn | head -5 2>/dev/null || true)

  if [[ -z "$ip_summary" ]]; then
    echo "    (none in last hour)"
  else
    echo "$ip_summary" | while read -r count ip; do
      if (( count >= MAX_FAILED_LOGINS )); then
        echo -e "    ${RED}${count}x${RST}  $ip  ${RED}← exceeds threshold${RST}"
        alert "IP $ip had $count failed logins in the last hour"
        log "High-frequency attacker: $ip ($count attempts in 60 min)"
      else
        echo -e "    ${YEL}${count}x${RST}  $ip"
        log "Failed login source: $ip ($count attempts in 60 min)"
      fi
    done
  fi

  # Root login attempts in last hour
  local root_attempts=0
  if [[ -n "$recent_lines" ]]; then
    root_attempts=$(echo "$recent_lines" | grep -c "Failed password for root" 2>/dev/null) || root_attempts=0
  fi
  echo ""
  if (( root_attempts > 0 )); then
    alert "Root login attempts in last hour: $root_attempts"
  else
    ok "No root login attempts in last hour"
  fi

  # Also show all-time total as context
  local alltime=0
  alltime=$(grep -c "Failed password" "$auth_log" 2>/dev/null) || alltime=0
  echo -e "  ${DIM}All-time failed logins in log: $alltime${RST}"
}

# ── 2. Active sessions & logged-in users ──────────────────────────────────────
check_active_sessions() {
  header "2. Active Sessions"

  local sessions
  sessions=$(who 2>/dev/null || true)

  if [[ -z "$sessions" ]]; then
    ok "No active user sessions"
  else
    echo -e "${DIM}  USER         TTY          LOGIN TIME       FROM${RST}"
    echo "$sessions" | while IFS= read -r line; do
      echo "    $line"
      log "Active session: $line"
    done

    # Flag remote sessions
    echo "$sessions" | grep -E '\([0-9]+\.[0-9]+\.' | while IFS= read -r line; do
      alert "Remote session detected: $line"
    done || true
  fi

  echo ""
  echo -e "${DIM}  Last 5 logins:${RST}"
  last -n 5 2>/dev/null | head -5 | while IFS= read -r line; do
    echo "    $line"
  done || true
}

# ── 3. Listening ports & connections ──────────────────────────────────────────
check_network() {
  header "3. Network — Listening Ports & Connections"

  echo -e "${DIM}  Listening ports:${RST}"
  if command -v ss &>/dev/null; then
    ss -tlnp 2>/dev/null | tail -n +2 | while IFS= read -r line; do
      echo "    $line"
    done
  else
    netstat -tlnp 2>/dev/null | tail -n +3 | while IFS= read -r line; do
      echo "    $line"
    done
  fi

  # Check for known suspicious ports
  for port in $SUSPICIOUS_PORTS; do
    if ss -tlnp 2>/dev/null | grep -q ":${port} " || \
       ss -tlnp 2>/dev/null | grep -q ":${port}$"; then
      alert "Suspicious port $port is OPEN and listening!"
      log "Suspicious port detected: $port"
    fi
  done

  # Total established connections
  local conn_count=0
  if command -v ss &>/dev/null; then
    conn_count=$(ss -tnp state established 2>/dev/null | tail -n +2 | wc -l) || conn_count=0
  else
    conn_count=$(netstat -tnp 2>/dev/null | grep -c ESTABLISHED) || conn_count=0
  fi

  if (( conn_count > MAX_CONNECTIONS )); then
    alert "High number of established connections: $conn_count (threshold: $MAX_CONNECTIONS)"
  else
    ok "Established connections: $conn_count"
  fi
}

# ── 4. Running processes — spot unusual activity ──────────────────────────────
check_processes() {
  header "4. Suspicious Processes"

  # Common attack/pentest tool process names
  local bad_procs="nc ncat netcat nmap masscan hydra john hashcat medusa \
                   tcpdump msfconsole msfvenom sqlmap socat xmrig minerd \
                   cryptominer ptrace strace"

  local found=0
  for proc in $bad_procs; do
    if pgrep -x "$proc" &>/dev/null; then
      alert "Suspicious process running: $proc (PID: $(pgrep -x "$proc" | tr '\n' ' '))"
      found=1
    fi
  done
  (( found == 0 )) && ok "No known suspicious processes found"

  # Processes launched from /tmp or /dev/shm (common malware staging areas)
  echo ""
  echo -e "${DIM}  Checking for processes launched from /tmp or /dev/shm:${RST}"
  local tmp_procs
  tmp_procs=$(ls -la /proc/*/exe 2>/dev/null | grep -E '/tmp|/dev/shm' || true)
  if [[ -n "$tmp_procs" ]]; then
    alert "Process(es) running from /tmp or /dev/shm — possible malware!"
    echo "$tmp_procs" | while IFS= read -r line; do
      echo -e "    ${RED}$line${RST}"
      log "Tmp-launched process: $line"
    done
  else
    ok "No processes running from /tmp or /dev/shm"
  fi

  # Top 5 CPU consumers (useful for spotting cryptominers)
  echo ""
  echo -e "${DIM}  Top 5 processes by CPU:${RST}"
  ps aux --sort=-%cpu 2>/dev/null | awk 'NR==1 || NR<=6 {printf "    %-10s %-6s %-5s %s\n", $1, $2, $3, $11}' || true
}

# ── 5. SUID / SGID file check ─────────────────────────────────────────────────
check_suid() {
  header "5. SUID / SGID Files"
  info "Scanning filesystem for SUID/SGID files (may take a moment)…"

  local suid_list
  suid_list=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null || true)

  local count
  count=$(echo "$suid_list" | grep -c . || true)
  echo -e "${DIM}  Found $count SUID/SGID files total${RST}"

  # Flag anything in suspicious locations
  echo "$suid_list" | grep -E '^/tmp|^/var/tmp|^/home|^/dev/shm' | while IFS= read -r f; do
    alert "Unexpected SUID/SGID file in suspicious location: $f"
    log "Suspicious SUID/SGID: $f"
  done || ok "No SUID/SGID files found in suspicious locations"
}

# ── 6. File integrity check ───────────────────────────────────────────────────
create_baseline() {
  header "Creating File Integrity Baseline"
  info "Hashing files in: $WATCH_DIRS"
  info "This may take several minutes…"

  # shellcheck disable=SC2086
  find $WATCH_DIRS -type f 2>/dev/null \
    | sort \
    | xargs md5sum 2>/dev/null > "$BASELINE_FILE"

  local count
  count=$(wc -l < "$BASELINE_FILE")
  ok "Baseline created: $count files hashed → $BASELINE_FILE"
  log "Baseline created with $count files"
}

check_integrity() {
  header "6. File Integrity Check"

  if [[ ! -f "$BASELINE_FILE" ]]; then
    warn "No baseline found. Run:  sudo bash ids_monitor.sh --baseline"
    return
  fi

  info "Comparing current state against baseline…"
  local tmp_current="/tmp/ids_current_$$.md5"

  awk '{print $2}' "$BASELINE_FILE" \
    | xargs md5sum 2>/dev/null > "$tmp_current" || true

  local changes
  changes=$(diff "$BASELINE_FILE" "$tmp_current" 2>/dev/null | grep '^[<>]' || true)

  if [[ -z "$changes" ]]; then
    ok "No file changes detected — integrity verified"
  else
    local changed_count
    changed_count=$(echo "$changes" | wc -l)
    alert "File integrity violations: $changed_count change(s) detected"
    echo "$changes" | head -30 | while IFS= read -r line; do
      echo -e "    ${RED}$line${RST}"
      log "Integrity change: $line"
    done
    (( changed_count > 30 )) && echo -e "    ${DIM}… and $((changed_count - 30)) more. See $LOG_FILE${RST}"
  fi

  rm -f "$tmp_current"
}

# ── 7. Cron jobs ──────────────────────────────────────────────────────────────
check_cron() {
  header "7. Cron Jobs"

  echo -e "${DIM}  System cron directories:${RST}"
  for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$dir" ]] && ls "$dir" 2>/dev/null | while IFS= read -r f; do
      echo "    $dir/$f"
    done
  done

  echo ""
  echo -e "${DIM}  User crontabs:${RST}"
  if [[ -d /var/spool/cron/crontabs ]]; then
    ls /var/spool/cron/crontabs/ 2>/dev/null | while IFS= read -r user; do
      echo -e "    ${YEL}$user${RST}:"
      grep -v '^#\|^$' "/var/spool/cron/crontabs/$user" 2>/dev/null | while IFS= read -r line; do
        echo "      $line"
        # Flag entries that look like download-and-execute patterns
        echo "$line" | grep -qiE 'curl|wget|bash -i|/tmp|base64|python.*socket|nc -e' && \
          alert "Suspicious cron entry for user '$user': $line"
      done || true
    done || true
  else
    echo "    (no user crontabs found)"
  fi

  ok "Cron check complete"
}

# ── 8. System summary ─────────────────────────────────────────────────────────
system_summary() {
  header "System Info"
  echo -e "  ${DIM}Hostname   :${RST} $(hostname)"
  echo -e "  ${DIM}Kernel     :${RST} $(uname -r)"
  echo -e "  ${DIM}Uptime     :${RST} $(uptime -p 2>/dev/null || uptime)"
  echo -e "  ${DIM}Scan time  :${RST} $(ts)"
  echo -e "  ${DIM}Log file   :${RST} $LOG_FILE"
  echo -e "  ${DIM}Alert log  :${RST} $ALERT_FILE"
}

# ── 8. Privilege escalation ───────────────────────────────────────────────────
check_privilege_escalation() {
  header "8. Privilege Escalation"

  # ── a) Users with UID 0 (should only ever be root) ──────────────────────
  echo -e "${DIM}  Accounts with UID 0:${RST}"
  local uid0
  uid0=$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null || true)
  local uid0_count=0
  uid0_count=$(echo "$uid0" | grep -c . || true)
  if (( uid0_count > 1 )); then
    alert "Multiple accounts with UID 0 detected: $uid0"
  else
    ok "Only root has UID 0"
  fi
  echo "$uid0" | while IFS= read -r u; do echo "    $u"; done

  # ── b) Users in sudo / wheel group ──────────────────────────────────────
  echo ""
  echo -e "${DIM}  Members of sudo/wheel group:${RST}"
  for grp in sudo wheel admin; do
    local members
    members=$(getent group "$grp" 2>/dev/null | cut -d: -f4 || true)
    [[ -n "$members" ]] && echo "    $grp: $members" && log "Sudo group '$grp' members: $members"
  done || true

  # ── c) /etc/sudoers — flag NOPASSWD entries ──────────────────────────────
  echo ""
  echo -e "${DIM}  Sudoers NOPASSWD entries (high risk):${RST}"
  local nopasswd
  nopasswd=$(grep -E 'NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true)
  if [[ -n "$nopasswd" ]]; then
    alert "NOPASSWD sudoers entries found — passwordless root access possible!"
    echo "$nopasswd" | while IFS= read -r line; do
      echo -e "    ${RED}$line${RST}"
      log "NOPASSWD sudoers: $line"
    done
  else
    ok "No NOPASSWD sudoers entries found"
  fi

  # ── d) Recently modified /etc/passwd or /etc/sudoers ────────────────────
  echo ""
  echo -e "${DIM}  Checking age of sensitive auth files:${RST}"
  for f in /etc/passwd /etc/shadow /etc/sudoers /etc/group; do
    [[ ! -f "$f" ]] && continue
    local age_min
    age_min=$(( ( $(date +%s) - $(stat -c %Y "$f" 2>/dev/null || echo 0) ) / 60 ))
    if (( age_min < 60 )); then
      alert "$f was modified $age_min minute(s) ago — possible tampering!"
      log "Recent modification: $f ($age_min min ago)"
    else
      ok "$f last modified ${age_min} min ago"
    fi
  done

  # ── e) Recent sudo usage (last hour) ────────────────────────────────────
  echo ""
  echo -e "${DIM}  Recent sudo commands (last hour):${RST}"
  local auth_log=""
  for f in /var/log/auth.log /var/log/secure; do
    [[ -f "$f" ]] && auth_log="$f" && break
  done
  if [[ -n "$auth_log" ]]; then
    local cutoff=$(( $(date +%s) - 3600 ))
    local current_year
    current_year=$(date +%Y)
    awk -v cutoff="$cutoff" -v year="$current_year" '
      /sudo.*COMMAND/ {
        ts = year " " $1 " " $2 " " $3
        cmd = "date -d \"" ts "\" +%s 2>/dev/null"
        cmd | getline epoch
        close(cmd)
        if (epoch != "" && epoch+0 >= cutoff+0) print "    " $0
      }
    ' "$auth_log" 2>/dev/null | head -20 || true
  else
    echo "    (no auth log available)"
  fi
}

# ── 9. Outbound connections ────────────────────────────────────────────────────
check_outbound() {
  header "9. Outbound Connections"

  # Known-good internal ranges — adjust to match your network
  local whitelist="127\. 10\. 192\.168\. 172\.(1[6-9]|2[0-9]|3[01])\."

  echo -e "${DIM}  Established outbound connections:${RST}"
  echo -e "${DIM}  (flagging non-RFC1918 / non-localhost destinations)${RST}"
  echo ""

  local connections
  if command -v ss &>/dev/null; then
    connections=$(ss -tnp state established 2>/dev/null | tail -n +2 || true)
  else
    connections=$(netstat -tnp 2>/dev/null | grep ESTABLISHED || true)
  fi

  if [[ -z "$connections" ]]; then
    ok "No established outbound connections"
    return
  fi

  local flagged=0
  echo "$connections" | while IFS= read -r line; do
    # Extract remote IP (works for both ss and netstat output)
    local remote_ip
    remote_ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1 || true)
    [[ -z "$remote_ip" ]] && continue

    if echo "$remote_ip" | grep -qE "$whitelist"; then
      echo -e "    ${DIM}$line${RST}"
    else
      echo -e "    ${YEL}$line${RST}"
      alert "Unexpected outbound connection to public IP: $remote_ip"
      log "Outbound: $remote_ip — $line"
      flagged=1
    fi
  done

  # Reverse DNS — full scan only (skipped in fast mode to avoid DNS latency)
  if [[ "$FULL_SCAN" == "1" ]]; then
    echo ""
    echo -e "${DIM}  Reverse DNS for external IPs:${RST}"
    if command -v ss &>/dev/null; then
      ss -tnp state established 2>/dev/null | tail -n +2
    else
      netstat -tnp 2>/dev/null | grep ESTABLISHED
    fi | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
       | grep -vE "$whitelist" \
       | sort -u \
       | while read -r ip; do
           local rdns
           rdns=$(host "$ip" 2>/dev/null | awk '/domain name pointer/ {print $NF}' || echo "no rDNS")
           echo -e "    $ip  →  ${DIM}$rdns${RST}"
         done || true
  fi
}

# ── 10. Log tampering detection ───────────────────────────────────────────────
check_log_tampering() {
  header "10. Log Tampering Detection"

  local watched_logs="/var/log/auth.log /var/log/syslog /var/log/kern.log \
                      /var/log/messages /var/log/secure /var/log/wtmp /var/log/btmp"

  for f in $watched_logs; do
    [[ ! -f "$f" ]] && continue

    local size
    size=$(stat -c %s "$f" 2>/dev/null || echo 0)
    local age_min
    age_min=$(( ( $(date +%s) - $(stat -c %Y "$f" 2>/dev/null || echo 0) ) / 60 ))

    # Flag zero-byte log files — classic sign of log wiping
    if (( size == 0 )); then
      alert "Log file is EMPTY (possible wipe): $f"
      log "Empty log file detected: $f"
    else
      ok "$f  —  size: ${size} bytes,  last modified: ${age_min} min ago"
    fi

    # Flag if modified in last 5 minutes outside of normal append behaviour
    # (i.e. inode change time much newer than mtime — suggests truncation/replacement)
    local mtime ctime
    mtime=$(stat -c %Y "$f" 2>/dev/null || echo 0)
    ctime=$(stat -c %Z "$f" 2>/dev/null || echo 0)
    local delta=$(( ctime - mtime ))
    if (( delta < 0 )); then delta=$(( -delta )); fi
    if (( delta > 5 && age_min < 10 )); then
      warn "inode/mtime mismatch on $f — possible truncation or replacement (delta: ${delta}s)"
      log "Mtime/ctime mismatch: $f (delta ${delta}s)"
    fi
  done

  # Check if last login records look suspiciously short
  echo ""
  echo -e "${DIM}  Last login record count (wtmp):${RST}"
  local wtmp_count=0
  wtmp_count=$(last 2>/dev/null | grep -vc "^$\|begins" || true)
  if (( wtmp_count < 3 )); then
    warn "Very few records in wtmp ($wtmp_count) — log may have been cleared"
    log "Low wtmp record count: $wtmp_count"
  else
    ok "wtmp contains $wtmp_count login records"
  fi

  # Check for gaps in syslog (missing hours indicate possible deletion)
  echo ""
  echo -e "${DIM}  Checking for time gaps in syslog (>2 hour gaps flagged):${RST}"
  local syslog=""
  for f in /var/log/syslog /var/log/messages; do
    [[ -f "$f" ]] && syslog="$f" && break
  done
  if [[ -n "$syslog" ]]; then
    local current_year
    current_year=$(date +%Y)
    awk -v year="$current_year" '
      NF>=3 {
        ts = year " " $1 " " $2 " " $3
        cmd = "date -d \"" ts "\" +%s 2>/dev/null"
        cmd | getline epoch
        close(cmd)
        if (epoch+0 > 0) {
          if (prev > 0 && (epoch - prev) > 7200) {
            printf "    GAP: %d minutes between entries around %s %s %s\n", \
              (epoch-prev)/60, $1, $2, $3
          }
          prev = epoch
        }
      }
    ' "$syslog" 2>/dev/null | head -5 || true
    ok "Syslog gap check complete"
  else
    warn "No syslog/messages file found"
  fi
}

# ── 11. Kernel module check ───────────────────────────────────────────────────
check_kernel_modules() {
  header "11. Kernel Modules"

  # ── a) All loaded modules ────────────────────────────────────────────────
  local total_mods
  total_mods=$(lsmod 2>/dev/null | tail -n +2 | wc -l || echo 0)
  info "Total loaded modules: $total_mods"

  # ── b) Unsigned / out-of-tree modules ───────────────────────────────────
  echo ""
  echo -e "${DIM}  Checking for unsigned or out-of-tree modules:${RST}"
  local unsigned=0
  if [[ -d /sys/module ]]; then
    for mod_dir in /sys/module/*/; do
      local mod
      mod=$(basename "$mod_dir")
      local taint_file="$mod_dir/taint"
      if [[ -f "$taint_file" ]]; then
        local taint
        taint=$(cat "$taint_file" 2>/dev/null || true)
        # O = out-of-tree, E = unsigned, P = proprietary
        if echo "$taint" | grep -qE '[OE]'; then
          echo -e "    ${YEL}$mod${RST}  taint: $taint"
          log "Out-of-tree/unsigned module: $mod (taint: $taint)"
          unsigned=$(( unsigned + 1 ))
        fi
      fi
    done
  fi
  (( unsigned == 0 )) && ok "No unsigned or out-of-tree modules detected" \
                       || warn "$unsigned unsigned/out-of-tree module(s) found — review above"

  # ── c) Hidden modules (modules visible in /proc/modules but not lsmod) ──
  echo ""
  echo -e "${DIM}  Cross-checking /proc/modules vs lsmod (rootkit indicator):${RST}"
  local proc_mods lsmod_mods hidden=0
  proc_mods=$(awk '{print $1}' /proc/modules 2>/dev/null | sort || true)
  lsmod_mods=$(lsmod 2>/dev/null | tail -n +2 | awk '{print $1}' | sort || true)
  local diff_result
  diff_result=$(diff <(echo "$proc_mods") <(echo "$lsmod_mods") 2>/dev/null | grep '^[<>]' || true)
  if [[ -n "$diff_result" ]]; then
    alert "Module discrepancy between /proc/modules and lsmod — possible rootkit!"
    echo "$diff_result" | while IFS= read -r line; do
      echo -e "    ${RED}$line${RST}"
      log "Module discrepancy: $line"
    done
    hidden=1
  fi
  (( hidden == 0 )) && ok "/proc/modules and lsmod are consistent"

  # ── d) Recently loaded modules (last hour) ───────────────────────────────
  echo ""
  echo -e "${DIM}  Recently loaded modules (kernel ring buffer):${RST}"
  dmesg 2>/dev/null \
    | grep -iE 'module|insmod|modprobe' \
    | tail -10 \
    | while IFS= read -r line; do
        echo "    $line"
      done || true
}

# ── 12. Open files & deleted-but-running binaries ─────────────────────────────
check_open_files() {
  header "12. Open Files & Deleted Binaries"

  if ! command -v lsof &>/dev/null; then
    warn "lsof not installed — skipping. Install with: apt install lsof"
    return
  fi

  # ── a) Deleted executables still running (classic rootkit / malware sign) ─
  echo -e "${DIM}  Processes running from deleted binaries:${RST}"
  local deleted
  deleted=$(lsof +L1 2>/dev/null | grep -E 'REG.*deleted' || true)
  if [[ -n "$deleted" ]]; then
    alert "Deleted-but-running binaries detected — possible in-memory malware!"
    echo "$deleted" | head -20 | while IFS= read -r line; do
      echo -e "    ${RED}$line${RST}"
      log "Deleted binary running: $line"
    done
  else
    ok "No deleted-but-still-running executables found"
  fi

  # ── b) Files open in /tmp or /dev/shm ────────────────────────────────────
  echo ""
  echo -e "${DIM}  Files open in /tmp or /dev/shm:${RST}"
  local tmp_files
  tmp_files=$(lsof 2>/dev/null | grep -E '^[^ ]+ +[0-9]+ .*(/tmp|/dev/shm)' || true)
  if [[ -n "$tmp_files" ]]; then
    echo "$tmp_files" | head -15 | while IFS= read -r line; do
      echo -e "    ${YEL}$line${RST}"
      log "File open in tmp/shm: $line"
    done
    alert "Files open in /tmp or /dev/shm — review above"
  else
    ok "No suspicious files open in /tmp or /dev/shm"
  fi

  # ── c) Network sockets owned by unexpected processes ─────────────────────
  echo ""
  echo -e "${DIM}  Processes with open network sockets (non-standard):${RST}"
  lsof -i 2>/dev/null \
    | grep -vE 'sshd|systemd|chronyd|ntpd|dhclient|NetworkManager|COMMAND' \
    | head -15 \
    | while IFS= read -r line; do
        echo "    $line"
        log "Open socket: $line"
      done || true
}

# ── 13. Data exfiltration indicators ──────────────────────────────────────────
check_data_exfil() {
  header "13. Data Exfiltration Indicators"

  # ── a) Large outbound transfers via active connections ───────────────────
  echo -e "${DIM}  High-volume network connections (sent bytes, TCP):${RST}"
  if command -v ss &>/dev/null; then
    # ss with -i shows internal TCP info including bytes sent
    ss -tinp 2>/dev/null \
      | awk '
          /bytes_sent/ {
            match($0, /bytes_sent:([0-9]+)/, a)
            if (a[1]+0 > 10485760) {   # > 10 MB
              print "    [HIGH TX]  " prev "  sent=" a[1]/1048576 " MB"
            }
          }
          { prev = $0 }
        ' | head -10 || true
  fi
  ok "High-volume connection check complete"

  # ── b) Abnormally large files recently created in home dirs / tmp ────────
  echo ""
  echo -e "${DIM}  Large files (>50MB) created in last 24h in /home /tmp /var/tmp:${RST}"
  local large_files
  large_files=$(find /home /tmp /var/tmp -xdev -type f -size +50M -mtime -1 2>/dev/null || true)
  if [[ -n "$large_files" ]]; then
    alert "Large recently-created files found — possible data staging!"
    echo "$large_files" | while IFS= read -r f; do
      local sz
      sz=$(du -sh "$f" 2>/dev/null | cut -f1 || echo "?")
      echo -e "    ${RED}$sz  $f${RST}"
      log "Large recent file: $f ($sz)"
    done
  else
    ok "No large recently-created files in home/tmp directories"
  fi

  # ── c) Compressed archives recently created (zip, tar, gz, 7z) ──────────
  echo ""
  echo -e "${DIM}  Archive files created in last 24h (/home /tmp /var/tmp):${RST}"
  local archives
  archives=$(find /home /tmp /var/tmp -xdev -type f \
    \( -name "*.zip" -o -name "*.tar" -o -name "*.tar.gz" \
       -o -name "*.tgz" -o -name "*.7z" -o -name "*.rar" \) \
    -mtime -1 2>/dev/null || true)
  if [[ -n "$archives" ]]; then
    warn "Recent archives found — verify these are expected:"
    echo "$archives" | while IFS= read -r f; do
      echo -e "    ${YEL}$f${RST}"
      log "Recent archive: $f"
    done
  else
    ok "No unexpected archive files found"
  fi

  # ── d) Base64 / encoded data in running processes (encode-and-exfil) ─────
  echo ""
  echo -e "${DIM}  Checking running process command lines for base64/encoded payloads:${RST}"
  local enc_procs
  enc_procs=$(ps aux 2>/dev/null \
    | grep -E 'base64|xxd|python.*b64|perl.*encode|openssl enc' \
    | grep -v grep || true)
  if [[ -n "$enc_procs" ]]; then
    alert "Processes with encoding utilities running — possible data exfiltration!"
    echo "$enc_procs" | while IFS= read -r line; do
      echo -e "    ${RED}$line${RST}"
      log "Encoding process: $line"
    done
  else
    ok "No encoding-related process command lines detected"
  fi

  # ── e) Unusual outbound ports (non-80/443/22) with high data ─────────────
  echo ""
  echo -e "${DIM}  Outbound connections on non-standard ports:${RST}"
  local nonstandard
  if command -v ss &>/dev/null; then
    nonstandard=$(ss -tnp state established 2>/dev/null \
      | awk 'NR>1 {print $5}' \
      | grep -oE ':([0-9]+)$' \
      | tr -d ':' \
      | grep -vE '^(22|80|443|53|123|3306|5432)$' \
      | sort | uniq -c | sort -rn || true)
  fi
  if [[ -n "$nonstandard" ]]; then
    warn "Connections on non-standard ports:"
    echo "$nonstandard" | while read -r count port; do
      echo -e "    ${YEL}${count}x${RST}  port $port"
      (( count > 5 )) && alert "High connection count on unusual port $port ($count connections)"
    done
  else
    ok "No unusual outbound ports detected"
  fi
}

# ── Alert summary ─────────────────────────────────────────────────────────────
alert_summary() {
  header "Scan Complete — Alert Summary"
  local count=0
  count=$(grep "\[ALERT\]" "$ALERT_FILE" 2>/dev/null | grep "$(date '+%Y-%m-%d')" | wc -l) || count=0

  if (( count == 0 )); then
    echo -e "  ${GRN}✔  No alerts generated in this scan.${RST}"
  else
    echo -e "  ${RED}✘  $count alert(s) this scan:${RST}"
    grep "\[ALERT\]" "$ALERT_FILE" | grep "$(date '+%Y-%m-%d')" | while IFS= read -r line; do
      echo -e "    ${RED}▶${RST} $line"
    done
  fi

  echo ""
  echo -e "  Full log   : ${DIM}$LOG_FILE${RST}"
  echo -e "  Alert log  : ${DIM}$ALERT_FILE${RST}"
  echo ""
}

# ── Fast scan (low-overhead checks only) ─────────────────────────────────────
run_fast_scan() {
  echo ""
  echo -e "${WHT}╔══════════════════════════════════════════════════════════╗${RST}"
  echo -e "${WHT}║  IDS Monitor [FAST] — $(ts)        ║${RST}"
  echo -e "${WHT}╚══════════════════════════════════════════════════════════╝${RST}"
  log "=== Fast scan started ==="

  system_summary
  check_failed_logins        # auth log grep — fast
  check_active_sessions      # who + last — fast
  check_network              # ss/netstat — fast
  check_processes            # pgrep + ps — fast
  check_privilege_escalation # passwd/sudoers checks — fast
  check_outbound             # ss + host lookup — fast
  alert_summary

  log "=== Fast scan complete ==="
}

# ── Full scan (all 13 modules including slow filesystem checks) ───────────────
run_full_scan() {
  echo ""
  echo -e "${WHT}╔══════════════════════════════════════════════════════════╗${RST}"
  echo -e "${WHT}║  IDS Monitor [FULL] — $(ts)        ║${RST}"
  echo -e "${WHT}╚══════════════════════════════════════════════════════════╝${RST}"
  log "=== Full scan started ==="

  system_summary
  check_failed_logins
  check_active_sessions
  check_network
  check_processes
  check_suid              # filesystem walk — slow
  check_integrity         # md5 comparison — slow
  check_cron
  check_privilege_escalation
  check_outbound
  check_log_tampering
  check_kernel_modules
  check_open_files        # lsof — moderate
  check_data_exfil
  alert_summary

  log "=== Full scan complete ==="
}

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
  echo ""
  echo -e "${WHT}ids_monitor.sh${RST} — Linux Intrusion Detection Monitor"
  echo ""
  echo -e "  ${WHT}Scan modes:${RST}"
  echo "  sudo bash ids_monitor.sh              Fast scan (7 checks, seconds to run)"
  echo "  sudo bash ids_monitor.sh --full       Full scan (all 13 checks)"
  echo "  sudo bash ids_monitor.sh --baseline   Create/refresh file integrity baseline"
  echo ""
  echo -e "  ${WHT}Continuous modes:${RST}"
  echo "  sudo bash ids_monitor.sh --watch      Fast scan loop (default: every 60s)"
  echo "  sudo bash ids_monitor.sh --watch --full          Full scan loop"
  echo "  sudo bash ids_monitor.sh --watch --interval 300  Custom interval (seconds)"
  echo "  sudo bash ids_monitor.sh --monitor    tmux dashboard (3 panes, fast scan)"
  echo "  sudo bash ids_monitor.sh --monitor --full        tmux dashboard, full scan"
  echo ""
  echo -e "  ${WHT}Utilities:${RST}"
  echo "  sudo bash ids_monitor.sh --live-alerts  Tail alerts file in colour"
  echo "  sudo bash ids_monitor.sh --help         Show this help"
  echo ""
  echo -e "  ${WHT}Log files:${RST}"
  echo "  Full event log : $LOG_FILE"
  echo "  Alerts only    : $ALERT_FILE  (new alerts only, no duplicates)"
  echo ""
}

# ── Live alert tail with colour ───────────────────────────────────────────────
live_alerts() {
  echo -e "${WHT}  Tailing alerts: $ALERT_FILE${RST}"
  echo -e "${DIM}  (only new unique alerts are written here — Ctrl+C to stop)${RST}"
  echo ""
  tail -f "$ALERT_FILE" 2>/dev/null | while IFS= read -r line; do
    echo -e "${RED}${line}${RST}"
  done
}

# ── tmux monitor dashboard ────────────────────────────────────────────────────
# Layout:
#  ┌─────────────────────────────────┐
#  │  pane 0 — continuous scan       │  (top 70%)
#  ├──────────────────┬──────────────┤
#  │  pane 1          │  pane 2      │
#  │  live alert tail │  full log    │  (bottom 30%)
#  └──────────────────┴──────────────┘
launch_monitor() {
  if ! command -v tmux &>/dev/null; then
    echo -e "${RED}tmux is not installed.${RST}"
    echo "Install it with:  apt install tmux   or   yum install tmux"
    echo ""
    echo "Falling back to plain --watch mode…"
    watch_mode
    return
  fi

  local session="ids_monitor"
  local script
  script=$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || echo "$0")

  # Build the watch command, forwarding --full and --interval if set
  local watch_cmd="sudo bash \"$script\" --watch"
  [[ "$FULL_SCAN" == "1" ]] && watch_cmd="$watch_cmd --full"
  watch_cmd="$watch_cmd --interval $SCAN_INTERVAL"

  # Kill any stale session
  tmux kill-session -t "$session" 2>/dev/null || true

  # Enable pane border titles if supported
  local tmux_ver
  tmux_ver=$(tmux -V 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo "0")
  local show_titles=0
  (( $(echo "$tmux_ver >= 2.6" | awk '{print ($1 >= $3)}') )) && show_titles=1

  # ── Create session with the scan pane (pane 0) ──────────────────────────
  tmux new-session -d -s "$session" \
    -x "$(tput cols 2>/dev/null || echo 220)" \
    -y "$(tput lines 2>/dev/null || echo 50)" \
    "$watch_cmd"

  # ── Split bottom 30% horizontally → becomes pane 1 ──────────────────────
  tmux split-window -v -t "${session}:0.0" -p 30 \
    "tail -f \"$LOG_FILE\" 2>/dev/null || { echo 'Waiting for log…'; sleep 2; tail -f \"$LOG_FILE\"; }"

  # ── Split pane 1 vertically → left=pane 1 (alerts), right=pane 2 (log) ──
  # After the vertical split, pane 1 is on the left — send alerts there
  # and the right half (new pane 2) gets the full log
  tmux split-window -h -t "${session}:0.1" \
    "sudo bash \"$script\" --live-alerts"

  # Swap: we want alerts on the LEFT and full log on the RIGHT
  # After split-window -h on pane 1, pane 1=left(log), pane 2=right(alerts)
  # swap them so alerts are on the left
  tmux swap-pane -s "${session}:0.1" -t "${session}:0.2" 2>/dev/null || true

  # ── Optionally label panes ───────────────────────────────────────────────
  if (( show_titles == 1 )); then
    tmux set-option -t "$session" pane-border-status top 2>/dev/null || true
    tmux set-option -t "$session" pane-border-format " #{pane_title} " 2>/dev/null || true
    tmux select-pane -t "${session}:0.0" -T "  Continuous Scan " 2>/dev/null || true
    tmux select-pane -t "${session}:0.1" -T "  Alerts (new only) " 2>/dev/null || true
    tmux select-pane -t "${session}:0.2" -T "  Full Event Log " 2>/dev/null || true
  fi

  # Focus the scan pane
  tmux select-pane -t "${session}:0.0"

  echo -e "${GRN}Dashboard launched → tmux session '${session}'${RST}"
  echo -e "  Ctrl+B then D   detach (keeps running)"
  echo -e "  Re-attach with: tmux attach -t $session"
  echo ""
  sleep 1
  tmux attach-session -t "$session"
}

# ── Continuous watch mode ─────────────────────────────────────────────────────
watch_mode() {
  local mode_label="FAST"
  [[ "$FULL_SCAN" == "1" ]] && mode_label="FULL"
  info "Watch mode [$mode_label] — every ${SCAN_INTERVAL}s. Ctrl+C to stop."
  info "Full log  : $LOG_FILE"
  info "Alert log : $ALERT_FILE"
  echo ""
  while true; do
    if [[ "$FULL_SCAN" == "1" ]]; then
      run_full_scan
    else
      run_fast_scan
    fi
    echo -e "${DIM}  Next scan in ${SCAN_INTERVAL}s — alerts: $ALERT_FILE${RST}"
    sleep "$SCAN_INTERVAL"
  done
}

# ── Entry point ───────────────────────────────────────────────────────────────
require_root
init

# ── Parse all arguments ───────────────────────────────────────────────────────
# Flags: --full, --interval N  can appear anywhere alongside the mode word
FULL_SCAN=0
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --full)
      FULL_SCAN=1
      shift
      ;;
    --interval)
      shift
      if [[ "${1:-}" =~ ^[0-9]+$ ]] && (( $1 >= 5 )); then
        SCAN_INTERVAL="$1"
        shift
      else
        echo -e "${RED}--interval requires a whole number >= 5 (seconds)${RST}"
        exit 1
      fi
      ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

MODE="${ARGS[0]:-}"

case "$MODE" in
  --baseline)
    create_baseline
    ;;
  --monitor)
    launch_monitor
    ;;
  --watch)
    watch_mode
    ;;
  --live-alerts)
    live_alerts
    ;;
  --help|-h)
    usage
    ;;
  "")
    # No mode — default to fast scan, unless --full was passed
    if [[ "$FULL_SCAN" == "1" ]]; then
      run_full_scan
    else
      run_fast_scan
    fi
    ;;
  *)
    echo -e "${RED}Unknown option: $MODE${RST}"
    usage
    exit 1
    ;;
esac


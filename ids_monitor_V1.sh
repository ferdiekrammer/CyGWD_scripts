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
alert() { local m="[ALERT] $*"; echo "[$(ts)] $m" | tee -a "$LOG_FILE" "$ALERT_FILE" >/dev/null
          echo -e "${RED}[ALERT]${RST} $*"; }
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
  header "1. Failed Login Attempts"

  local auth_log=""
  for f in /var/log/auth.log /var/log/secure; do
    [[ -f "$f" ]] && auth_log="$f" && break
  done

  if [[ -z "$auth_log" ]]; then
    warn "No auth log found (/var/log/auth.log or /var/log/secure)"
    return
  fi

  local total=0
  total=$(grep -c "Failed password" "$auth_log" 2>/dev/null) || total=0

  if (( total > MAX_FAILED_LOGINS )); then
    alert "Total failed SSH password attempts: $total (threshold: $MAX_FAILED_LOGINS)"
  else
    ok "Failed login count: $total — within threshold ($MAX_FAILED_LOGINS)"
  fi

  # Top 5 offending IPs
  echo -e "${DIM}  Top offending IPs:${RST}"
  grep "Failed password" "$auth_log" 2>/dev/null \
    | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | sort | uniq -c | sort -rn | head -5 \
    | while read -r count ip; do
        echo -e "    ${YEL}${count}x${RST}  $ip"
        log "Failed login source: $ip ($count attempts)"
      done || true

  # Root login attempts
  local root_attempts=0
  root_attempts=$(grep -c "Failed password for root" "$auth_log" 2>/dev/null) || root_attempts=0
  (( root_attempts > 0 )) \
    && alert "Root login attempts detected: $root_attempts" \
    || ok "No root login attempts found"
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

# ── Run a full scan ───────────────────────────────────────────────────────────
run_scan() {
  echo ""
  echo -e "${WHT}╔══════════════════════════════════════════════════════════╗${RST}"
  echo -e "${WHT}║   IDS Monitor — Scan started $(ts)      ║${RST}"
  echo -e "${WHT}╚══════════════════════════════════════════════════════════╝${RST}"
  log "=== Scan started ==="

  system_summary
  check_failed_logins
  check_active_sessions
  check_network
  check_processes
  check_suid
  check_integrity
  check_cron
  alert_summary

  log "=== Scan complete ==="
}

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
  echo ""
  echo -e "${WHT}ids_monitor.sh${RST} — Linux Intrusion Detection Monitor"
  echo ""
  echo "  sudo bash ids_monitor.sh             Run a full one-time scan"
  echo "  sudo bash ids_monitor.sh --watch     Continuous scan every ${SCAN_INTERVAL}s"
  echo "  sudo bash ids_monitor.sh --baseline  Create/refresh file integrity baseline"
  echo "  sudo bash ids_monitor.sh --help      Show this help"
  echo ""
}

# ── Entry point ───────────────────────────────────────────────────────────────
require_root
init

case "${1:-}" in
  --baseline) create_baseline ;;
  --watch)
    info "Watch mode active — scanning every ${SCAN_INTERVAL}s. Ctrl+C to stop."
    while true; do
      run_scan
      echo -e "${DIM}  Next scan in ${SCAN_INTERVAL}s…${RST}"
      sleep "$SCAN_INTERVAL"
    done
    ;;
  --help|-h) usage ;;
  "") run_scan ;;
  *) echo -e "${RED}Unknown option: $1${RST}"; usage; exit 1 ;;
esac

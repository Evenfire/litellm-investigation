#!/usr/bin/env bash
set -uo pipefail

# ╔══════════════════════════════════════════════════════════════════╗
# ║  litellm-audit.sh                                                ║
# ║  Detect indicators of compromise from the litellm supply chain   ║
# ║  attack (versions 1.82.7 / 1.82.8, March 2026)                   ║
# ║                                                                  ║
# ║  Reference: snyk.io/articles/poisoned-security-scanner-          ║
# ║             backdooring-litellm/                                 ║
# ╚══════════════════════════════════════════════════════════════════╝

# ── Known IOCs ──
MALICIOUS_VERSIONS=("1.82.7" "1.82.8")
PTH_SHA256="71e35aef03099cd1f2d6446734273025a163597de93912df321ef118bf135238"
SYSMON_SHA256="6cf223aea68b0e8031ff68251e30b6017a0513fe152e235c26f248ba1e15c92a"
RSA_KEY_PREFIX="MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvahaZDo8mucujrT15ry+"
EXFIL_DOMAIN="models.litellm.cloud"
C2_DOMAIN="checkmarx.zone"


# ── Defaults ──
OUTPUT_DIR="./litellm-audit-report"
STEPS=()
SKIP_DOCKER=false
PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')"
EXIT_CODE=0

# ── Shared state ──
SITE_PACKAGES_FILE=""
LITELLM_DIRS=()

# ── Output helpers ──
log_clean() { echo "[CLEAN]  $*"; }
log_warn()  { echo "[WARN]   $*"; [[ $EXIT_CODE -lt 1 ]] && EXIT_CODE=1; }
log_crit()  { echo "[CRIT]   $*"; EXIT_CODE=2; }
log_info()  { echo "[INFO]   $*"; }
log_skip()  { echo "[SKIP]   $*"; }

phase_header() {
  echo ""
  echo "════════════════════════════════════════════════════════════"
  echo "  Phase $1"
  echo "════════════════════════════════════════════════════════════"
}

# ── SHA-256 helper (cross-platform) ──
sha256_of() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum &>/dev/null; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "NO_SHA256_TOOL"
  fi
}

# ── Usage ──
usage() {
  cat <<'EOF'
Usage: litellm-audit.sh [OPTIONS]

Scan this machine for indicators of compromise from the litellm
supply chain attack (versions 1.82.7 and 1.82.8, March 2026).

Options:
  -s, --step STEP       Run specific phase(s). Repeatable.
                        Values: 1, 2, 3, 4, 5, 6, all (default: all)
                        1=Discovery, 2=litellm check, 3=IOC artifacts,
                        4=Persistence, 5=Network, 6=History/cache
  -o, --output DIR      Output directory for report (default: ./litellm-audit-report)
  --skip-docker         Skip Docker container/image scanning
  -h, --help            Show this help message

Exit codes:
  0  Clean — no indicators of compromise found
  1  Warning — litellm present but safe version
  2  Compromised — malicious version or IOC artifacts found
EOF
  exit 0
}

# ── Arg parsing ──
require_arg() {
  if [[ $# -lt 2 || "$2" == -* ]]; then
    echo "Error: $1 requires a value" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--step)      require_arg "$1" "${2:-}"; STEPS+=("$2"); shift 2 ;;
    -o|--output)    require_arg "$1" "${2:-}"; OUTPUT_DIR="$2"; shift 2 ;;
    --skip-docker)  SKIP_DOCKER=true; shift ;;
    -h|--help)      usage ;;
    *) echo "Error: unknown option: $1" >&2; usage ;;
  esac
done

[[ ${#STEPS[@]} -eq 0 ]] && STEPS=("all")
mkdir -p "$OUTPUT_DIR"
SITE_PACKAGES_FILE="$OUTPUT_DIR/discovered_site_packages.txt"

should_run() {
  local phase="$1"
  for s in "${STEPS[@]}"; do
    [[ "$s" == "all" || "$s" == "$phase" ]] && return 0
  done
  return 1
}

# ── Version comparison helper ──
is_malicious_version() {
  local ver="$1"
  for mv in "${MALICIOUS_VERSIONS[@]}"; do
    [[ "$ver" == "$mv" ]] && return 0
  done
  return 1
}


# ╔══════════════════════════════════════════════════════════════════╗
# ║  Phase 1 — Discovery                                             ║
# ╚══════════════════════════════════════════════════════════════════╝
run_phase_1() {
  phase_header "1 — Discovery"

  log_info "Platform: $PLATFORM"

  # ── Find Python interpreters ──
  log_info "Searching for Python interpreters..."
  local pythons_file="$OUTPUT_DIR/discovered_pythons.txt"
  > "$pythons_file"

  # which
  for cmd in python python3; do
    local p
    p=$(command -v "$cmd" 2>/dev/null) && echo "$p" >> "$pythons_file"
  done

  # pyenv
  for p in "$HOME"/.pyenv/versions/*/bin/python3; do
    [[ -x "$p" ]] && echo "$p" >> "$pythons_file"
  done

  # asdf
  for p in "$HOME"/.asdf/installs/python/*/bin/python3; do
    [[ -x "$p" ]] && echo "$p" >> "$pythons_file"
  done

  # uv
  for p in "$HOME"/.local/share/uv/python/*/bin/python3.*; do
    [[ -x "$p" ]] && echo "$p" >> "$pythons_file"
  done

  # homebrew (Apple Silicon + Intel)
  for base in /opt/homebrew/opt /usr/local/opt; do
    for p in "$base"/python@*/bin/python3.*; do
      [[ -x "$p" ]] && echo "$p" >> "$pythons_file"
    done
  done

  # conda / anaconda / miniconda
  for base in "$HOME/anaconda3" "$HOME/miniconda3" /opt/homebrew/anaconda3; do
    [[ -x "$base/bin/python3" ]] && echo "$base/bin/python3" >> "$pythons_file"
    for p in "$base"/envs/*/bin/python3; do
      [[ -x "$p" ]] && echo "$p" >> "$pythons_file"
    done
  done

  # system
  for p in /usr/bin/python3 /usr/local/bin/python3; do
    [[ -x "$p" ]] && echo "$p" >> "$pythons_file"
  done

  sort -u -o "$pythons_file" "$pythons_file"
  local py_count
  py_count=$(wc -l < "$pythons_file" | tr -d ' ')
  log_info "Found $py_count Python interpreter(s) — saved to $pythons_file"

  # ── Parallel discovery: host find + Docker scanning run concurrently ──
  # Each writes to its own temp file; merged into SITE_PACKAGES_FILE at the end.

  local host_sp_file="$OUTPUT_DIR/.host_site_packages.tmp"
  local docker_sp_file="$OUTPUT_DIR/.docker_site_packages.tmp"
  > "$host_sp_file"
  > "$docker_sp_file"
  > "$SITE_PACKAGES_FILE"

  # ── Background job 1: Host site-packages ──
  log_info "1a — Searching for host site-packages (background)..."
  (
    find / -xdev -type d -name "site-packages" \
      -not -path "*/OrbStack/*" \
      -not -path "*/docker/*" \
      -not -path "*/containers/storage/*" \
      -not -path "*/overlay2/*" \
      -not -path "*/buildkit/*" \
      2>/dev/null > "$host_sp_file"
  ) &
  local host_find_pid=$!

  # ── Docker scanning (fully static — no code execution inside containers) ──
  # Uses docker create + docker cp only. Never docker exec.
  DOCKER_SCAN_DIR="$OUTPUT_DIR/docker_scan"
  local docker_available=false

  if [[ "$SKIP_DOCKER" == true ]]; then
    log_skip "Docker scanning disabled (--skip-docker)"
  elif ! command -v docker &>/dev/null; then
    log_skip "docker CLI not found — skipping container/image scanning"
  elif ! docker info &>/dev/null 2>&1; then
    log_skip "Docker daemon not reachable — skipping container/image scanning"
  else
    docker_available=true
    mkdir -p "$DOCKER_SCAN_DIR"
  fi

  # Helper: scan a stopped container by ID (no code ever runs inside it)
  # Exports the filesystem listing once, then uses docker cp to extract only what we need.
  # Writes discovered site-packages paths to $docker_sp_file.
  _scan_docker_fs() {
    local cid="$1"
    local label="$2"
    local dest_prefix="$3"

    local listing_file
    listing_file=$(mktemp)
    docker export "$cid" 2>/dev/null | tar -t > "$listing_file" 2>/dev/null || true

    if [[ ! -s "$listing_file" ]]; then
      log_info "  $label: could not list filesystem"
      rm -f "$listing_file"
      return
    fi

    local sp_paths
    sp_paths=$(grep 'site-packages/$' "$listing_file" | sed 's|/$||; s|^|/|') || true

    if [[ -z "$sp_paths" ]]; then
      rm -f "$listing_file"
      return
    fi

    log_info "  $label: found site-packages"
    while IFS= read -r sp; do
      local dest="${dest_prefix}$(echo "$sp" | tr '/' '_')"
      mkdir -p "$dest"

      docker cp "$cid:$sp/litellm" "$dest/litellm" 2>/dev/null || true
      docker cp "$cid:$sp/litellm_init.pth" "$dest/" 2>/dev/null || true

      grep "^${sp#/}/[^/]*\\.pth$" "$listing_file" | while IFS= read -r pth; do
        docker cp "$cid:/$pth" "$dest/" 2>/dev/null || true
      done

      grep "^${sp#/}/litellm-.*\\.dist-info/" "$listing_file" \
        | sed 's|/[^/]*$||' | sort -u | while IFS= read -r di; do
          docker cp "$cid:/$di" "$dest/" 2>/dev/null || true
        done

      echo "$dest" >> "$docker_sp_file"
      log_info "    Extracted: $sp -> $dest"
    done <<< "$sp_paths"

    for ioc_path in "root/.config/sysmon/sysmon.py" "tmp/tpcp.tar.gz" "tmp/session.key" \
                    "tmp/payload.enc" "tmp/session.key.enc" "tmp/.pg_state" "tmp/pglog"; do
      if grep -q "^${ioc_path}$" "$listing_file" 2>/dev/null; then
        local ioc_dest="${dest_prefix}_ioc"
        mkdir -p "$ioc_dest"
        if docker cp "$cid:/$ioc_path" "$ioc_dest/" 2>/dev/null; then
          log_crit "IOC artifact found in $label: /$ioc_path"
        fi
      fi
    done

    rm -f "$listing_file"
  }

  if [[ "$docker_available" == true ]]; then
    # ── Background job 2: Docker scanning (containers + images) ──
    log_info "1b — Scanning Docker containers + images (background)..."
    (
      # Running containers
      local container_ids
      container_ids=$(docker ps -q 2>/dev/null) || true
      if [[ -n "$container_ids" ]]; then
        local c_count
        c_count=$(echo "$container_ids" | wc -l | tr -d ' ')
        log_info "  Found $c_count running container(s)"
        while IFS= read -r cid; do
          local cname
          cname=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||')
          local cid_short="${cid:0:12}"
          _scan_docker_fs "$cid" "container $cname ($cid_short)" "$DOCKER_SCAN_DIR/containers/${cid_short}"
        done <<< "$container_ids"
      fi

      # Local images
      local image_ids
      image_ids=$(docker images -q 2>/dev/null | sort -u) || true
      if [[ -n "$image_ids" ]]; then
        local i_count
        i_count=$(echo "$image_ids" | wc -l | tr -d ' ')
        log_info "  Found $i_count unique image(s)"
        while IFS= read -r iid; do
          local iid_short="${iid:0:12}"
          local iname
          iname=$(docker inspect --format '{{index .RepoTags 0}}' "$iid" 2>/dev/null) || iname="$iid_short"
          local tmp_cid
          tmp_cid=$(docker create --entrypoint /bin/false "$iid" 2>/dev/null) || true
          if [[ -z "$tmp_cid" ]]; then
            log_info "  Image $iname: could not create temp container — skipping"
            continue
          fi
          _scan_docker_fs "$tmp_cid" "image $iname ($iid_short)" "$DOCKER_SCAN_DIR/images/${iid_short}"
          docker rm "$tmp_cid" &>/dev/null
        done <<< "$image_ids"
      fi
    ) &
    local docker_scan_pid=$!
  fi

  # ── Wait for both background jobs ──
  log_info "Waiting for parallel discovery to complete..."

  wait "$host_find_pid" 2>/dev/null || true
  local sp_count
  sp_count=$(wc -l < "$host_sp_file" | tr -d ' ')
  log_info "1a complete — found $sp_count host site-packages directory(s)"

  if [[ "$docker_available" == true ]]; then
    wait "$docker_scan_pid" 2>/dev/null || true
    local docker_sp_count
    docker_sp_count=$(wc -l < "$docker_sp_file" | tr -d ' ')
    log_info "1b complete — extracted $docker_sp_count Docker site-packages directory(s)"
  fi

  # ── Merge results ──
  cat "$host_sp_file" "$docker_sp_file" | sort -u > "$SITE_PACKAGES_FILE"
  rm -f "$host_sp_file" "$docker_sp_file"
  local total_sp
  total_sp=$(wc -l < "$SITE_PACKAGES_FILE" | tr -d ' ')
  log_info "Total: $total_sp site-packages directory(s) — saved to $SITE_PACKAGES_FILE"
}

# ╔══════════════════════════════════════════════════════════════════╗
# ║  Phase 2 — litellm Presence & Version Check                      ║
# ╚══════════════════════════════════════════════════════════════════╝

# Helper: walk up from a path to find a project root
find_project_root() {
  local current="$1"
  while [[ "$current" != "/" ]]; do
    if [[ -f "$current/pyproject.toml" || -f "$current/setup.py" || -f "$current/Pipfile" ]]; then
      echo "$current"
      return
    fi
    if [[ "$(basename "$current")" == ".venv" ]]; then
      echo "$(dirname "$current")"
      return
    fi
    current="$(dirname "$current")"
  done
}

# Helper: flag a litellm version
flag_litellm_version() {
  local ver="$1"
  local location="$2"
  local method="$3"
  if is_malicious_version "$ver"; then
    log_crit "litellm $ver found via $method at $location — COMPROMISED"
  else
    log_warn "litellm $ver found via $method at $location"
  fi
}

run_phase_2() {
  phase_header "2 — litellm Presence & Version Check"

  if [[ ! -f "$SITE_PACKAGES_FILE" || ! -s "$SITE_PACKAGES_FILE" ]]; then
    log_info "No site-packages file found. Run phase 1 first or run all phases."
    return
  fi

  # ── 2a: Filesystem scan ──
  log_info "2a — Filesystem scan across all site-packages..."
  local found_any=false
  while IFS= read -r d; do
    [[ ! -d "$d" ]] && continue
    local found_via=""
    [[ -d "$d/litellm" ]] && found_via="directory"
    ls "$d"/litellm-*.dist-info &>/dev/null && found_via="${found_via:+$found_via + }dist-info"
    ls "$d"/litellm-*.egg-info &>/dev/null && found_via="${found_via:+$found_via + }egg-info"
    [[ -f "$d/litellm.egg-link" ]] && found_via="${found_via:+$found_via + }egg-link"

    if [[ -n "$found_via" ]]; then
      found_any=true
      local ver="unknown"
      # Try version.py
      if [[ -f "$d/litellm/version.py" ]]; then
        ver=$(awk -F'"' '/version\s*=/{print $2; exit}' "$d/litellm/version.py" 2>/dev/null)
        [[ -z "$ver" ]] && ver="unknown"
      fi
      # Try dist-info METADATA
      if [[ "$ver" == "unknown" ]]; then
        local di
        di=$(find "$d" -maxdepth 1 -name "litellm-*.dist-info" -type d 2>/dev/null | head -1)
        if [[ -n "$di" && -f "$di/METADATA" ]]; then
          ver=$(grep '^Version:' "$di/METADATA" | awk '{print $2}')
        fi
      fi
      # Try egg-info PKG-INFO
      if [[ "$ver" == "unknown" ]]; then
        local ei
        ei=$(find "$d" -maxdepth 1 -name "litellm-*.egg-info" -type d 2>/dev/null | head -1)
        if [[ -n "$ei" && -f "$ei/PKG-INFO" ]]; then
          ver=$(grep '^Version:' "$ei/PKG-INFO" | awk '{print $2}')
        fi
      fi
      flag_litellm_version "${ver:-unknown}" "$d" "filesystem ($found_via)"
      LITELLM_DIRS+=("$d")
    fi
  done < "$SITE_PACKAGES_FILE"

  if [[ "$found_any" == false ]]; then
    log_clean "No litellm found via filesystem scan"
  fi

  # ── 2b: Package manager scan ──
  log_info "2b — Package manager scan (poetry, uv, pip, pipenv)..."
  local has_poetry has_uv has_pipenv
  has_poetry=$(command -v poetry 2>/dev/null) || true
  has_uv=$(command -v uv 2>/dev/null) || true
  has_pipenv=$(command -v pipenv 2>/dev/null) || true

  local checked_roots_file
  checked_roots_file=$(mktemp)
  trap "rm -f '$checked_roots_file'" RETURN
  local pm_found=false
  while IFS= read -r d; do
    [[ ! -d "$d" ]] && continue
    local root
    root=$(find_project_root "$d")
    [[ -z "$root" ]] && continue
    grep -qxF "$root" "$checked_roots_file" 2>/dev/null && continue
    echo "$root" >> "$checked_roots_file"

    local ver=""

    # poetry
    if [[ -f "$root/poetry.lock" ]]; then
      if [[ -n "$has_poetry" ]]; then
        ver=$(cd "$root" && poetry show litellm 2>/dev/null | grep -m1 'version' | awk '{print $NF}') || true
        if [[ -n "$ver" ]]; then
          flag_litellm_version "$ver" "$root" "poetry"
          pm_found=true
          continue
        fi
      fi
    fi

    # uv
    if [[ -f "$root/uv.lock" ]]; then
      if [[ -n "$has_uv" ]]; then
        ver=$(cd "$root" && uv pip show litellm 2>/dev/null | grep -m1 'Version' | awk '{print $NF}') || true
        if [[ -n "$ver" ]]; then
          flag_litellm_version "$ver" "$root" "uv"
          pm_found=true
          continue
        fi
      fi
    fi

    # .venv pip
    if [[ -x "$root/.venv/bin/pip" ]]; then
      ver=$("$root/.venv/bin/pip" show litellm 2>/dev/null | grep -m1 'Version' | awk '{print $NF}') || true
      if [[ -n "$ver" ]]; then
        flag_litellm_version "$ver" "$root" ".venv/bin/pip"
        pm_found=true
        continue
      fi
    fi

    # pipenv
    if [[ -f "$root/Pipfile" ]]; then
      if [[ -n "$has_pipenv" ]]; then
        ver=$(cd "$root" && pipenv run pip show litellm 2>/dev/null | grep -m1 'Version' | awk '{print $NF}') || true
        if [[ -n "$ver" ]]; then
          flag_litellm_version "$ver" "$root" "pipenv"
          pm_found=true
          continue
        fi
      fi
    fi
  done < "$SITE_PACKAGES_FILE"

  if [[ "$pm_found" == false ]]; then
    log_clean "No litellm found via package managers"
  fi

  # ── 2c: litellm_init.pth search ──
  # Searches only the already-discovered site-packages paths (from phase 1).
  # Phase 1 already did the full filesystem traversal; no need to repeat it.
  log_info "2c — Searching for litellm_init.pth in discovered site-packages..."
  local pth_found=false
  while IFS= read -r d; do
    [[ ! -d "$d" ]] && continue
    if [[ -f "$d/litellm_init.pth" ]]; then
      pth_found=true
      local hash
      hash=$(sha256_of "$d/litellm_init.pth")
      if [[ "$hash" == "$PTH_SHA256" ]]; then
        log_crit "litellm_init.pth found at $d — SHA-256 MATCHES known malicious payload"
      else
        log_crit "litellm_init.pth found at $d — SHA-256: $hash (does not match known hash, still suspicious)"
      fi
    fi
  done < "$SITE_PACKAGES_FILE"

  if [[ "$pth_found" == false ]]; then
    log_clean "No litellm_init.pth found in any discovered site-packages"
  fi
}

# ╔══════════════════════════════════════════════════════════════════╗
# ║  Phase 3 — IOC File Artifacts                                    ║
# ╚══════════════════════════════════════════════════════════════════╝
run_phase_3() {
  phase_header "3 — IOC File Artifacts"

  # ── Known file artifacts ──
  log_info "Checking for known IOC file artifacts..."

  # sysmon.py backdoor
  local sysmon="$HOME/.config/sysmon/sysmon.py"
  if [[ -f "$sysmon" ]]; then
    local hash
    hash=$(sha256_of "$sysmon")
    if [[ "$hash" == "$SYSMON_SHA256" ]]; then
      log_crit "Backdoor found: $sysmon — SHA-256 MATCHES known malicious payload"
    else
      log_crit "Suspicious file: $sysmon — SHA-256: $hash (different from known hash)"
    fi
  else
    log_clean "No backdoor at $sysmon"
  fi

  # sysmon.service (Linux)
  local sysmon_svc="$HOME/.config/systemd/user/sysmon.service"
  if [[ "$PLATFORM" == "linux" ]]; then
    if [[ -f "$sysmon_svc" ]]; then
      log_crit "Systemd persistence found: $sysmon_svc"
    else
      log_clean "No systemd persistence at $sysmon_svc"
    fi
  fi

  # /tmp artifacts
  local tmp_artifacts=(
    "/tmp/tpcp.tar.gz"
    "/tmp/session.key"
    "/tmp/payload.enc"
    "/tmp/session.key.enc"
    "/tmp/.pg_state"
    "/tmp/pglog"
  )
  for f in "${tmp_artifacts[@]}"; do
    if [[ -f "$f" ]]; then
      log_crit "Exfiltration artifact found: $f (size: $(wc -c < "$f") bytes)"
    else
      log_clean "No artifact at $f"
    fi
  done

  # ── Full .pth scan ──
  log_info "Scanning all .pth files for suspicious patterns..."

  if [[ ! -f "$SITE_PACKAGES_FILE" || ! -s "$SITE_PACKAGES_FILE" ]]; then
    log_info "No site-packages file found. Run phase 1 first or run all phases."
    return
  fi

  local pth_suspicious=0
  local pth_report="$OUTPUT_DIR/pth_scan_report.txt"
  > "$pth_report"

  while IFS= read -r d; do
    [[ ! -d "$d" ]] && continue
    while IFS= read -r pth_file; do
      [[ -z "$pth_file" ]] && continue

      # Check for RSA key prefix (strong signal)
      if grep -qF "$RSA_KEY_PREFIX" "$pth_file" 2>/dev/null; then
        log_crit ".pth file contains known malicious RSA key: $pth_file"
        echo "CRIT: $pth_file (RSA key match)" >> "$pth_report"
        ((pth_suspicious++))
        continue
      fi

      # Check for suspicious patterns
      if grep -qE 'base64|subprocess|exec|eval|compile|__import__|socket|urllib|requests\.get' "$pth_file" 2>/dev/null; then
        log_warn "Suspicious .pth file: $pth_file"
        grep -n 'base64\|subprocess\|exec\|eval\|compile\|__import__\|socket\|urllib\|requests\.get' "$pth_file" | head -3 | sed 's/^/         /'
        echo "SUSPICIOUS: $pth_file" >> "$pth_report"
        grep -n 'base64\|subprocess\|exec\|eval\|compile\|__import__\|socket\|urllib\|requests\.get' "$pth_file" >> "$pth_report"
        ((pth_suspicious++))
      fi
    done < <(find "$d" -maxdepth 1 -name "*.pth" -type f 2>/dev/null)
  done < "$SITE_PACKAGES_FILE"

  log_info ".pth scan complete: $pth_suspicious suspicious"
  log_info "Full .pth report saved to $pth_report"
}

# ╔══════════════════════════════════════════════════════════════════╗
# ║  Phase 4 — Persistence Mechanisms                                ║
# ╚══════════════════════════════════════════════════════════════════╝
run_phase_4() {
  phase_header "4 — Persistence Mechanisms"

  if [[ "$PLATFORM" == "linux" ]]; then
    # systemd user service
    log_info "Checking systemd user services..."
    if systemctl --user is-active sysmon.service &>/dev/null; then
      log_crit "sysmon.service is ACTIVE — backdoor is running"
    elif systemctl --user is-enabled sysmon.service &>/dev/null; then
      log_crit "sysmon.service is ENABLED (but not running)"
    else
      log_clean "sysmon.service not found in systemd"
    fi

    # Check for suspicious units in user systemd dir
    local user_systemd="$HOME/.config/systemd/user"
    if [[ -d "$user_systemd" ]]; then
      log_info "Listing units in $user_systemd:"
      local suspicious_units
      suspicious_units=$(find "$user_systemd" -name "*.service" -exec grep -li 'sysmon\|telemetry\|litellm\|checkmarx' {} \; 2>/dev/null) || true
      if [[ -n "$suspicious_units" ]]; then
        log_crit "Suspicious systemd units found:"
        echo "$suspicious_units" | sed 's/^/         /'
      else
        log_clean "No suspicious systemd user units"
      fi
    fi

    # System-wide (if root)
    if [[ $EUID -eq 0 ]] && [[ -d /etc/systemd/system ]]; then
      local sys_suspicious
      sys_suspicious=$(find /etc/systemd/system -name "*.service" -exec grep -li 'sysmon\|telemetry\|litellm\|checkmarx' {} \; 2>/dev/null) || true
      if [[ -n "$sys_suspicious" ]]; then
        log_crit "Suspicious system-wide systemd units:"
        echo "$sys_suspicious" | sed 's/^/         /'
      else
        log_clean "No suspicious system-wide systemd units"
      fi
    fi
  fi

  if [[ "$PLATFORM" == "darwin" ]]; then
    # LaunchAgents
    log_info "Checking macOS LaunchAgents..."
    local la_dirs=("$HOME/Library/LaunchAgents")
    [[ $EUID -eq 0 ]] && la_dirs+=("/Library/LaunchDaemons" "/Library/LaunchAgents")

    for la_dir in "${la_dirs[@]}"; do
      if [[ -d "$la_dir" ]]; then
        local suspicious_la
        suspicious_la=$(grep -rli 'sysmon\|litellm\|checkmarx\|telemetry' "$la_dir" 2>/dev/null) || true
        if [[ -n "$suspicious_la" ]]; then
          log_crit "Suspicious LaunchAgent/Daemon found:"
          echo "$suspicious_la" | sed 's/^/         /'
        else
          log_clean "No suspicious plists in $la_dir"
        fi
      fi
    done
  fi

  # Crontab (both platforms)
  log_info "Checking crontab..."
  local cron_output
  cron_output=$(crontab -l 2>/dev/null) || true
  if [[ -n "$cron_output" ]]; then
    local cron_suspicious
    cron_suspicious=$(echo "$cron_output" | grep -i 'sysmon\|litellm\|checkmarx\|models\.litellm') || true
    if [[ -n "$cron_suspicious" ]]; then
      log_crit "Suspicious crontab entry:"
      echo "$cron_suspicious" | sed 's/^/         /'
    else
      log_clean "Crontab exists but no suspicious entries"
    fi
  else
    log_clean "No crontab for current user"
  fi

  # Running processes
  log_info "Checking running processes..."
  local proc_suspicious
  proc_suspicious=$(ps aux 2>/dev/null | grep -i 'sysmon\.py\|checkmarx\|models\.litellm' | grep -v grep) || true
  if [[ -n "$proc_suspicious" ]]; then
    log_crit "Suspicious process(es) running:"
    echo "$proc_suspicious" | sed 's/^/         /'
  else
    log_clean "No suspicious processes found"
  fi
}

# ╔══════════════════════════════════════════════════════════════════╗
# ║  Phase 5 — Network Indicators                                    ║
# ╚══════════════════════════════════════════════════════════════════╝
run_phase_5() {
  phase_header "5 — Network Indicators"

  # ── Helper: resolve a domain to IPs ──
  _resolve_domain() {
    local domain="$1"
    if command -v dig &>/dev/null; then
      dig +short "$domain" 2>/dev/null
    elif command -v nslookup &>/dev/null; then
      nslookup "$domain" 2>/dev/null | grep -A1 'Name:' | grep 'Address:' | awk '{print $2}'
    elif command -v host &>/dev/null; then
      host "$domain" 2>/dev/null | grep 'has address' | awk '{print $NF}'
    fi
  }

  # ── Resolve C2/exfil domains to IPs ──
  log_info "Resolving C2/exfil domains..."
  local exfil_ips c2_ips
  exfil_ips=$(_resolve_domain "$EXFIL_DOMAIN") || true
  c2_ips=$(_resolve_domain "$C2_DOMAIN") || true

  if [[ -n "$exfil_ips" ]]; then
    log_warn "$EXFIL_DOMAIN resolves to:"
    echo "$exfil_ips" | sed 's/^/         /'
  else
    log_info "$EXFIL_DOMAIN does not resolve (may be taken down)"
  fi

  if [[ -n "$c2_ips" ]]; then
    log_warn "$C2_DOMAIN resolves to:"
    echo "$c2_ips" | sed 's/^/         /'
  else
    log_info "$C2_DOMAIN does not resolve (may be taken down)"
  fi

  # ── Build grep pattern from domain names + resolved IPs ──
  # This is critical: ss and lsof show raw IPs, not hostnames.
  local conn_pattern="$EXFIL_DOMAIN|$C2_DOMAIN"
  for ip in $exfil_ips $c2_ips; do
    # Escape dots for grep -E
    local escaped_ip
    escaped_ip=$(echo "$ip" | sed 's/\./\\./g')
    conn_pattern="${conn_pattern}|${escaped_ip}"
  done

  # ── Active connections ──
  log_info "Checking active network connections (domains + resolved IPs)..."
  local conn_suspicious=""
  if [[ "$PLATFORM" == "linux" ]]; then
    if command -v ss &>/dev/null; then
      conn_suspicious=$(ss -tnp 2>/dev/null | grep -E "$conn_pattern") || true
    elif command -v netstat &>/dev/null; then
      conn_suspicious=$(netstat -tnp 2>/dev/null | grep -E "$conn_pattern") || true
    fi
  elif [[ "$PLATFORM" == "darwin" ]]; then
    if command -v lsof &>/dev/null; then
      conn_suspicious=$(lsof -i -nP 2>/dev/null | grep -E "$conn_pattern") || true
    fi
  fi

  if [[ -n "$conn_suspicious" ]]; then
    log_crit "Active connection(s) to C2/exfil infrastructure:"
    echo "$conn_suspicious" | sed 's/^/         /'
  else
    log_clean "No active connections to known C2/exfil domains or IPs"
  fi

  # ── /etc/hosts ──
  log_info "Checking /etc/hosts for tampering..."
  local hosts_suspicious
  hosts_suspicious=$(grep -iE "$EXFIL_DOMAIN|$C2_DOMAIN|litellm" /etc/hosts 2>/dev/null) || true
  if [[ -n "$hosts_suspicious" ]]; then
    log_warn "/etc/hosts contains references to litellm/C2 domains:"
    echo "$hosts_suspicious" | sed 's/^/         /'
  else
    log_clean "/etc/hosts is clean"
  fi
}

# ╔══════════════════════════════════════════════════════════════════╗
# ║  Phase 6 — History & Cache Forensics                             ║
# ╚══════════════════════════════════════════════════════════════════╝
run_phase_6() {
  phase_header "6 — History & Cache Forensics"

  # ── Shell history ──
  log_info "Searching shell history for litellm installs..."
  local history_files=(
    "$HOME/.bash_history"
    "$HOME/.zsh_history"
    "$HOME/.local/share/fish/fish_history"
  )

  local history_found=false
  for hf in "${history_files[@]}"; do
    [[ ! -f "$hf" ]] && continue
    local matches
    matches=$(grep -in 'pip.*install.*litellm' "$hf" 2>/dev/null) || true
    if [[ -n "$matches" ]]; then
      # Check specifically for malicious versions
      local bad_matches
      bad_matches=$(echo "$matches" | grep -E '1\.82\.7|1\.82\.8') || true
      if [[ -n "$bad_matches" ]]; then
        log_crit "Shell history ($hf) shows install of malicious litellm version:"
        echo "$bad_matches" | sed 's/^/         /'
        history_found=true
      else
        log_info "Shell history ($hf) shows litellm install (non-malicious versions):"
        echo "$matches" | head -5 | sed 's/^/         /'
        history_found=true
      fi
    fi
  done

  if [[ "$history_found" == false ]]; then
    log_clean "No litellm install commands found in shell history"
  fi

  # ── pip cache ──
  log_info "Checking pip cache for malicious litellm versions..."
  local pip_cache_dirs=(
    "$HOME/.cache/pip/wheels"
    "$HOME/.cache/pip/http"
    "$HOME/Library/Caches/pip/wheels"
    "$HOME/Library/Caches/pip/http"
  )

  local cache_found=false
  for cache_dir in "${pip_cache_dirs[@]}"; do
    [[ ! -d "$cache_dir" ]] && continue
    local cached
    cached=$(find "$cache_dir" -name "*litellm*1.82.7*" -o -name "*litellm*1.82.8*" 2>/dev/null) || true
    if [[ -n "$cached" ]]; then
      log_crit "Malicious litellm version cached in pip:"
      echo "$cached" | sed 's/^/         /'
      cache_found=true
    fi
  done

  if [[ "$cache_found" == false ]]; then
    log_clean "No malicious litellm versions in pip cache"
  fi

  # ── uv cache ──
  log_info "Checking uv cache..."
  local uv_cache_dirs=(
    "$HOME/.cache/uv"
    "$HOME/Library/Caches/uv"
  )

  local uv_found=false
  for uv_dir in "${uv_cache_dirs[@]}"; do
    [[ ! -d "$uv_dir" ]] && continue
    local uv_cached
    uv_cached=$(find "$uv_dir" -name "*litellm*1.82.7*" -o -name "*litellm*1.82.8*" 2>/dev/null) || true
    if [[ -n "$uv_cached" ]]; then
      log_crit "Malicious litellm version cached in uv:"
      echo "$uv_cached" | sed 's/^/         /'
      uv_found=true
    fi
  done

  if [[ "$uv_found" == false ]]; then
    log_clean "No malicious litellm versions in uv cache"
  fi

  # ── pip logs ──
  log_info "Checking pip install logs..."
  local pip_log_locations=(
    "$HOME/.pip/pip.log"
    "$HOME/.cache/pip/log/debug.log"
    "$HOME/Library/Caches/pip/log/debug.log"
  )

  local log_found=false
  for logfile in "${pip_log_locations[@]}"; do
    [[ ! -f "$logfile" ]] && continue
    local log_matches
    log_matches=$(grep -in 'litellm.*1\.82\.[78]' "$logfile" 2>/dev/null) || true
    if [[ -n "$log_matches" ]]; then
      log_crit "Pip log ($logfile) references malicious litellm version:"
      echo "$log_matches" | head -10 | sed 's/^/         /'
      log_found=true
    fi
  done

  if [[ "$log_found" == false ]]; then
    log_clean "No references to malicious litellm in pip logs"
  fi
}

# ╔══════════════════════════════════════════════════════════════════╗
# ║  Main                                                            ║
# ╚══════════════════════════════════════════════════════════════════╝

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  litellm-audit — Supply Chain Compromise Scanner                 ║"
echo "║  Checking for IOCs from litellm 1.82.7 / 1.82.8 (March 2026)     ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Platform:     $PLATFORM"
echo "  Output dir:   $OUTPUT_DIR"
echo "  Steps:        ${STEPS[*]}"
echo "  Skip Docker:  $SKIP_DOCKER"

should_run "1" && run_phase_1
should_run "2" && run_phase_2
should_run "3" && run_phase_3
should_run "4" && run_phase_4
should_run "5" && run_phase_5
should_run "6" && run_phase_6

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  SCAN COMPLETE"
echo "════════════════════════════════════════════════════════════"
case $EXIT_CODE in
  0) echo "  Result: ALL CLEAN — no indicators of compromise found" ;;
  1) echo "  Result: WARNINGS — litellm present but no malicious version detected" ;;
  2) echo "  Result: COMPROMISED — indicators of compromise detected!" ;;
esac
echo "  Report saved to: $OUTPUT_DIR"
echo "════════════════════════════════════════════════════════════"

exit $EXIT_CODE

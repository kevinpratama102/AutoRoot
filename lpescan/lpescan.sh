#!/usr/bin/env bash
# ======================================================================
# lpescan.sh — scanner LPE ala PEAS + CVE matcher (port bash dari lpescan.py)
# Target: bash >= 4 + POSIX awk (mawk/busybox-safe). Tanpa python/jq.
# Read-only: scanner TIDAK PERNAH mengeksekusi PoC.
# Data (dihasilkan build-scanner.py): lpe-cves-linux.tsv, lpe-cve-meta.tsv,
#   lpe-pkgmap.tsv, lpe-distromap.tsv, lpe-gtfo.tsv, lpe-pocs.tsv, lpe-info.tsv
# ======================================================================
set -u
LC_ALL=C
export LC_ALL

SCANNER_VERSION="1.2.0"
IMPL="bash"
BACKPORT_GRACE_DAYS=60

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# data TSV: di sebelah script (unit deploy dist/), atau dist/ di atasnya (mesin dev)
DATA_DIR="$SCRIPT_DIR"
[ -r "$SCRIPT_DIR/lpe-cves-linux.tsv" ] || DATA_DIR="$SCRIPT_DIR/dist"
D_CVES_LIN="$DATA_DIR/lpe-cves-linux.tsv"
D_META="$DATA_DIR/lpe-cve-meta.tsv"
D_PKGMAP="$DATA_DIR/lpe-pkgmap.tsv"
D_DISTROMAP="$DATA_DIR/lpe-distromap.tsv"
D_GTFO="$DATA_DIR/lpe-gtfo.tsv"
D_POCS="$DATA_DIR/lpe-pocs.tsv"
D_INFO="$DATA_DIR/lpe-info.tsv"

# ---- flags ----
REPORT_PATH=""
JSON_ONLY=0
NO_COLOR=0
DO_SELFTEST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --report) REPORT_PATH="$2"; shift 2 ;;
    --json-only) JSON_ONLY=1; shift ;;
    --no-color) NO_COLOR=1; shift ;;
    --selftest) DO_SELFTEST=1; shift ;;
    -h|--help) cat <<'USAGE'
lpescan.sh — LPE scanner + CVE matcher (bash)
  lpescan.sh [--report PATH] [--json-only] [--no-color]
  lpescan.sh --selftest
USAGE
      exit 0 ;;
    *) echo "[!] argumen tak dikenal: $1" >&2; exit 2 ;;
  esac
done

# ---- warna ----
if [ "$NO_COLOR" = 1 ]; then
  C_R="" C_B="" C_G="" C_DIM="" C_RB="" C_M="" C_MB="" C_Y=""
  S_CRIT="" S_HIGH="" S_MED="" S_LOW="" S_INFO=""
else
  C_R=$'\033[0m'    C_B=$'\033[1m'   C_G=$'\033[32m' C_DIM=$'\033[2m'
  C_RB=$'\033[1;31m' C_M=$'\033[35m' C_MB=$'\033[1;35m' C_Y=$'\033[33m'
  S_CRIT=$'\033[1;31m' S_HIGH=$'\033[1;33m' S_MED=$'\033[33m'
  S_LOW=$'\033[36m' S_INFO=$'\033[37m'
fi

# ======================================================================
# Mesin versi — awk POSIX (mawk/busybox-safe: tanpa match 3-arg, tanpa patsplit)
# ======================================================================
read -r -d '' AWK_LIB <<'AWK_EOF' || true
function toks(s,  t, n, i, out) {
  # tokenisasi seperti python re.findall(r"[0-9]+|[a-z]+"): run digit & huruf saja,
  # pemisah (. - _ + dll.) DIBUANG — bukan jadi token
  s = tolower(s)
  gsub(/[0-9]+|[a-z]+/, "|&|", s)
  gsub(/[^0-9a-z|]/, "", s)
  n = split(s, t, "|")
  out = ""
  for (i = 1; i <= n; i++)
    if (t[i] != "") out = out (out == "" ? "" : " ") t[i]
  return out
}

function norm(s,  t, n, i, out) {
  # normalize_num: hanya digit, buang trailing zero -> "5 15 0 72"
  gsub(/[^0-9]+/, " ", s)
  n = split(s, t, " ")
  while (n > 0 && (t[n] + 0) == 0) n--
  out = ""
  for (i = 1; i <= n; i++) out = out (i > 1 ? " " : "") (t[i] + 0)
  return out
}

function cmpv(a, b,  na, nb, i, ta, tb, va, vb) {
  # banding dua list token dipisah spasi: -1/0/1 (numeric > alpha;
  # prefix lebih pendek = lebih kecil) — parity cmp_version/_cmp_list
  na = split(a, aa, " ")
  nb = split(b, bb, " ")
  for (i = 1; i <= na && i <= nb; i++) {
    va = aa[i]; vb = bb[i]
    ta = (va ~ /^[0-9]+$/); tb = (vb ~ /^[0-9]+$/)
    if (ta && tb) {
      if ((va + 0) == (vb + 0)) continue
      return ((va + 0) < (vb + 0)) ? -1 : 1
    }
    if (!ta && !tb) {
      if (va == vb) continue
      return (va < vb) ? -1 : 1
    }
    return ta ? 1 : -1
  }
  if (na == nb) return 0
  return (na > nb) ? 1 : -1
}

function days_from_civil(y, m, d,  era, yoe, doy, doe) {
  # hari sipil eksak (integer) — parity datetime.date
  y -= (m <= 2)
  era = int(y / 400)
  yoe = y - era * 400
  doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
  doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
  return era * 146097 + doe - 719468
}

function bpdays(pub, bd,  py, pm, pd, by, bm, bday) {
  # selisih (build - published) dalam hari sipil; "" bila tak terparse
  if (bd == "-" || pub == "-") return ""
  by = substr(bd, 1, 4) + 0; bm = substr(bd, 6, 2) + 0; bday = substr(bd, 9, 2) + 0
  py = substr(pub, 1, 4) + 0; pm = substr(pub, 6, 2) + 0; pd = substr(pub, 9, 2) + 0
  if (by < 1900 || py < 1900 || bm < 1 || bm > 12 || pm < 1 || pm > 12) return ""
  return days_from_civil(by, bm, bday) - days_from_civil(py, pm, pd)
}
AWK_EOF

read -r -d '' AWK_EVAL <<'AWK_EOF' || true
function eval_row(pv,  i, op, v, n, qv, c) {
  # MODE="t" -> pv token list mentah, banding vs toks(v)
  # MODE="n" -> pv list int ternormalisasi, banding vs kolom n
  # kolom: 10=op1 11=v1 12=n1 13=op2 14=v2 15=n2 16=op3 17=v3 18=n3
  for (i = 0; i < 3; i++) {
    op = $(10 + 3*i); v = $(11 + 3*i); n = $(12 + 3*i)
    if (op == "-") continue
    if (op == "ALL") return 1
    if (op == "EXACT") {
      qv = (MODE == "t") ? toks(v) : n
      if (cmpv(pv, qv) != 0) return 0
      continue
    }
    qv = (MODE == "t") ? toks(v) : n
    c = cmpv(pv, qv)
    if (op == "<")  { if (c >= 0) return 0; continue }
    if (op == "<=") { if (c > 0)  return 0; continue }
    if (op == ">")  { if (c <= 0) return 0; continue }
    if (op == ">=") { if (c < 0)  return 0; continue }
    return 0   # op tak dikenal -> python return False
  }
  return 1
}

BEGIN { FS = "\t"; n = split(cands, C, "\n") }
{ if (SKIPALL && $10 == "ALL") next
  for (i = 1; i <= n; i++) {
    if (MODE == "n") { pv = norm(C[i]); if (pv == "") continue }
    else pv = toks(C[i])
    if (eval_row(pv)) {
      d = bpdays($2, BD)
      bp = (d != "" && d > GRACE) ? 1 : 0
      # jangan pernah emit field kosong: read bash meng-collapse delimiter ganda
      print i-1 "\t" $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6 "\t" $8 "\t" $9 "\t" bp "\t" (d == "" ? "-" : d) "\t" $10
      break   # parity python: satu entry per baris, kandidat pertama yang match
    }
  }
}
AWK_EOF

# ======================================================================
# Util
# ======================================================================
run_cmd() { # $1 timeout detik, $2 command -> stdout+stderr ("" bila gagal)
  local t="$1" out
  out=$( { timeout "$t" bash -c "$2" ; } 2>&1 ) || true
  printf '%s' "$out"
}

json_esc() { # escape backslash/quote; \t\r\n jadi \t\r\n (parity json.dumps); kontrol lain dibuang
  tr -d '\001-\010\013\014\016-\037' | awk '
    { gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t"); gsub(/\r/, "\\r")
      if (n++) printf "\\n"
      printf "%s", $0 }
  '
}

jstr() { printf '%s' "$1" | json_esc; }

month_num() {
  case "$(printf '%s' "$1" | tr 'A-Z' 'a-z')" in
    jan) echo 1 ;; feb) echo 2 ;; mar) echo 3 ;; apr) echo 4 ;;
    may) echo 5 ;; jun) echo 6 ;; jul) echo 7 ;; aug) echo 8 ;;
    sep) echo 9 ;; oct) echo 10 ;; nov) echo 11 ;; dec) echo 12 ;;
    *) echo 0 ;;
  esac
}

# ======================================================================
# Version engine (bash) — parity candidate_versions()
# ======================================================================
candidate_versions() {
  local v="$1" base b
  [[ "$v" =~ ^[0-9]+: ]] && v="${v#*:}"
  printf '%s\n' "$v"
  if [[ "$v" =~ ^(.+)-[0-9][^-]*$ && "${BASH_REMATCH[1]}" != *-* ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    for base in "$v" "${BASH_REMATCH[1]}"; do
      b="$base"
      while [[ "$b" == *.0 ]]; do b="${b%.0}"; printf '%s\n' "$b"; done
    done
  else
    b="$v"
    while [[ "$b" == *.0 ]]; do b="${b%.0}"; printf '%s\n' "$b"; done
  fi
}

# ======================================================================
# Distro-kernel / backport detection — parity _kernel_build_info
# ======================================================================
kernel_build_info() { # -> "distro_kernel|name|build_date|source"
  local kernel="$1" pv="$2" kl pvl s name d
  kl=$(printf '%s' "$kernel" | tr 'A-Z' 'a-z')
  pvl=$(printf '%s' "$pv" | tr 'A-Z' 'a-z')
  local suffix_hit=0
  for s in -generic -amd64 -cloud -azure -aws -gke -gcp -oracle -lowlatency \
           -realtime -rt -raspi -server -desktop -oem +kali -kali -xanmod -liquorix; do
    [[ "$kl" == *"$s" ]] && { suffix_hit=1; break; }
  done
  [[ "$kl" == *-ubuntu* || "$kl" == *-debian* ]] && suffix_hit=1
  name=""
  for d in ubuntu debian kali fedora redhat suse arch manjaro centos rocky \
           almalinux alma oracle mint raspbian; do
    if [[ "$kl" == *"$d"* ]]; then name="$d"; break; fi
  done
  if [ -z "$name" ]; then
    for d in ubuntu debian kali fedora redhat suse arch manjaro centos rocky \
             almalinux alma oracle mint raspbian; do
      if [[ "$pvl" == *"$d"* ]]; then name="$d"; break; fi
    done
  fi
  if [ "$suffix_hit" = 1 ] && [ -z "$name" ]; then
    if [[ "$kl" == *-generic* || "$kl" == *-ubuntu* ]]; then name="ubuntu"
    else name="debian"; fi
  fi
  if [ "$suffix_hit" = 0 ] && [ -z "$name" ]; then
    echo "0|-|-|-"
    return
  fi
  local bd
  bd=$(parse_proc_version_date "$pv")
  local src="-"
  [ -n "$pv" ] && src="/proc/version"
  echo "1|$name|$bd|$src"
}

parse_proc_version_date() { # -> "YYYY-MM-DD HH:MM:SS" atau "-" (parity str(datetime))
  local text="$1" mon m d hh mm ss yyyy
  if [[ "$text" =~ [[:alnum:]]{3}\ ([A-Za-z]{3})[[:space:]]+([0-9]{1,2})\ ([0-9]{1,2}):([0-9]{2}):([0-9]{2})\ [A-Za-z]{3,5}\ ([0-9]{4}) ]]; then
    mon=$(month_num "${BASH_REMATCH[1]}")
    d="${BASH_REMATCH[2]}"
    hh="${BASH_REMATCH[3]}" mm="${BASH_REMATCH[4]}" ss="${BASH_REMATCH[5]}"
    yyyy="${BASH_REMATCH[6]}"
    # validasi ringan (parity ValueError datetime)
    if [ "$mon" -ge 1 ] && [ "$mon" -le 12 ] && [ "$((10#$d))" -ge 1 ] && [ "$((10#$d))" -le 31 ] \
       && [ "$((10#$hh))" -le 23 ] && [ "$((10#$mm))" -le 59 ] && [ "$((10#$ss))" -le 59 ]; then
      printf '%s-%02d-%02d %02d:%02d:%02d' "$yyyy" "$mon" "$((10#$d))" "$((10#$hh))" "$((10#$mm))" "$((10#$ss))"
      return
    fi
  fi
  if [[ "$text" =~ \(([0-9]{4})-([0-9]{2})-([0-9]{2})\) ]]; then
    printf '%s-%s-%s 00:00:00' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
    return
  fi
  echo "-"
}

likely_backported() { # $1 published, $2 build_date ("YYYY-MM-DD ...") -> 1/0
  local pub="$1" bd="${2:0:10}"
  if [ -z "$pub" ] || [ "$pub" = "-" ] || [ -z "$bd" ] || [ "$bd" = "-" ]; then
    echo 0; return
  fi
  local days
  days=$(printf '' | awk -v pub="$pub" -v bd="$bd" "$AWK_LIB"$'\n'"BEGIN{print bpdays(pub, bd)}")
  [ -n "$days" ] && [ "$days" -gt "$BACKPORT_GRACE_DAYS" ] && { echo 1; return; }
  echo 0
}

in_container() {
  [ -e /.dockerenv ] && { echo 1; return; }
  [ -r /proc/1/cgroup ] && grep -qE 'docker|kubepods|lxc|libpod' /proc/1/cgroup 2>/dev/null && { echo 1; return; }
  echo 0
}

# ======================================================================
# Fakta target (Linux)
# ======================================================================
F_HOST="" F_ARCH="" F_KERNEL="" F_KERNEL_BUILD="0|-|-|-"
F_DISTRO_ID="" F_DISTRO_VID="" F_DISTRO_CODENAME="" F_DISTRO_PRETTY=""
F_DEBIAN_VER="" F_PACKAGES="" F_IN_CONTAINER=0

collect_facts_linux() {
  F_HOST=$(hostname 2>/dev/null || uname -n)
  F_ARCH=$(uname -m)
  F_KERNEL=$(uname -r)
  local pv
  pv=$(cat /proc/version 2>/dev/null || uname -v)
  F_KERNEL_BUILD=$(kernel_build_info "$F_KERNEL" "$pv")

  local id="" vid="" codename="" pretty="" k v
  if [ -r /etc/os-release ]; then
    while IFS='=' read -r k v; do
      v=${v#\"}; v=${v%\"}
      case "$k" in
        ID) [ -z "$id" ] && id="$v" ;;
        VERSION_ID) [ -z "$vid" ] && vid="$v" ;;
        VERSION_CODENAME) [ -z "$codename" ] && codename="$v" ;;
        PRETTY_NAME) [ -z "$pretty" ] && pretty="$v" ;;
      esac
    done < /etc/os-release
  fi
  if [ -z "$id" ] && command -v lsb_release >/dev/null 2>&1; then
    local lsb
    lsb=$(run_cmd 10 "lsb_release -a 2>/dev/null")
    id=$(printf '%s\n' "$lsb" | sed -n 's/^Distributor ID:[[:space:]]*//p' | head -1 | tr 'A-Z' 'a-z')
    [ -z "$vid" ] && vid=$(printf '%s\n' "$lsb" | sed -n 's/^Release:[[:space:]]*//p' | head -1)
    [ -z "$codename" ] && codename=$(printf '%s\n' "$lsb" | sed -n 's/^Codename:[[:space:]]*//p' | head -1 | tr 'A-Z' 'a-z')
  fi
  F_DISTRO_ID=$(printf '%s' "$id" | tr 'A-Z' 'a-z')
  F_DISTRO_VID="$vid" F_DISTRO_CODENAME="$codename" F_DISTRO_PRETTY="$pretty"
  F_DEBIAN_VER=$(cat /etc/debian_version 2>/dev/null)

  if command -v dpkg-query >/dev/null 2>&1; then
    F_PACKAGES=$(run_cmd 30 "dpkg-query -W -f='\${Package}\t\${Version}\n' 2>/dev/null")
  fi
  if [ -z "$F_PACKAGES" ] && command -v rpm >/dev/null 2>&1; then
    F_PACKAGES=$(run_cmd 30 "rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null")
  fi
  F_IN_CONTAINER=$(in_container)
}

# ======================================================================
# Data (dimuat sekali)
# ======================================================================
declare -A ROWS_BY_CPE EVAL_CACHE META_BY_ID POC_BY_ID
declare -a PKG_PATTERNS PKG_CPES DISTRO_OSIDS DISTRO_CPES GTFO_PATTERNS
CVE_COUNT="0" DATASET_GEN="-"

load_data() {
  local f ok=1
  for f in "$D_CVES_LIN" "$D_META" "$D_PKGMAP" "$D_DISTROMAP" "$D_POCS" "$D_INFO" "$D_GTFO"; do
    if [ ! -r "$f" ]; then
      echo "[!] $f tidak ditemukan — jalankan build-scanner.py di mesin arsip, lalu copy dist/." >&2
      ok=0
    fi
  done
  [ "$ok" = 0 ] && exit 1

  while IFS=$'\t' read -r cpe line; do
    ROWS_BY_CPE[$cpe]+="$line"$'\n'
  done < <(awk -F'\t' '{print $8"\t"$0}' "$D_CVES_LIN")

  while IFS=$'\t' read -r pat vend prod; do
    PKG_PATTERNS+=("$pat"); PKG_CPES+=("$vend:$prod")
  done < "$D_PKGMAP"

  while IFS=$'\t' read -r osid cpe; do
    DISTRO_OSIDS+=("$osid"); DISTRO_CPES+=("$cpe")
  done < "$D_DISTROMAP"

  while IFS=$'\t' read -r pat; do
    [ -n "$pat" ] && GTFO_PATTERNS+=("$pat")
  done < "$D_GTFO"

  CVE_COUNT=$(awk -F'\t' '{for(i=1;i<=NF;i+=2) if($i=="count"){print $(i+1);exit}}' "$D_INFO")
  DATASET_GEN=$(awk -F'\t' '{for(i=1;i<=NF;i+=2) if($i=="generated"){print $(i+1);exit}}' "$D_INFO")
  [ -z "$CVE_COUNT" ] && CVE_COUNT=0
  [ -z "$DATASET_GEN" ] && DATASET_GEN="-"
}

load_desc_pocs() { # setelah matching: desc + pocs untuk id yang match
  local idsfile out id desc repo url
  idsfile=$(mktemp /tmp/lpescan-ids.XXXXXX) || return 1
  printf '%s\n' "${MATCH_IDS[@]}" | sort -u > "$idsfile"
  out=$(awk -F'\t' 'NR==FNR{w[$1]=1;next} w[$1]{print $1"\t"$2}' "$idsfile" "$D_META")
  while IFS=$'\t' read -r id desc; do
    [ -n "$id" ] && META_BY_ID[$id]="$desc"
  done <<< "$out"
  out=$(awk -F'\t' 'NR==FNR{w[$1]=1;next} w[$1]{print $1"\t"$2"\t"$3}' "$idsfile" "$D_POCS")
  while IFS=$'\t' read -r id repo url; do
    [ -n "$id" ] && POC_BY_ID[$id]+="{\"repo\":\"$(jstr "$repo")\",\"url\":\"$(jstr "$url")\"},"
  done <<< "$out"
  rm -f "$idsfile"
}

# ======================================================================
# CVE matcher
# ======================================================================
declare -A M_TIER M_CONF M_RANK M_KEV M_ESC M_BP M_SCORE M_SEV M_PUB M_MATCHES
declare -A M_FIRST_CONST M_FIRST_INST
declare -a MATCH_IDS

add_match() { # id tier conf cpe raw installed kev esc score sev pub bp
  local id="$1" tier="$2" conf="$3" cpe="$4" raw="$5" installed="$6"
  local kev="$7" esc="$8" score="$9" sev="${10}" pub="${11}" bp="${12}"
  [ "$bp" = 1 ] && [ "$conf" = high ] && conf=possible
  local newrank=9
  case "$tier" in kernel) newrank=0 ;; package) newrank=1 ;;
    os_build) newrank=2 ;; distro_pin) newrank=3 ;; esac
  local mjson
  mjson="{\"cpe\":\"$(jstr "$cpe")\",\"constraint\":\"$(jstr "$raw")\",\"installed\":\"$(jstr "$installed")\"}"
  if [ -z "${M_TIER[$id]+x}" ]; then
    M_TIER[$id]="$tier"; M_CONF[$id]="$conf"; M_RANK[$id]="$newrank"
    M_KEV[$id]="$kev"; M_ESC[$id]="$esc"; M_BP[$id]="$bp"
    M_SCORE[$id]="$score"; M_SEV[$id]="$sev"; M_PUB[$id]="$pub"
    M_MATCHES[$id]="$mjson"
    M_FIRST_CONST[$id]="$raw"; M_FIRST_INST[$id]="$installed"
    MATCH_IDS+=("$id")
  else
    if [ "$newrank" -lt "${M_RANK[$id]}" ]; then
      M_TIER[$id]="$tier"; M_CONF[$id]="$conf"; M_RANK[$id]="$newrank"
      M_MATCHES[$id]="$mjson"
      M_FIRST_CONST[$id]="$raw"; M_FIRST_INST[$id]="$installed"
    elif [ "$newrank" -gt "${M_RANK[$id]}" ]; then
      return
    else
      [ "$conf" = high ] && M_CONF[$id]=high
      M_MATCHES[$id]+=",$mjson"
    fi
    [ "$bp" = 1 ] && M_BP[$id]=1
    [ "$esc" = 1 ] && M_ESC[$id]=1
  fi
}

eval_rows() { # $1 cpe $2 cands(NL) $3 mode $4 bd $5 skipall -> baris hasil
  local rows key out
  rows="${ROWS_BY_CPE[$1]-}"
  [ -z "$rows" ] || [ -z "$2" ] && return
  key="$1|$3|$5|$(printf '%s' "$2" | tr '\n' '~')"
  if [ -n "${EVAL_CACHE[$key]+x}" ]; then
    # wajib berakhir \n — bila tidak, while read akan EOF parsial di baris terakhir
    # dan baris itu HILANG (read return 1)
    printf '%s\n' "${EVAL_CACHE[$key]}"
    return
  fi
  out=$(printf '%s' "$rows" | awk -F'\t' -v cands="$2" -v MODE="$3" -v BD="$4" \
    -v GRACE="$BACKPORT_GRACE_DAYS" -v SKIPALL="$5" "$AWK_LIB$AWK_EVAL")
  EVAL_CACHE[$key]="$out"
  printf '%s\n' "$out"
}

kernel_build_parts() { # -> KB_FLAG KB_NAME KB_DATE KB_SRC
  IFS='|' read -r KB_FLAG KB_NAME KB_DATE KB_SRC <<< "$F_KERNEL_BUILD"
}

match_kernel() {
  kernel_build_parts
  local kb_flag=0 kb_date="-"
  [ "$KB_FLAG" = 1 ] && kb_flag=1
  if [ "$KB_DATE" != "-" ]; then kb_date="${KB_DATE:0:10}"; fi
  local idx id pub score sev kev esc cpe raw bp days op1
  while IFS=$'\t' read -r idx id pub score sev kev esc cpe raw bp days op1; do
    [ -z "$id" ] && continue
    local backported=$((kb_flag && bp))
    if [ "$op1" = ALL ]; then
      [ "$kev" = 1 ] && add_match "$id" kernel possible "$cpe" "$raw" "$F_KERNEL" \
        "$kev" "$esc" "$score" "$sev" "$pub" "$backported"
      continue
    fi
    add_match "$id" kernel high "$cpe" "$raw" "$F_KERNEL" \
      "$kev" "$esc" "$score" "$sev" "$pub" "$backported"
  done < <(eval_rows "linux:linux_kernel" "$F_KERNEL" n "$kb_date" 0)
}

match_package() {
  local name ver nl i pat cpe cands
  local idx id pub score sev kev esc cpe2 raw bp days op1
  while IFS=$'\t' read -r name ver; do
    [ -z "$name" ] && continue
    nl=$(printf '%s' "$name" | tr 'A-Z' 'a-z')
    for i in "${!PKG_PATTERNS[@]}"; do
      pat="${PKG_PATTERNS[$i]}"
      case "$nl" in
        $pat) ;;
        *) continue ;;
      esac
      cpe="${PKG_CPES[$i]}"
      cands=$(candidate_versions "$ver")
      while IFS=$'\t' read -r idx id pub score sev kev esc cpe2 raw bp days op1; do
        [ -z "$id" ] && continue
        if [ "$op1" = ALL ]; then
          [ "$kev" = 1 ] && add_match "$id" package possible "$cpe2" "$raw" "$name $ver" \
            "$kev" "$esc" "$score" "$sev" "$pub" 0
          continue
        fi
        add_match "$id" package high "$cpe2" "$raw" "$name $ver" \
          "$kev" "$esc" "$score" "$sev" "$pub" 0
      done < <(eval_rows "$cpe" "$cands" t - 0)
    done
  done <<< "$F_PACKAGES"
}

match_distro() {
  [ -z "$F_DISTRO_ID" ] && return
  local i idx id pub score sev kev esc cpe2 raw bp days op1
  for i in "${!DISTRO_OSIDS[@]}"; do
    [ "${DISTRO_OSIDS[$i]}" != "$F_DISTRO_ID" ] && continue
    local cpe="${DISTRO_CPES[$i]}"
    # parity python: vids = [version_id, debian_version], break per row setelah match pertama
    local cands="" vids=()
    if [ -n "$F_DISTRO_VID" ]; then cands="$F_DISTRO_VID"; vids+=("$F_DISTRO_VID"); fi
    if [ -n "$F_DEBIAN_VER" ]; then
      [ -n "$cands" ] && cands="$cands"$'\n'
      cands="$cands$F_DEBIAN_VER"; vids+=("$F_DEBIAN_VER")
    fi
    [ -z "$cands" ] && continue
    while IFS=$'\t' read -r idx id pub score sev kev esc cpe2 raw bp days op1; do
      [ -z "$id" ] && continue
      add_match "$id" distro_pin possible "$cpe2" "$raw" "$F_DISTRO_ID ${vids[$idx]}" \
        "$kev" "$esc" "$score" "$sev" "$pub" 0
    done < <(eval_rows "$cpe" "$cands" n - 1)
  done
}

match_cves() {
  match_kernel
  match_package
  match_distro
}

sorted_ids() { # -> urutan (not kev, tier, -score, id)
  local tmp id
  tmp=$(mktemp /tmp/lpescan-sort.XXXXXX) || { printf '%s\n' "${MATCH_IDS[@]}"; return; }
  for id in "${MATCH_IDS[@]}"; do
    printf '%s\t%s\t%s\t%s\n' "${M_KEV[$id]}" "${M_RANK[$id]}" "${M_SCORE[$id]-0}" "$id" >> "$tmp"
  done
  sort -t$'\t' -k1,1n -k2,2n -k3,3nr -k4,4 "$tmp" | cut -f4
  rm -f "$tmp"
}

# ======================================================================
# PEAS checks — port 1:1 dari PEAS_CHECKS linux (16 cek)
# Temuan identik python: {category, severity, title, detail, check}
# ======================================================================
declare -a P_CAT P_SEV P_TITLE P_DETAIL P_CHECK P_DLIST
PEAS_TOTAL=0

peas_add() { # $1 cat $2 sev $3 title $4 detail $5 detail-is-list(0/1)
  P_CAT+=("$1"); P_SEV+=("$2"); P_TITLE+=("$3")
  P_DETAIL+=("$4"); P_CHECK+=("${FUNCNAME[1]}"); P_DLIST+=("${5:-0}")
  PEAS_TOTAL=$((PEAS_TOTAL+1))
}

sh_out() { # $1 timeout detik $2 command -> stdout+stderr, "" bila rc != 0 (parity python)
  local t="$1" out rc
  out=$( { timeout "$t" bash -c "$2" ; } 2>&1 )
  rc=$?
  [ "$rc" -eq 0 ] && printf '%s' "$out"
}

is_ww() { # $1 path -> 0 bila world-writable (mode & 0002), parity os.stat+0o002
  # stat -L: ikuti symlink (default stat = lstat; python os.stat follow)
  local m
  m=$(stat -L -c %a "$1" 2>/dev/null) || return 1
  case "${m: -1}" in 2|3|6|7) return 0 ;; *) return 1 ;; esac
}

chk_linux_sysinfo() {
  local un p v name sym hard txt
  un=$(sh_out 15 "uname -a")
  if [ -n "$un" ]; then
    peas_add system INFO uname "$(printf '%s' "$un" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')" 0
  fi
  [ -n "${F_DISTRO_PRETTY:-}" ] && peas_add system INFO distro "$F_DISTRO_PRETTY" 0
  for p in /proc/sys/kernel/randomize_va_space /proc/sys/kernel/kptr_restrict \
           /proc/sys/kernel/dmesg_restrict /proc/sys/kernel/unprivileged_userns_clone \
           /proc/sys/kernel/yama/ptrace_scope; do
    [ -r "$p" ] || continue
    v=$(tr -d '[:space:]' < "$p" 2>/dev/null) || continue
    name=${p##*/}
    case "$name" in
      randomize_va_space) [ "$v" = 0 ] && peas_add system MEDIUM "ASLR mati" "$p = 0 (eksploitasi lebih mudah)" 0 ;;
      kptr_restrict) [ "$v" = 0 ] && peas_add system LOW "kptr_restrict=0" "alamat kernel terlihat dari usermode" 0 ;;
      dmesg_restrict) [ "$v" = 0 ] && peas_add system LOW "dmesg bisa dibaca user" "dmesg_restrict=0" 0 ;;
      unprivileged_userns_clone) [ "$v" = 1 ] && peas_add system LOW "user namespaces aktif" "unprivileged_userns_clone=1" 0 ;;
    esac
  done
  [ -r /dev/kmsg ] && peas_add system LOW "/dev/kmsg bisa dibaca" "leak alamat kernel" 0
  [ -w /etc/ld.so.preload ] && peas_add system HIGH "/etc/ld.so.preload writable!" "injeksi library via preload" 0
  [ -n "${LD_LIBRARY_PATH:-}" ] && peas_add system LOW "LD_LIBRARY_PATH di environment" "$LD_LIBRARY_PATH" 0
  if sym=$(tr -d '[:space:]' < /proc/sys/fs/protected_symlinks 2>/dev/null) && \
     hard=$(tr -d '[:space:]' < /proc/sys/fs/protected_hardlinks 2>/dev/null); then
    [ "$sym" = 0 ] && peas_add system MEDIUM "protected_symlinks=0" "symlink attack dimungkinkan" 0
    [ "$hard" = 0 ] && peas_add system MEDIUM "protected_hardlinks=0" "hardlink attack dimungkinkan" 0
  fi
  [ -e /etc/hosts.equiv ] && peas_add system HIGH "/etc/hosts.equiv ada!" "trust equivalence" 0
  if [ -e /etc/selinux/config ]; then
    txt=$(sh_out 15 "getenforce 2>/dev/null")
    txt=${txt%$'\n'}
    if [ -n "$txt" ]; then
      peas_add system INFO "SELinux: $txt" /etc/selinux/config 0
    else
      peas_add system INFO "SELinux: konfigurasi ada" /etc/selinux/config 0
    fi
  fi
  [ -d /sys/kernel/security/apparmor ] && peas_add system INFO "AppArmor aktif" /sys/kernel/security/apparmor 0
}

chk_linux_users() {
  local line parts g members sev p
  while IFS= read -r line; do
    case "$line" in \#*|"") continue ;; esac
    IFS=: read -ra parts <<< "$line"
    [ "${#parts[@]}" -gt 6 ] || continue
    { [ "${parts[2]}" = 0 ] || [ "${parts[3]}" = 0 ]; } || continue
    [ "${parts[0]}" != root ] || continue
    peas_add users HIGH "akun UID/GID 0 selain root: ${parts[0]}" "$line" 0
  done < /etc/passwd 2>/dev/null
  for g in sudo wheel docker lxd lxc adm shadow disk video; do
    while IFS= read -r line; do
      case "$line" in "$g":*) ;; *) continue ;; esac
      members=$(printf '%s' "$line" | cut -d: -f4 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
      [ -n "$members" ] || continue
      sev=MEDIUM
      case "$g" in sudo|wheel|docker|lxd|lxc) sev=HIGH ;; esac
      peas_add users "$sev" "anggota grup $g: $members" "$line" 0
    done < /etc/group 2>/dev/null
  done
  is_ww /etc/sudoers && peas_add users HIGH "/etc/sudoers world-writable!" "" 0
  for p in /etc/sudoers.d/*; do
    [ -e "$p" ] || continue
    is_ww "$p" && peas_add users HIGH "$p world-writable!" "" 0
  done
}

chk_linux_sudo() {
  local v l ll sr f line
  v=$(sh_out 15 "sudo -V 2>/dev/null | head -1")
  if [ -n "$v" ]; then
    peas_add sudo INFO "sudo version" "$(printf '%s' "$v" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')" 0
  fi
  l=$(sh_out 15 "sudo -n -l 2>&1")
  if [ -n "$l" ]; then
    l=${l%$'\n'}
    ll=$(printf '%s' "$l" | tr 'A-Z' 'a-z')
    case "$ll" in
      *"not allowed"*|*"a password is required"*|*"command not found"*) ;;
      *)
        if grep -Eq '\(ALL[[:space:]]*(:[[:space:]]*ALL)?\)[[:space:]]*(ALL|NOPASSWD:[[:space:]]*ALL)' <<< "$l" \
           || grep -q NOPASSWD <<< "$l"; then
          peas_add sudo HIGH "sudo NOPASSWD untuk user ini" "${l:0:400}" 0
        else
          peas_add sudo MEDIUM "sudo -l tersedia (non-interaktif)" "${l:0:400}" 0
        fi
        grep -Eq 'env_keep\+?=(LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PERL5LIB|RUBYLIB)' <<< "$l" \
          && peas_add sudo HIGH "sudo env_keep LD_* terkonfigurasi" "potensi injeksi library" 0
        ;;
    esac
  fi
  sr=""
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -r "$f" ] || continue
    sr="$sr$(cat "$f" 2>/dev/null)"$'\n'
  done
  while IFS= read -r line || [ -n "$line" ]; do
    peas_add sudo HIGH "baris NOPASSWD di sudoers" "$line" 0
  done < <(grep -E '^[^#]*NOPASSWD' <<< "$sr" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
}

chk_linux_suid() {
  local pat p m mode_oct base suid sgid tag found=0 gtfo
  while IFS= read -r p || [ -n "$p" ]; do
    [ "$found" -le 400 ] || break
    found=$((found+1))
    mode_oct=$(stat -c %a "$p" 2>/dev/null) || continue  # lstat — parity os.lstat
    m=$(( 8#$mode_oct ))
    suid=0; sgid=0
    (( m & 04000 )) && suid=1
    (( m & 02000 )) && sgid=1
    [ "$suid" = 1 ] || [ "$sgid" = 1 ] || continue
    tag=SGID; [ "$suid" = 1 ] && tag=SUID
    base=$(basename "$p" | tr 'A-Z' 'a-z')
    # fnmatch per-pattern (case tidak re-parse "|" dari ekspansi variabel)
    gtfo=0
    for pat in "${GTFO_PATTERNS[@]}"; do
      case "$base" in
        $pat) gtfo=1; break ;;
      esac
    done
    if [ "$gtfo" = 1 ]; then
      if [ "$suid" = 1 ]; then
        peas_add suid HIGH "$tag GTFO-bins: $p" "$mode_oct" 0
      else
        peas_add suid MEDIUM "$tag GTFO-bins: $p" "$mode_oct" 0
      fi
    else
      [ "$suid" = 1 ] && peas_add suid MEDIUM "SUID custom: $p" "$mode_oct" 0
    fi
  done < <(find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap \
    -o -path /var/lib/docker -o -path /var/lib/lxc -o -path /var/cache -o -path /var/tmp -o -path /tmp \) \
    -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | head -n 401)
}

chk_linux_caps() {
  local txt line ll
  txt=$(sh_out 45 "getcap -r / 2>/dev/null")
  [ -z "$txt" ] && txt=$(sh_out 45 "/usr/sbin/getcap -r / 2>/dev/null")
  while IFS= read -r line || [ -n "$line" ]; do
    line=$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    ll=$(printf '%s' "$line" | tr 'A-Z' 'a-z')
    case "$ll" in
      *cap_setuid*|*cap_dac_override*|*cap_dac_read_search*|*cap_chown*|*cap_sys_admin*|\
      *cap_sys_module*|*cap_net_admin*|*cap_sys_ptrace*|*cap_net_raw*|*cap_setgid*|\
      *cap_linux_immutable*|*cap_fowner*)
        peas_add capabilities HIGH "file capability berbahaya" "$line" 0 ;;
      *=*) peas_add capabilities MEDIUM "file capability" "$line" 0 ;;
    esac
  done <<< "$txt"
}

chk_linux_path() {
  local -a ents
  local ent uid
  if [ -z "${PATH:-}" ]; then
    peas_add path HIGH "PATH berisi '.' atau entri kosong" "PATH=" 0
    return
  fi
  IFS=: read -ra ents <<< "$PATH"
  for ent in "${ents[@]}"; do
    if [ -z "$ent" ] || [ "$ent" = . ]; then
      peas_add path HIGH "PATH berisi '.' atau entri kosong" "PATH=$PATH" 0
      continue
    fi
    if is_ww "$ent"; then
      peas_add path HIGH "entri PATH world-writable: $ent" "" 0
      continue
    fi
    uid=$(stat -L -c %u "$ent" 2>/dev/null) || continue
    [ "$uid" != 0 ] && [ "$(id -u)" != "$uid" ] \
      && peas_add path MEDIUM "entri PATH milik user lain: $ent" "" 0
  done
}

chk_linux_cron() {
  local p uid body hits
  for p in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* \
           /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
    [ -e "$p" ] || continue
    is_ww "$p" && peas_add cron HIGH "file cron world-writable: $p" "" 0
    uid=$(stat -L -c %u "$p" 2>/dev/null) || continue
    [ "$uid" != 0 ] && peas_add cron MEDIUM "file cron milik non-root: $p" "" 0
    body=$(cat "$p" 2>/dev/null) || continue
    hits=$(grep -E '\<(tar|chown|chmod|rsync|zip|find)\>.*\*' <<< "$body" \
      | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | head -3)
    [ -n "$hits" ] && peas_add cron HIGH "kemungkinan wildcard injection di $p" "$hits" 1
  done
  for p in /etc/cron.d /var/spool/cron/crontabs /var/spool/cron; do
    [ -d "$p" ] && is_ww "$p" && peas_add cron HIGH "direktori cron world-writable: $p" "" 0
  done
}

chk_linux_passwd() {
  local f uid
  for f in /etc/passwd /etc/shadow /etc/gshadow; do
    [ -e "$f" ] || continue
    is_ww "$f" && peas_add passwd HIGH "$f world-writable!" "" 0
    if [ "$f" = /etc/shadow ] && [ -r "$f" ]; then
      uid=$(stat -L -c %u "$f" 2>/dev/null) || continue
      [ "$uid" != "$(id -u)" ] && peas_add passwd HIGH "/etc/shadow bisa dibaca (hash crack)" "" 0
    fi
  done
}

chk_linux_containers() {
  local cg p
  [ -e /.dockerenv ] && peas_add containers INFO "berjalan di dalam container docker" "" 0
  if [ -r /proc/1/cgroup ]; then
    cg=$(cat /proc/1/cgroup 2>/dev/null)
    case "$cg" in
      *docker*|*kubepod*) peas_add containers INFO "cgroup menunjukkan container" "" 0 ;;
    esac
  fi
  if [ -e /var/run/docker.sock ]; then
    if stat -L -c %a /var/run/docker.sock >/dev/null 2>&1; then
      if is_ww /var/run/docker.sock || [ -w /var/run/docker.sock ]; then
        peas_add containers HIGH "docker.sock writable!" "docker run -v /:/host → escape" 0
      else
        peas_add containers MEDIUM "docker.sock ada (perlu grup docker)" "" 0
      fi
    else
      peas_add containers MEDIUM "docker.sock ada" "" 0
    fi
  fi
  for p in /run/podman/podman.sock /run/containerd/containerd.sock; do
    [ -e "$p" ] && peas_add containers MEDIUM "$p ada" "" 0
  done
  for p in /root/.kube/config "${HOME:-}"/.kube/config; do
    [ -e "$p" ] && peas_add containers HIGH "kubeconfig: $p" "" 0
  done
}

chk_linux_net() {
  local txt line dline pid status pair port svc r rc
  txt=$(sh_out 15 "ss -tlnp 2>/dev/null")
  [ -z "$txt" ] && txt=$(sh_out 15 "netstat -tlnp 2>/dev/null")
  while IFS= read -r line || [ -n "$line" ]; do
    [[ "$line" =~ pid=([0-9]+) ]] || continue
    pid=${BASH_REMATCH[1]}
    status=$(cat "/proc/$pid/status" 2>/dev/null)
    case "$status" in
      *$'Uid:\t0\t'*)
        dline=$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        peas_add network MEDIUM "service sebagai root: ${dline:0:120}" "" 0 ;;
    esac
  done <<< "$txt"
  while IFS= read -r line || [ -n "$line" ]; do
    dline=$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    for pair in "127.0.0.1:6379:redis" "127.0.0.1:3306:mysql" "127.0.0.1:5432:postgres" \
               "127.0.0.1:2375:docker-api" "127.0.0.1:27017:mongodb" "127.0.0.1:11211:memcached" \
               "127.0.0.1:9200:elasticsearch" ":22:ssh"; do
      port=${pair%:*}; svc=${pair##*:}
      case "$line" in
        *"$port"*) peas_add network INFO "listener $svc terdeteksi" "${dline:0:120}" 0 ;;
      esac
    done
  done <<< "$txt"
  r=$( { timeout 3 bash -c "redis-cli -h 127.0.0.1 ping 2>/dev/null"; } 2>&1 ); rc=$?
  [ "$rc" = 124 ] && r=""
  case "$r" in
    *PONG*) peas_add network HIGH "redis tanpa auth!" "redis-cli ping → PONG" 0 ;;
  esac
}

chk_linux_systemd() {
  local d f exe
  for d in /etc/systemd/system /usr/lib/systemd/system; do
    # parity glob.glob (os.scandir = urutan readdir): find juga readdir, bukan sort;
    # *.service dulu baru *.timer, per direktori
    while IFS= read -r f || [ -n "$f" ]; do
      [ -e "$f" ] || continue
      is_ww "$f" && peas_add systemd HIGH "unit systemd world-writable: $f" "" 0
      while IFS= read -r exe || [ -n "$exe" ]; do
        [ -e "$exe" ] && is_ww "$exe" \
          && peas_add systemd HIGH "binary ExecStart writable: $exe (unit $f)" "" 0
      done < <(grep -Eo 'Exec[A-Za-z0-9_]*=(/[A-Za-z0-9_./-]+)' "$f" 2>/dev/null \
        | sed 's/^Exec[A-Za-z0-9_]*=//')
    done < <(find "$d" -maxdepth 1 -name '*.service' -print 2>/dev/null; \
             find "$d" -maxdepth 1 -name '*.timer' -print 2>/dev/null)
  done
}

chk_linux_nfs() {
  local line txt
  while IFS= read -r line || [ -n "$line" ]; do
    line=$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -n "$line" ] || continue
    case "$line" in \#*) continue ;; esac
    case "$line" in
      *no_root_squash*) peas_add nfs HIGH "export NFS berisiko" "$line" 0 ;;
      *)
        printf '%s' "$line" | grep -Eq '(^|[^[:alnum:]])rw([^[:alnum:]]|$)' \
          && peas_add nfs MEDIUM "export NFS berisiko" "$line" 0 ;;
    esac
  done < /etc/exports 2>/dev/null
  txt=$(sh_out 15 "mount -t nfs,nfs4 2>/dev/null")
  if [ -n "$txt" ]; then
    peas_add nfs INFO "mount NFS" "$(printf '%s\n' "$txt" | head -5)" 1
  fi
}

chk_linux_creds() {
  local pat='password|passwd|token|secret|api[_-]?key|access[_-]?key|mysql|psql|bearer'
  local -a homes
  local h hh hf kf cf p hits
  for h in "${HOME:-}" /root /home/*; do
    [ -n "$h" ] || continue
    [ -d "$h" ] || continue
    local seen=0
    for hh in "${homes[@]}"; do [ "$hh" = "$h" ] && seen=1; done
    [ "$seen" = 0 ] && homes+=("$h")
  done
  for h in "${homes[@]}"; do
    for hf in .bash_history .zsh_history .mysql_history .psql_history; do
      p="$h/$hf"
      [ -e "$p" ] || continue
      [ -r "$p" ] || continue
      hits=$(grep -Ei "$pat" "$p" 2>/dev/null \
        | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | head -3)
      [ -n "$hits" ] && peas_add credentials MEDIUM "$p: kredensial mencurigakan" "$hits" 1
    done
    for kf in id_rsa id_ed25519 id_dsa id_ecdsa; do
      p="$h/.ssh/$kf"
      [ -e "$p" ] && [ -r "$p" ] && peas_add credentials HIGH "kunci SSH terbaca: $p" "" 0
    done
    for cf in .aws/credentials .git-credentials .netrc .config/gcloud/credentials.db; do
      p="$h/$cf"
      [ -e "$p" ] && [ -r "$p" ] && peas_add credentials HIGH "file kredensial: $p" "" 0
    done
  done
  for p in /var/www/*/wp-config.php /var/www/*/*/wp-config.php /var/www/*/.env /var/www/*/*/.env; do
    [ -e "$p" ] || continue
    [ -r "$p" ] || continue
    case "$p" in
      *.env) peas_add credentials HIGH ".env terbaca: $p" "" 0 ;;
      *) peas_add credentials HIGH "wp-config.php terbaca: $p" "" 0 ;;
    esac
  done
}

chk_linux_sessions() {
  local p
  for p in /tmp/tmux-* /tmp/.tmux* /run/screen/S-* /var/run/screen/S-* /dev/shm/screen/S-*; do
    [ -e "$p" ] || continue
    case "$p" in
      *tmux*) peas_add sessions MEDIUM "socket sesi aktif: $p" "attach: tmux -S $p" 0 ;;
      *) peas_add sessions MEDIUM "socket sesi aktif: $p" "attach: screen -x $p" 0 ;;
    esac
  done
}

chk_linux_git() {
  local p r rc line
  p="${HOME:-}/.gitconfig"
  [ -n "${HOME:-}" ] && [ -e "$p" ] && [ -r "$p" ] && peas_add git INFO "gitconfig user" "$p" 0
  r=$( { timeout 20 bash -c "find /home /root /var/www /opt /srv -maxdepth 5 \( -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' -o -name '*.ovpn' -o -name '*.kdbx' \) -type f 2>/dev/null"; } 2>&1 )
  rc=$?
  [ "$rc" = 124 ] && r=""
  while IFS= read -r line || [ -n "$line" ]; do
    peas_add git MEDIUM "file sensitif ditemukan: $line" "" 0
  done < <(printf '%s\n' "$r" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | head -15)
}

chk_linux_misc() {
  local d h f p txt proc
  for d in /etc/update-motd.d; do
    [ -d "$d" ] && is_ww "$d" && peas_add misc MEDIUM "$d world-writable (motd exec saat login)" "" 0
  done
  for h in /root "${HOME:-}"; do
    [ -n "$h" ] || continue
    for f in .rhosts .forward; do
      p="$h/$f"
      [ -e "$p" ] && peas_add misc MEDIUM "$p ada" "" 0
    done
  done
  txt=$(sh_out 15 "ps aux 2>/dev/null")
  for proc in mysqld mariadbd; do
    printf '%s' "$txt" | grep -Eq "^[^[:space:]]+[[:space:]]+[0-9]+.*${proc}.*--skip-grant-tables" \
      && peas_add misc HIGH "mysqld jalan dengan --skip-grant-tables!" "" 0
  done
}

run_peas() {
  chk_linux_sysinfo
  chk_linux_users
  chk_linux_sudo
  chk_linux_suid
  chk_linux_caps
  chk_linux_path
  chk_linux_cron
  chk_linux_passwd
  chk_linux_containers
  chk_linux_net
  chk_linux_systemd
  chk_linux_nfs
  chk_linux_creds
  chk_linux_sessions
  chk_linux_git
  chk_linux_misc
}

# ======================================================================
# Report JSON
# ======================================================================
json_or_null() { # $1 nilai ; "-" -> null ; "" -> null
  if [ -z "$1" ] || [ "$1" = "-" ]; then printf 'null'; else printf '%s' "$1"; fi
}

facts_json() {
  local kb_flag kb_name kb_date kb_src
  IFS='|' read -r kb_flag kb_name kb_date kb_src <<< "$F_KERNEL_BUILD"
  local kb_distro=false kb_name_j=null kb_date_j=null kb_src_j=null
  if [ "$kb_flag" = 1 ]; then
    kb_distro=true
    [ "$kb_name" != "-" ] && kb_name_j="\"$(jstr "$kb_name")\""
    [ "$kb_date" != "-" ] && kb_date_j="\"$(jstr "$kb_date")\""
    [ "$kb_src" != "-" ] && kb_src_j="\"$(jstr "$kb_src")\""
  fi
  local container=false
  [ "$F_IN_CONTAINER" = 1 ] && container=true
  printf '{"hostname":"%s","os":"linux","arch":"%s","kernel":"%s",\n' \
    "$(jstr "$F_HOST")" "$(jstr "$F_ARCH")" "$(jstr "$F_KERNEL")"
  printf ' "kernel_build":{"distro_kernel":%s,"distro_name":%s,"build_date":%s,"source":%s},\n' \
    "$kb_distro" "$kb_name_j" "$kb_date_j" "$kb_src_j"
  printf ' "distro":{"id":"%s","version_id":"%s","codename":"%s","pretty":"%s"},\n' \
    "$(jstr "$F_DISTRO_ID")" "$(jstr "$F_DISTRO_VID")" "$(jstr "$F_DISTRO_CODENAME")" "$(jstr "$F_DISTRO_PRETTY")"
  if [ -z "$F_DEBIAN_VER" ]; then
    printf ' "debian_version":null,\n'
  else
    printf ' "debian_version":"%s",\n' "$(jstr "$F_DEBIAN_VER")"
  fi
  local name ver first=1
  printf ' "packages":{'
  while IFS=$'\t' read -r name ver; do
    [ -z "$name" ] && continue
    [ "$first" = 1 ] && first=0 || printf ','
    printf '"%s":"%s"' "$(jstr "$name")" "$(jstr "$ver")"
  done <<< "$F_PACKAGES"
  printf '},\n "in_container":%s}\n' "$container"
}

findings_json() {
  local id sev tier conf pub desc
  local kev_j esc_j bp_j poc_j first=1
  printf '  ['
  local sid
  for sid in $(sorted_ids); do
    [ "$first" = 1 ] && first=0 || printf ','
    kev_j=false; esc_j=false; bp_j=false
    [ "${M_KEV[$sid]}" = 1 ] && kev_j=true
    [ "${M_ESC[$sid]}" = 1 ] && esc_j=true
    [ "${M_BP[$sid]}" = 1 ] && bp_j=true
    sev="${M_SEV[$sid]}"
    printf '\n   {"id":"%s","score":%s,"severity":%s,"published":%s,"kev":%s,\n' \
      "$sid" "$(json_or_null "${M_SCORE[$sid]}")" \
      "$( [ -z "$sev" ] || [ "$sev" = "-" ] && printf null || printf '"%s"' "$(jstr "$sev")")" \
      "$( [ -z "${M_PUB[$sid]}" ] || [ "${M_PUB[$sid]}" = "-" ] && printf null || printf '"%s"' "$(jstr "${M_PUB[$sid]}")")" \
      "$kev_j"
    printf '    "matched_by":"%s","confidence":"%s","likely_backported":%s,"escape_class":%s,\n' \
      "${M_TIER[$sid]}" "${M_CONF[$sid]}" "$bp_j" "$esc_j"
    printf '    "matches":[%s],\n' "${M_MATCHES[$sid]}"
    desc="${META_BY_ID[$sid]-}"
    printf '    "description":"%s",\n' "$(jstr "$desc")"
    if [ -n "${POC_BY_ID[$sid]-}" ]; then
      poc_j="${POC_BY_ID[$sid]}"
      printf '    "has_poc":true,"pocs":[%s]}\n' "${poc_j%,}"
    else
      printf '    "has_poc":false,"pocs":[]}\n'
    fi
  done
  printf ']'
}

stats_json() {
  local id kev_n=0 bp_n=0 esc_n=0 k_n=0 p_n=0 ob_n=0 d_n=0
  local -A sev_count
  for id in "${MATCH_IDS[@]}"; do
    [ "${M_KEV[$id]}" = 1 ] && kev_n=$((kev_n+1))
    [ "${M_BP[$id]}" = 1 ] && bp_n=$((bp_n+1))
    [ "${M_ESC[$id]}" = 1 ] && esc_n=$((esc_n+1))
    case "${M_TIER[$id]}" in
      kernel) k_n=$((k_n+1)) ;; package) p_n=$((p_n+1)) ;;
      os_build) ob_n=$((ob_n+1)) ;; distro_pin) d_n=$((d_n+1)) ;;
    esac
    local s="${M_SEV[$id]}"
    [ -z "$s" ] || [ "$s" = "-" ] && s="N/A"
    sev_count[$s]=$(( ${sev_count[$s]-0} + 1 ))
  done
  printf '{"peas_total":%s,"cve_total":%s,"kev":%s,"backport_flagged":%s,"escape_flagged":%s,\n' \
    "$PEAS_TOTAL" "${#MATCH_IDS[@]}" "$kev_n" "$bp_n" "$esc_n"
  printf ' "by_tier":{"kernel":%s,"package":%s,"os_build":%s,"distro_pin":%s},\n' \
    "$k_n" "$p_n" "$ob_n" "$d_n"
  printf ' "by_severity":{'
  local first=1 s
  for s in "${!sev_count[@]}"; do
    [ "$first" = 1 ] && first=0 || printf ','
    printf '"%s":%s' "$(jstr "$s")" "${sev_count[$s]}"
  done
  printf '}}'  # } untuk by_severity, } untuk objek stats
}

peas_json() { # -> array findings, schema identik python (category,severity,title,detail,check)
  printf '  ['
  local i line first=1 first2
  for ((i = 0; i < PEAS_TOTAL; i++)); do
    [ "$first" = 1 ] && first=0 || printf ','
    printf '\n   {"category":"%s","severity":"%s","title":"%s","detail":' \
      "$(jstr "${P_CAT[$i]}")" "$(jstr "${P_SEV[$i]}")" "$(jstr "${P_TITLE[$i]}")"
    if [ "${P_DLIST[$i]}" = 1 ] && [ -n "${P_DETAIL[$i]}" ]; then
      first2=1
      printf '['
      while IFS= read -r line || [ -n "$line" ]; do
        [ "$first2" = 1 ] && first2=0 || printf ','
        printf '"%s"' "$(jstr "$line")"
      done <<< "${P_DETAIL[$i]}"
      printf ']'
    else
      printf '"%s"' "$(jstr "${P_DETAIL[$i]}")"
    fi
    printf ',"check":"%s"}' "$(jstr "${P_CHECK[$i]}")"
  done
  printf ']'
}

write_report() {
  local out_path="$REPORT_PATH" ts
  if [ -z "$out_path" ]; then
    ts=$(date +%Y%m%d-%H%M%S)
    out_path="./scan-report-${F_HOST}-${ts}.json"
    REPORT_PATH="$out_path"
  fi
  if [ ! -d "$(dirname "$out_path")" ]; then
    echo "[!] direktori report tidak ada: $(dirname "$out_path")" >&2
    exit 1
  fi
  {
    printf '{\n "scanner":{"version":"%s","impl":"%s","dataset_generated":"%s","cve_count":%s},\n' \
      "$SCANNER_VERSION" "$IMPL" "$DATASET_GEN" "$CVE_COUNT"
    printf ' "target":'
    facts_json
    printf ',\n "findings":{"peas":'
    peas_json
    printf ',"cve":'
    findings_json
    printf '},\n "stats":'
    stats_json
    printf '\n}\n'
  } > "$out_path"
}

# ======================================================================
# Konsol
# ======================================================================
paint() { printf '%s%s%s' "${2:-$C_R}" "$1" "$C_R"; }

print_report() {
  local sid n i
  printf '================ LPESCAN ================\n'
  printf '%s LPESCAN v%s — LPE scanner + CVE matcher %s\n' "$C_B" "$SCANNER_VERSION" "$C_R"
  printf '%s dataset: %s CVE (%s)%s\n' "$C_DIM" "$CVE_COUNT" "$DATASET_GEN" "$C_R"
  printf '\n[ TARGET ]\n'
  printf 'hostname  : %s\n' "$F_HOST"
  printf 'os/arch   : linux / %s\n' "$F_ARCH"
  printf 'kernel    : %s' "$F_KERNEL"
  local kb_flag kb_name kb_date kb_src
  IFS='|' read -r kb_flag kb_name kb_date kb_src <<< "$F_KERNEL_BUILD"
  if [ "$kb_flag" = 1 ]; then
    printf ' %s[distro-kernel: %s build %s]%s' "$C_DIM" "$kb_name" "${kb_date:0:10}" "$C_R"
  fi
  printf '\n'
  printf 'distro    : %s\n' "$F_DISTRO_PRETTY"
  local npkg=0
  [ -n "$F_PACKAGES" ] && npkg=$(printf '%s\n' "$F_PACKAGES" | grep -c $'\t')
  printf 'packages  : %s terpasang\n' "$npkg"
  if [ "$F_IN_CONTAINER" = 1 ]; then
    printf '%s container : YA (/.dockerenv/cgroup) — match [ESC] bisa menyentuh host%s\n' "$C_M" "$C_R"
  fi

  local kev_ids=() kev_n=0
  for sid in $(sorted_ids); do
    if [ "${M_KEV[$sid]}" = 1 ]; then kev_ids+=("$sid"); kev_n=$((kev_n+1)); fi
  done
  if [ "$kev_n" -gt 0 ]; then
    printf '\n%s[ !!! ] %s CVE KEV (known exploited) TERDETEKSI !!!%s\n' "$C_RB" "$kev_n" "$C_R"
    n=0
    for sid in "${kev_ids[@]}"; do
      [ "$n" -ge 10 ] && break
      printf '  %s (%s %s) — %s' "$sid" "${M_SEV[$sid]}" "${M_SCORE[$sid]}" "${M_TIER[$sid]}"
      [ "${M_BP[$sid]}" = 1 ] && printf ' %s[BP]%s' "$C_Y" "$C_R"
      printf '\n'
      n=$((n+1))
    done
  fi

  local k_n=0 p_n=0 ob_n=0 d_n=0
  for sid in "${MATCH_IDS[@]}"; do
    case "${M_TIER[$sid]}" in kernel) k_n=$((k_n+1)) ;; package) p_n=$((p_n+1)) ;;
      os_build) ob_n=$((ob_n+1)) ;; distro_pin) d_n=$((d_n+1)) ;; esac
  done
  printf '\n[ CVE MATCH ] %s CVE (by tier: kernel=%s, package=%s, os_build=%s, distro_pin=%s)\n' \
    "${#MATCH_IDS[@]}" "$k_n" "$p_n" "$ob_n" "$d_n"
  printf '    %s ID/SEV/KEV/TIER/KONSTRUKSI/TERPASANG%s\n' "$C_DIM" "$C_R"
  n=0
  for sid in $(sorted_ids); do
    [ "$n" -ge 40 ] && { printf '    %s... %s lagi (lihat file report)%s\n' "$C_DIM" "$((${#MATCH_IDS[@]}-40))" "$C_R"; break; }
    printf '    %s %s %s %s %s %s' "$sid" "${M_SEV[$sid]}" \
      "$([ "${M_KEV[$sid]}" = 1 ] && printf KEV || printf '   ')" \
      "${M_TIER[$sid]}" "${M_FIRST_CONST[$sid]}" "${M_FIRST_INST[$sid]}"
    [ -n "${POC_BY_ID[$sid]-}" ] && printf ' %s[PoC]%s' "$C_G" "$C_R"
    [ "${M_BP[$sid]}" = 1 ] && printf ' %s[BP]%s' "$C_Y" "$C_R"
    [ "${M_ESC[$sid]}" = 1 ] && printf ' %s[ESC]%s' "$C_M" "$C_R"
    printf '\n'
    n=$((n+1))
  done

  local bp_n=0
  for sid in "${MATCH_IDS[@]}"; do [ "${M_BP[$sid]}" = 1 ] && bp_n=$((bp_n+1)); done
  if [ "$bp_n" -gt 0 ]; then
    printf '\n%s[ i ] %s match di-flag [BP]: nomor ABI kernel distro tidak setara patch level upstream%s\n' "$C_DIM" "$bp_n" "$C_R"
    printf '%s      (CVE dipublikasikan >%s hari sebelum build date kernel — hampir pasti sudah%s\n' "$C_DIM" "$BACKPORT_GRACE_DAYS" "$C_R"
    printf '%s       di-backport distro; confidence turun ke possible. Verifikasi checker empiris.)%s\n' "$C_DIM" "$C_R"
  fi

  local esc_ids=() esc_n=0
  for sid in $(sorted_ids); do
    if [ "${M_ESC[$sid]}" = 1 ]; then esc_ids+=("$sid"); esc_n=$((esc_n+1)); fi
  done
  if [ "$esc_n" -gt 0 ]; then
    printf '\n%s[ ! ] %s match kelas container-escape (runc/containerd/kernel):' "$C_MB" "$esc_n"
    for sid in "${esc_ids[@]}"; do printf ' %s' "$sid"; done
    printf '%s\n' "$C_R"
    if [ "$F_IN_CONTAINER" = 1 ]; then
      printf '%s      Scanner berjalan DI DALAM container — match ini bisa menyentuh HOST.%s\n' "$C_MB" "$C_R"
      printf '%s      Verifikasi versi runtime host dari sisi host sebelum eksekusi PoC.%s\n' "$C_MB" "$C_R"
    else
      printf '%s      Relevan bila host ini menjalankan container (runc/containerd/buildkit).%s\n' "$C_M" "$C_R"
    fi
  fi

  printf '\n%s[ PEAS CHECKS ] %s temuan%s\n' "$C_B" "$PEAS_TOTAL" "$C_R"
  local -A cat_tot
  local i cur_cat="" cat_n=0 shown=0 line dstr sev scol
  for ((i = 0; i < PEAS_TOTAL; i++)); do
    cat_tot[${P_CAT[$i]}]=$(( ${cat_tot[${P_CAT[$i]}]-0} + 1 ))
  done
  for ((i = 0; i < PEAS_TOTAL; i++)); do
    if [ "${P_CAT[$i]}" != "$cur_cat" ]; then
      if [ -n "$cur_cat" ] && [ "$shown" -lt "$cat_n" ]; then
        printf '      %s... %s lagi (lihat file report)%s\n' "$C_DIM" "$((cat_n-shown))" "$C_R"
      fi
      cur_cat="${P_CAT[$i]}"
      cat_n=$((cat_tot[$cur_cat])); shown=0
      printf '  %s--- %s (%s) ---%s\n' "$C_B" "$cur_cat" "$cat_n" "$C_R"
    fi
    [ "$shown" -lt 15 ] || continue
    shown=$((shown+1))
    sev="${P_SEV[$i]}"
    case "$sev" in
      CRITICAL) scol=$S_CRIT ;; HIGH) scol=$S_HIGH ;; MEDIUM) scol=$S_MED ;;
      LOW) scol=$S_LOW ;; INFO) scol=$S_INFO ;; *) scol=$C_R ;;
    esac
    printf '    %s[%-7s]%s %s\n' "$scol" "$sev" "$C_R" "${P_TITLE[$i]}"
    if [ -n "${P_DETAIL[$i]}" ]; then
      if [ "${P_DLIST[$i]}" = 1 ]; then
        dstr=""
        while IFS= read -r line || [ -n "$line" ]; do
          [ -n "$dstr" ] && dstr="$dstr ; "
          dstr="$dstr$line"
        done <<< "${P_DETAIL[$i]}"
        printf '      %s%s%s\n' "$C_DIM" "${dstr:0:200}" "$C_R"
      else
        printf '      %s%s%s\n' "$C_DIM" "${P_DETAIL[$i]:0:200}" "$C_R"
      fi
    fi
  done
  if [ -n "$cur_cat" ] && [ "$shown" -lt "$cat_n" ]; then
    printf '      %s... %s lagi (lihat file report)%s\n' "$C_DIM" "$((cat_n-shown))" "$C_R"
  fi
  printf '%sScanner hanya mendeteksi — TIDAK mengeksekusi PoC%s\n' "$C_DIM" "$C_R"
  printf '%sJalankan buildkit.py --report %s di mesin arsip%s\n' "$C_DIM" "$REPORT_PATH" "$C_R"
}

# ======================================================================
# Selftest
# ======================================================================
selftest() {
  local ok=0 fail=0 name cond
  chk() {
    if [ "$2" = 1 ]; then ok=$((ok+1)); printf '  [OK]   %s\n' "$1"
    else fail=$((fail+1)); printf '  [FAIL] %s %s\n' "$1" "${3:-}"; fi
  }

  mkrow() { # id cpe raw op1 v1 n1 op2 v2 n2 op3 v3 n3 [kev esc] — arg hilang jadi "-"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$1" "2022-01-01" "7.0" "HIGH" "${13:-0}" "${14:-0}" "linux" "$2" "$3" \
      "${4:--}" "${5:--}" "${6:--}" "${7:--}" "${8:--}" "${9:--}" "${10:--}" "${11:--}" "${12:--}"
  }
  engine_test() { # $1=line $2=cands $3=mode $4=bd $5=skipall -> baris hasil
    printf '%s\n' "$1" | awk -F'\t' -v cands="$2" -v MODE="$3" -v BD="${4:--}" \
      -v GRACE="$BACKPORT_GRACE_DAYS" -v SKIPALL="${5:-0}" "$AWK_LIB$AWK_EVAL"
  }
  has_out() { [ -n "$(engine_test "$1" "$2" "$3" "$4" "$5")" ]; }

  printf '[*] selftest version engine...\n'
  local row
  row=$(mkrow T1 "linux:linux_kernel" "linux:linux_kernel [>=3.15 <5.15.149]" ">=" "3.15" "3 15" "<" "5.15.149" "5 15 149")
  chk "kernel 5.15.0-72 match" "$(has_out "$row" "5.15.0-72-generic" n - 0 && echo 1 || echo 0)"
  chk "kernel 5.15.149 tidak match" "$(has_out "$row" "5.15.149" n - 0 && echo 0 || echo 1)"
  row=$(mkrow T2 "linux:linux_kernel" "linux:linux_kernel [6.8]" "EXACT" "6.8" "6 8" "-" "-" "-")
  chk "kernel 6.8.0 match pin" "$(has_out "$row" "6.8.0-generic" n - 0 && echo 1 || echo 0)"
  chk "kernel 6.9 tidak match pin" "$(has_out "$row" "6.9" n - 0 && echo 0 || echo 1)"
  row=$(mkrow T3 "todd_miller:sudo" "todd_miller:sudo [<1.9.5p2]" "<" "1.9.5p2" "-" "-" "-" "-")
  chk "sudo 1.9.5p1 match" "$(has_out "$row" "1.9.5p1" t - 0 && echo 1 || echo 0)"
  chk "sudo 1.9.5p2 tidak match" "$(has_out "$row" "1.9.5p2" t - 0 && echo 0 || echo 1)"
  row=$(mkrow T4 "todd_miller:sudo" "todd_miller:sudo [1.6.3_p7]" "EXACT" "1.6.3_p7" "-" "-" "-" "-")
  chk "sudo 1.6.3_p7 exact match" "$(has_out "$row" "1.6.3_p7" t - 0 && echo 1 || echo 0)"
  chk "sudo 1.6.3 exact TIDAK match" "$(has_out "$row" "1.6.3" t - 0 && echo 0 || echo 1)"
  row=$(mkrow T5 "litespeedtech:litespeed_cpanel_plugin" "litespeedtech:litespeed_cpanel_plugin [<5.3.1.0]" "<" "5.3.1.0" "-" "-" "-" "-")
  chk "5.3.1 match <5.3.1.0" "$(has_out "$row" "5.3.1" t - 0 && echo 1 || echo 0)"
  row=$(mkrow T6 "microsoft:windows_11_23h2" "microsoft:windows_11_23h2 [<10.0.22631.4751]" "<" "10.0.22631.4751" "10 0 22631 4751" "-" "-" "-")
  chk "build 22631.3447 match" "$(has_out "$row" "10.0.22631.3447" n - 0 && echo 1 || echo 0)"
  chk "build 22631.4751 tidak match" "$(has_out "$row" "10.0.22631.4751" n - 0 && echo 0 || echo 1)"
  row=$(mkrow T7 "notepad-plus-plus:notepad++" "notepad-plus-plus:notepad++ [>=8.9.4 <8.9.6]" ">=" "8.9.4" "-" "<" "8.9.6" "-")
  chk "8.9.5 match escaped range" "$(has_out "$row" "8.9.5" t - 0 && echo 1 || echo 0)"
  row=$(mkrow T8 "canonical:ubuntu_linux" "canonical:ubuntu_linux [20.04]" "EXACT" "20.04" "20 4" "-" "-" "-")
  chk "distro pin ubuntu 20.04 match" "$(has_out "$row" "20.04" n - 1 && echo 1 || echo 0)"
  row=$(mkrow T9 "debian:debian_linux" "debian:debian_linux [10.0]" "EXACT" "10.0" "10" "-" "-" "-")
  chk "debian 10 == 10.0" "$(has_out "$row" "10" n - 1 && echo 1 || echo 0)"
  row=$(mkrow T10 "redhat:enterprise_linux_server" "redhat:enterprise_linux_server [7.0_s390x]" "EXACT" "7.0_s390x" "7" "-" "-" "-")
  chk "rhel pin arch suffix match" "$(has_out "$row" "7.0" n - 1 && echo 1 || echo 0)"
  local c1 c2
  c1=$(printf 'x\n' | awk -v a="1.6.3" -v b="1.6.3_p7" "$AWK_LIB"$'\n'"BEGIN{print cmpv(toks(a), toks(b))}")
  chk "cmp 1.6.3 < 1.6.3_p7" "$([ "$c1" = "-1" ] && echo 1 || echo 0)" "got=$c1"
  c2=$(printf 'x\n' | awk -v a="1.9.5" -v b="1.9.5p2" "$AWK_LIB"$'\n'"BEGIN{print cmpv(toks(a), toks(b))}")
  chk "cmp 1.9.5 < 1.9.5p2" "$([ "$c2" = "-1" ] && echo 1 || echo 0)" "got=$c2"
  chk "candidate rev strip" "$(printf '%s\n' "$(candidate_versions "2.0-1ubuntu2")" | grep -qx "2.0" && echo 1 || echo 0)"
  chk "candidate epoch strip" "$(printf '%s\n' "$(candidate_versions "1:1.9.5-2")" | grep -qx "1.9.5" && echo 1 || echo 0)"

  printf '[*] selftest distro-kernel / backport...\n'
  local kb bd
  kb=$(kernel_build_info "5.15.0-191-generic" \
    "Linux version 5.15.0-191-generic (buildd@lcy02-amd64-091) (gcc (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0) #201-Ubuntu SMP Fri Aug 7 18:39:04 UTC 2026")
  chk "distro kernel ubuntu terdeteksi" "$([ "${kb%%|*}" = 1 ] && [[ "$kb" == *"|ubuntu|"* ]] && echo 1 || echo 0)" "got=$kb"
  bd=$(parse_proc_version_date "Linux version 5.15.0-191-generic (buildd@lcy02-amd64-091) (gcc (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0) #201-Ubuntu SMP Fri Aug 7 18:39:04 UTC 2026")
  chk "build date terparse" "$([ "$bd" = "2026-08-07 18:39:04" ] && echo 1 || echo 0)" "got=$bd"
  chk "kernel vanilla bukan distro" "$([ "$(kernel_build_info "5.15.191" "" | cut -d'|' -f1)" = 0 ] && echo 1 || echo 0)"
  local kb3
  kb3=$(kernel_build_info "7.1.5+kali-amd64" \
    "Linux version 7.1.5+kali-amd64 (root@kali) (gcc-14 (Debian 14.2.0-19) 14.2.0) #1 SMP PREEMPT_DYNAMIC Tue Sep 22 12:00:00 UTC 2026")
  chk "suffix +kali terdeteksi" "$([ "${kb3%%|*}" = 1 ] && [[ "$kb3" == *"|kali|"* ]] && echo 1 || echo 0)" "got=$kb3"
  chk "backport: lama -> True" "$([ "$(likely_backported "2022-03-07" "2026-08-07 00:00:00")" = 1 ] && echo 1 || echo 0)"
  bd=$(parse_proc_version_date "Linux version 7.1.5+kali-amd64 (devel@kali.org) #1 SMP PREEMPT_DYNAMIC Kali 7.1.5-1kali1 (2026-07-29)")
  chk "format tanggal debian/kali terparse" "$([ "$bd" = "2026-07-29 00:00:00" ] && echo 1 || echo 0)" "got=$bd"
  chk "backport: dekat build -> False" "$([ "$(likely_backported "2026-08-01" "2026-08-07 00:00:00")" = 0 ] && echo 1 || echo 0)"
  chk "backport: tanggal hilang -> False" "$([ "$(likely_backported "" "-")" = 0 ] && [ "$(likely_backported "2022-01-01" "-")" = 0 ] && echo 1 || echo 0)"

  printf '[*] selftest container-escape...\n'
  chk "_in_container deterministik (host dev = False)" "$([ "$(in_container)" = 0 ] && echo 1 || echo 0)"
  # simulasi alur penuh: record escape + facts container (kernel vanilla, kb off)
  local tmpfile
  tmpfile=$(mktemp /tmp/lpescan-selftest.XXXXXX)
  row=$(mkrow CVE-TEST-ESC "linux:linux_kernel" "linux:linux_kernel [>=3.0 <11.0]" ">=" "3.0" "3" "<" "11.0" "11" "-" "-" "-" 0 1)
  printf '%s\n' "$row" > "$tmpfile"
  ROWS_BY_CPE=()
  while IFS=$'\t' read -r cpe line; do ROWS_BY_CPE[$cpe]+="$line"$'\n'; done < <(awk -F'\t' '{print $8"\t"$0}' "$tmpfile")
  F_KERNEL="5.10.0-generic" F_KERNEL_BUILD="0|-|-|-"
  MATCH_IDS=(); M_TIER=(); M_CONF=(); M_RANK=(); M_KEV=(); M_ESC=(); M_BP=()
  M_SCORE=(); M_SEV=(); M_PUB=(); M_MATCHES=(); M_FIRST_CONST=(); M_FIRST_INST=()
  match_kernel
  chk "match di dalam container membawa escape_class" \
    "$([ "${M_ESC[CVE-TEST-ESC]-0}" = 1 ] && echo 1 || echo 0)"
  chk "cve non-escape tanpa flag escape_class" \
    "$([ -z "${M_ESC[CVE-TEST-NO]+x}" ] && echo 1 || echo 0)"
  rm -f "$tmpfile"

  printf '\n[*] selftest selesai: %s OK, %s FAIL\n' "$ok" "$fail"
  [ "$fail" = 0 ]
}

# ======================================================================
# Main
# ======================================================================
main() {
  if [ "$DO_SELFTEST" = 1 ]; then
    selftest && exit 0 || exit 1
  fi
  load_data
  if [ "$JSON_ONLY" = 0 ]; then
    printf '[*] dataset: %s CVE (%s) — impl %s\n' "$CVE_COUNT" "$DATASET_GEN" "$IMPL"
  fi
  collect_facts_linux
  if [ "$JSON_ONLY" = 0 ]; then
    printf '[*] facts: kernel %s, %s paket terpasang\n' "$F_KERNEL" \
      "$(printf '%s\n' "$F_PACKAGES" | grep -c $'\t')"
  fi
  match_cves
  if [ "$JSON_ONLY" = 0 ]; then
    printf '[*] CVE match: %s\n' "${#MATCH_IDS[@]}"
  fi
  load_desc_pocs
  run_peas
  write_report
  if [ "$JSON_ONLY" = 0 ]; then
    print_report
    printf '\n'
  fi
  printf '[+] report tersimpan: %s\n' "$REPORT_PATH"
}

main

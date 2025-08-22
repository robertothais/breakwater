#!/usr/bin/env bash
# package_analyze.sh
# Static analysis for already-unpacked package payload and metadata.
# Works on a standard Debian/Ubuntu environment.

set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <payload-dir> <meta-dir> <outdir>"
  exit 1
fi

PAYLOAD="$1"
META="$2"
OUT="${3%/}"

# ---- deps check --------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || {
  echo "Missing: $1"
  exit 1
}; }
for c in file readelf objdump nm strings grep awk sed sha256sum sort uniq; do need "$c"; done

mkdir -p "$OUT"

# ---- basic metadata ----------------------------------------------------------
echo "[*] Writing metadata…"
{
  echo "=== CONTROL ==="
  [[ -f "$META/control" ]] && cat "$META/control"
  echo
  echo "=== MAINTAINER SCRIPTS ==="
  for s in postinst postrm preinst prerm; do
    if [[ -f "$META/$s" ]]; then
      echo "--- $s ---"
      sed -n '1,400p' "$META/$s"
      echo
    fi
  done
} >"$OUT/control_and_scripts.txt"

# ---- file inventory ----------------------------------------------------------
echo "[*] Indexing files…"
(cd "$PAYLOAD" && find . -xdev -printf '%y %m %u %g %s %p\n' | sort) >"$OUT/file_list.txt"

echo "[*] Scanning shebangs…"
(cd "$PAYLOAD" && grep -IRn --binary-files=without-match -m1 -E '^#!' . || true) >"$OUT/shebangs.txt"

# ---- ELF discovery -----------------------------------------------------------
echo "[*] Detecting ELF files (filtering Qt libraries)…"
ELF_LIST="$OUT/elves.txt"
: >"$ELF_LIST"
while IFS= read -r -d '' f; do
  if file -b "$f" | grep -q 'ELF'; then
    rel="${f#$PAYLOAD/}"

    # Filter out Qt libraries and plugins to reduce noise
    if [[ "$rel" =~ /Qt/lib/|/Qt/plugins/|libQt[0-9] ]]; then
      echo "[*] Skipping Qt library: $(basename "$rel")" >&2
      continue
    fi

    echo "$rel" >>"$ELF_LIST"
  fi
done < <(find "$PAYLOAD" -type f -print0)

# ---- ELF details (arch, interpreter, DT_NEEDED) ------------------------------
echo "[*] Extracting ELF details…"
ELF_REPORT="$OUT/elf_report.txt"
: >"$ELF_REPORT"
while read -r rel; do
  abs="$PAYLOAD/$rel"
  echo "### $rel" >>"$ELF_REPORT"
  file "$abs" >>"$ELF_REPORT" || true
  readelf -l "$abs" 2>/dev/null | awk '/Requesting program interpreter/ {print}' >>"$ELF_REPORT" || true
  readelf -d "$abs" 2>/dev/null | awk '/NEEDED/ {print}' >>"$ELF_REPORT" || true
  echo >>"$ELF_REPORT"
done <"$ELF_LIST"

# ---- deps (static: readelf/objdump; never executes binaries) ------------------
echo "[*] Collecting shared-library deps statically…"

deps_dump() {
  local f="$1"
  if command -v readelf >/dev/null 2>&1; then
    # Dynamic section (NEEDED, RPATH/RUNPATH) and interpreter from program headers
    {
      readelf -l "$f" 2>/dev/null | awk '/Requesting program interpreter|Interpreter/{print}'
      readelf -d "$f" 2>/dev/null | awk '
        /\(NEEDED\)/   {print}
        /\(RPATH\)/    {print}
        /\(RUNPATH\)/  {print}
        /\(SONAME\)/   {print}
      '
    }
  elif command -v objdump >/dev/null 2>&1; then
    objdump -p "$f" 2>/dev/null | awk '
      /^ *INTERP/   {print}
      /^ *NEEDED/   {print}
      /^ *RPATH/    {print}
      /^ *RUNPATH/  {print}
      /^ *SONAME/   {print}
    '
  else
    echo "[!] Neither readelf nor objdump found." >&2
    return 127
  fi
}

{
  while read -r rel; do
    abs="$PAYLOAD/$rel"
    echo "### $rel"
    # Only attempt on ELF files
    if file -b "$abs" | grep -qi 'ELF'; then
      deps_dump "$abs" || echo "[!] Failed to parse: $rel"
    else
      echo "[skip] Not an ELF: $rel"
    fi
    echo
  done <"$ELF_LIST"
} >"$OUT/ldd_report.txt"

# ---- symbols/imports (glibc calls as syscall proxies) ------------------------
echo "[*] Enumerating imported symbols (nm/readelf)…"
SYM_DIR="$OUT/elf_symbols"
mkdir -p "$SYM_DIR"
SYSCALL_CANDIDATES='(uname|getauxval|sysinfo|ioctl|ptrace|personality|prctl|seccomp|setcap|cap_|socket|connect|bind|listen|accept|getpeername|getsockname|getsockopt|setsockopt|send|sendto|recv|recvfrom|open|openat|mount|umount|reboot|epoll|inotify|eventfd|keyctl|add_key|request_key|finit_module|init_module|delete_module)'

while read -r rel; do
  abs="$PAYLOAD/$rel"
  base="$(echo "$rel" | tr '/' '_')"
  {
    echo "### $rel"
    echo "-- Dynamic symbols (nm -D):"
    nm -D --defined-only "$abs" 2>/dev/null | sort || true
    echo
    echo "-- All symbols (readelf -Ws, filtered):"
    readelf -Ws "$abs" 2>/dev/null | sed '1,3d' | sort || true
  } >"$SYM_DIR/${base}.symbols.txt"

  # Pull likely syscall-proxy funcs it imports
  {
    echo "### $rel"
    echo "-- Imported libc-ish calls likely to hit syscalls:"
    (
      nm -D "$abs" 2>/dev/null
      readelf -Ws "$abs" 2>/dev/null
    ) |
      grep -E "$SYSCALL_CANDIDATES" |
      sort -u || true
  } >"$SYM_DIR/${base}.syscall_candidates.txt"
done <"$ELF_LIST"

# ---- disasm heuristics to spot ioctl numbers etc. ----------------------------
echo "[*] Disassembling select patterns (objdump)…"
DIS_DIR="$OUT/elf_disasm_greps"
mkdir -p "$DIS_DIR"
# Heuristics: SIOCETHTOOL (0x8946), common HDIO (0x03xx… unreliable), NETLINK, prctl/ptrace inline syscalls.
HEX_HINTS='0x8946|0x89[0-9a-fA-F][0-9a-fA-F]' # keep broad for ethtool-like
TEXT_HINTS='SIOCETHTOOL|ETHTOOL_|HDIO_|/dev/input|/dev/uinput|/dev/net|netlink|AF_NETLINK|IPTables|conntrack'

while read -r rel; do
  abs="$PAYLOAD/$rel"
  base="$(echo "$rel" | tr '/' '_')"
  {
    echo "### $rel"
    echo "-- objdump -d | grep (hex hints):"
    objdump -d "$abs" 2>/dev/null | grep -E "$HEX_HINTS" -n || true
    echo
    echo "-- strings (TEXT_HINTS):"
    strings -a "$abs" | grep -E "$TEXT_HINTS" -n || true
  } >"$DIS_DIR/${base}.greps.txt"
done <"$ELF_LIST"

# ---- indicator greps across whole payload -----------------------------------
echo "[*] Grepping payload for indicators…"
join_outputs() {
  local title="$1"
  shift
  echo "=== $title ==="
  if [[ $# -gt 0 ]]; then
    grep -RIn --binary-files=without-match -E "$*" "$PAYLOAD" 2>/dev/null || true
  fi
  echo
}

{
  join_outputs "/dev nodes" '/dev/[a-zA-Z0-9/_-]+'
  join_outputs "/proc usage" '/proc/[a-zA-Z0-9/_-]+'
  join_outputs "/sys usage" '/sys/[a-zA-Z0-9/_-]+'
  join_outputs "modprobe/insmod" '(^|[^a-zA-Z])(modprobe|insmod)($|[^a-zA-Z])'
  join_outputs "helpers: ethtool/hdparm/cpuid" '(^|[^a-zA-Z])(ethtool|hdparm|cpuid)($|[^a-zA-Z])'
  join_outputs "iptables/nft/conntrack" '(^|[^a-zA-Z])(iptables|nft|conntrack)($|[^a-zA-Z])'
  join_outputs "netlink/libnf*" 'libnetfilter|libnfnetlink|NETLINK_'
  join_outputs "VM detection strings" 'QEMU|KVM|VMware|VirtualBox|Parallels|Hyper-V|Xen|Bochs|Virtual CPU|VBOX'
  join_outputs "DMI/sysinfo" '(/sys/class/dmi/id|DMI|dmidecode)'
  join_outputs "DBus/socket hints" 'dbus|/run/|/var/run/|\.sock|AF_UNIX|127\.0\.0\.1|localhost'
  join_outputs "Executables referenced" '(/sbin/|/bin/|/usr/sbin/|/usr/bin/)[a-zA-Z0-9._+-]+'
  join_outputs "Process spawn APIs" 'system\(|popen\(|execv|execve|execl|posix_spawn'
} >"$OUT/indicators_grep.txt"

# ---- URLs --------------------------------------------------------------------
echo "[*] Extracting URLs…"
{
  # Search text files (without binary data)
  grep -RIn --binary-files=without-match -E 'https?://[a-zA-Z0-9._~:/?#@!$&()*+,;=-]+' "$PAYLOAD" 2>/dev/null || true
  
  # Search ALL binary files using strings (including ELF, data files, archives)
  echo "=== URLs from binary files ==="
  find "$PAYLOAD" -type f -exec file {} \; | grep -vE "(text|empty)" | cut -d: -f1 | while read -r binary_file; do
    if [[ -f "$binary_file" ]]; then
      rel="${binary_file#$PAYLOAD/}"
      strings "$binary_file" 2>/dev/null | grep -E 'https?://[a-zA-Z0-9._~:/?#@!$&()*+,;=-]+' | sed "s|^|$rel:|" || true
    fi
  done
} | sort -u >"$OUT/urls.txt"

# ---- crypto/key analysis ----------------------------------------------------
echo "[*] Analyzing cryptographic patterns..."
CRYPTO_DIR="$OUT/crypto_analysis"
mkdir -p "$CRYPTO_DIR"

# High entropy file detection (potential encrypted data)
echo "[*] Detecting high-entropy files (encrypted data)..."
{
  while IFS= read -r -d '' f; do
    rel="${f#$PAYLOAD/}"
    if file -b "$f" | grep -q "data"; then
      # Simple entropy check using strings density
      total_bytes=$(wc -c < "$f" 2>/dev/null || echo 0)
      if [[ $total_bytes -gt 100 && $total_bytes -lt 10485760 ]]; then # 100B to 10MB
        printable_ratio=$(strings "$f" | wc -c)
        if [[ $total_bytes -gt 0 ]]; then
          ratio=$((printable_ratio * 100 / total_bytes))
          if [[ $ratio -lt 20 ]]; then # Less than 20% printable = likely encrypted
            echo "$rel: size=$total_bytes, printable_ratio=${ratio}% (likely encrypted/binary)"
          fi
        fi
      fi
    fi
  done < <(find "$PAYLOAD" -type f -size +100c -size -10M -print0)
} >"$CRYPTO_DIR/high_entropy_files.txt"

# Crypto constants and algorithm patterns
echo "[*] Searching for cryptographic indicators..."
{
  echo "=== CRYPTO CONSTANTS ==="
  # AES S-box constant (first 16 bytes)
  grep -r "637c777bf26b6fc53001672bfed7ab76" "$PAYLOAD" 2>/dev/null || true
  # Common RSA public exponent 65537 (0x010001)
  grep -r "010001" "$PAYLOAD" 2>/dev/null | head -10 || true
  echo
  
  echo "=== PEM BLOCKS ==="
  grep -r "BEGIN.*PRIVATE KEY\|BEGIN.*PUBLIC KEY\|BEGIN CERTIFICATE" "$PAYLOAD" 2>/dev/null || true
  echo
  
  echo "=== CRYPTO ALGORITHM REFERENCES ==="
  grep -ri "\b(aes|des|rsa|dsa|ecdsa|sha1|sha256|sha512|md5|pbkdf|scrypt|bcrypt|hmac|ssl|tls)\b" "$PAYLOAD" 2>/dev/null | head -30 || true
  echo
  
  echo "=== OPENSSL FUNCTION CALLS ==="
  grep -r "SSL_\|EVP_\|RSA_\|AES_\|CRYPTO_" "$PAYLOAD" 2>/dev/null | head -20 || true
} >"$CRYPTO_DIR/crypto_patterns.txt"

# Key extraction from binaries
echo "[*] Extracting potential keys from binaries..."
while read -r rel; do
  abs="$PAYLOAD/$rel"
  base="$(echo "$rel" | tr '/' '_')"
  
  {
    echo "### $rel"
    echo "-- Potential base64 keys (32+ chars):"
    strings "$abs" | grep -E '^[A-Za-z0-9+/]{32,}={0,2}$' | head -10 || true
    echo
    
    echo "-- Potential hex keys (32+ hex chars):"
    strings "$abs" | grep -E '^[0-9a-fA-F]{32,}$' | head -10 || true
    echo
    
    echo "-- Certificate/key markers:"
    strings "$abs" | grep -E "(BEGIN|END).*(KEY|CERT)" || true
    echo
    
    echo "-- Crypto library calls:"
    strings "$abs" | grep -E "(SSL_|EVP_|RSA_|AES_|CRYPTO_|OpenSSL)" | head -10 || true
  } >"$CRYPTO_DIR/${base}_keys.txt"
done <"$ELF_LIST"

# Configuration file analysis (encrypted configs)
echo "[*] Analyzing configuration files for encryption..."
{
  echo "=== CONFIGURATION FILES ==="
  find "$PAYLOAD" -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.xml" | while read -r conf_file; do
    rel="${conf_file#$PAYLOAD/}"
    echo "### $rel"
    
    # Check if file appears to be encrypted (low printable ratio)
    total_bytes=$(wc -c < "$conf_file" 2>/dev/null || echo 0)
    if [[ $total_bytes -gt 10 ]]; then
      printable_count=$(strings "$conf_file" | wc -c)
      ratio=$((printable_count * 100 / total_bytes))
      echo "Size: ${total_bytes}B, Printable: ${ratio}%"
      
      if [[ $ratio -lt 30 ]]; then
        echo "*** POTENTIALLY ENCRYPTED CONFIG ***"
        echo "First 64 bytes (hex):"
        xxd -l 64 "$conf_file" 2>/dev/null || od -x -N 64 "$conf_file" 2>/dev/null || true
      else
        echo "Plaintext config - showing key-related lines:"
        grep -i "key\|password\|secret\|encrypt\|decrypt\|cipher" "$conf_file" 2>/dev/null | head -5 || true
      fi
    fi
    echo
  done
} >"$CRYPTO_DIR/config_analysis.txt"

# ---- hashes ------------------------------------------------------------------
echo "[*] Hashing payload files…"
(cd "$PAYLOAD" && find . -type f -exec sha256sum {} + | sort) >"$OUT/sha256s.txt"

# ---- quick insights summary --------------------------------------------------
echo "[*] Writing quick summary…"
{
  echo "Package: $(awk '/^Package:/ {print $2}' "$META/control" 2>/dev/null)"
  echo "Version: $(awk '/^Version:/ {print $2}' "$META/control" 2>/dev/null)"
  echo "Architecture: $(awk '/^Architecture:/ {print $2}' "$META/control" 2>/dev/null)"
  echo
  echo "Total files: $(wc -l <"$OUT/file_list.txt" 2>/dev/null || echo 0)"
  echo "ELF binaries: $(wc -l <"$ELF_LIST" 2>/dev/null || echo 0)"
  echo
  echo "Top-level dirs:"
  (cd "$PAYLOAD" && du -sh * 2>/dev/null | sort -h)
} >"$OUT/summary.txt"

# ---- high-level insights aggregator -----------------------------------------
echo "[*] Aggregating high-level insights…"
INS="$OUT/insights.txt"
{
  echo "=== High-Level Insights ==="
  echo
  echo "- Likely kernel-surface usage (from symbols):"
  grep -E "$SYSCALL_CANDIDATES" -R "$SYM_DIR" --include="*.syscall_candidates.txt" | sed 's|.*/||' | sort -u || true
  echo
  echo "- Potential ethtool/ioctl references (disasm/strings hints):"
  grep -R "0x8946\|ETHTOOL" "$DIS_DIR" 2>/dev/null | sed 's|.*/||' | sort -u || true
  echo
  echo "- References to /dev, /proc, /sys (payload grep):"
  grep -E '(/dev/|/proc/|/sys/)' "$OUT/indicators_grep.txt" | sed 's|^[^:]*:||' | head -n 200 || true
  echo
  echo "- VM-detection strings:"
  grep -E 'QEMU|KVM|VMware|VirtualBox|Parallels|Hyper-V|Xen|Bochs|Virtual CPU|VBOX' "$OUT/indicators_grep.txt" || true
  echo
  echo "- DBus / socket hints:"
  grep -E 'dbus|/run/|/var/run/|\.sock|127\.0\.0\.1|localhost' "$OUT/indicators_grep.txt" | head -n 100 || true
  echo
  echo "- External helpers referenced:"
  grep -E '(/sbin/|/bin/|/usr/sbin/|/usr/bin/)[a-zA-Z0-9._+-]+' "$OUT/indicators_grep.txt" | sort -u | head -n 200 || true
  echo
  echo "- URLs found:"
  head -n 100 "$OUT/urls.txt" 2>/dev/null || true
  echo
  echo "- Cryptographic patterns found:"
  crypto_files=$(ls "$CRYPTO_DIR"/*.txt 2>/dev/null | wc -l || echo "0")
  echo "  Crypto analysis files: $crypto_files"
  
  # Count high-entropy files
  entropy_count=$(grep -c "likely encrypted" "$CRYPTO_DIR/high_entropy_files.txt" 2>/dev/null || echo "0")
  echo "  High-entropy (encrypted) files: $entropy_count"
  
  # Count potential keys found
  key_count=$(grep -c "^[A-Za-z0-9+/]\{32,\}" "$CRYPTO_DIR"/*_keys.txt 2>/dev/null || echo "0")
  echo "  Potential keys found: $key_count"
  
  # Count PEM blocks
  pem_count=$(grep -c "BEGIN.*KEY\|BEGIN CERTIFICATE" "$CRYPTO_DIR/crypto_patterns.txt" 2>/dev/null || echo "0")
  echo "  PEM certificates/keys: $pem_count"
  
  echo
  echo "- Encrypted configuration files:"
  grep "POTENTIALLY ENCRYPTED" "$CRYPTO_DIR/config_analysis.txt" 2>/dev/null | head -5 || echo "  None detected"
} >"$INS"

echo "[+] Done. Report dir: $OUT"
echo "    - summary.txt"
echo "    - control_and_scripts.txt"
echo "    - file_list.txt"
echo "    - shebangs.txt"
echo "    - elves.txt"
echo "    - elf_report.txt"
echo "    - ldd_report.txt"
echo "    - elf_symbols/*.symbols.txt"
echo "    - elf_symbols/*.syscall_candidates.txt"
echo "    - elf_disasm_greps/*.greps.txt"
echo "    - indicators_grep.txt"
echo "    - urls.txt"
echo "    - sha256s.txt"
echo "    - crypto_analysis/high_entropy_files.txt"
echo "    - crypto_analysis/crypto_patterns.txt"
echo "    - crypto_analysis/*_keys.txt"
echo "    - crypto_analysis/config_analysis.txt"
echo "    - insights.txt"

# ---- Analysis summary --------------------------------------------------------
QT_FILTERED=$(find "$PAYLOAD" -type f -name "*Qt*" -o -path "*/Qt/*" | wc -l)
ANALYZED_ELFS=$(wc -l <"$ELF_LIST")

echo
echo "[*] Analysis complete!"
echo "[*] Qt libraries filtered: $QT_FILTERED"
echo "[*] Core ELF files analyzed: $ANALYZED_ELFS"

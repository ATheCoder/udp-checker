#!/usr/bin/env bash
# check-udp443.sh
set -euo pipefail

###############################################################################
# CLI ­­­­­parsing
###############################################################################
ALL=0
usage() {
  cat <<EOF
Usage: $0 [-a] [cidr_file]

  -a, --all    Probe every host in each CIDR instead of one random host.
  -h, --help   Show this help and exit.

If cidr_file is omitted, ./ip.txt is assumed.  One CIDR per line; blank lines
and lines beginning with # are ignored.
EOF
}

# basic long-option handling
for arg in "$@"; do
  [[ $arg == "--all" ]]  && set -- "${@/--all/-a}"
  [[ $arg == "--help" ]] && set -- "${@/--help/-h}"
done

while getopts ":ah" opt; do
  case $opt in
    a) ALL=1 ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 1 ;;
  esac
done
shift $((OPTIND-1))

###############################################################################
# Config
###############################################################################
INFILE=${1:-ip.txt}                                   # path to the CIDR list
NPING_CMD=${NPING_CMD:-"sudo nping --udp -c 1 -p 443"}

command -v nping >/dev/null 2>&1 || {
  echo "nping not found; install nmap-nping first." >&2
  exit 1
}

###############################################################################
# Helpers
###############################################################################
# print all usable hosts (one per line) for a CIDR passed on stdin
all_hosts_py='
import ipaddress, sys, itertools, textwrap
net = ipaddress.ip_network(sys.stdin.read().strip(), strict=False)
hosts = list(net.hosts()) or [net.network_address]
for h in hosts:
    print(h)
'

# print a single random host for a CIDR passed on stdin
rand_host_py='
import ipaddress, random, sys
net = ipaddress.ip_network(sys.stdin.read().strip(), strict=False)
hosts = list(net.hosts()) or [net.network_address]
print(random.choice(hosts))
'

###############################################################################
# Main loop
###############################################################################
while IFS= read -r cidr || [[ -n $cidr ]]; do
  [[ -z $cidr || $cidr =~ ^# ]] && continue           # skip blanks / comments

  if (( ALL )); then
    mapfile -t ips < <(printf '%s\n' "$cidr" | python3 -c "$all_hosts_py")
  else
    ip=$(printf '%s\n' "$cidr" | python3 -c "$rand_host_py")
    ips=("$ip")
  fi

  for ip in "${ips[@]}"; do
    echo "[$cidr] probing $ip ..."
    out="$($NPING_CMD "$ip" 2>/dev/null)"
    if grep -qiE 'ICMP.*type=3.*code=3' <<<"$out"; then
      echo "  ✔ UDP/443 reachable (ICMP 3/3 received)"
    else
      echo "  ✘ no 3/3 reply (possibly filtered/blocked)"
    fi
  done
done < "$INFILE"

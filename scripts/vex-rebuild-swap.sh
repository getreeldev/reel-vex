#!/usr/bin/env bash
#
# vex-rebuild-swap.sh — blue/green rebuild-and-swap for the vex-hub prod server.
#
# WHY THIS EXISTS
#   vex-hub's database is 100% derived data — it is rebuilt from the upstream
#   vendor feeds by `ingest`, and nothing in it is irreplaceable (user VEX is
#   in-memory only). So instead of running VACUUM in place (which needs free
#   space >= the DB's own size and is painful on a near-full disk), we treat the
#   server as cattle: on each release we provision a fresh box, re-ingest from
#   scratch (a clean ingest carries NO upsert free-page bloat), validate, and
#   swap the primary IP. The old box stays as instant rollback.
#
#   This is run AT EACH RELEASE — the release is the cadence. There is no
#   separate monitoring daemon; the preflight stage below is the disk/staleness
#   "check at release time" that replaces alerting (see `preflight`).
#
# THREE INVARIANTS (do not break these or the model stops working)
#   1. Automated   — this script is the automation. Run it, don't hand-roll.
#   2. Checked     — `prepare` runs `preflight` first and prints prod disk
#                    headroom + data staleness so a human sees it at release.
#   3. Stateless   — the ONLY non-reconstructable artifact on the box is
#                    /opt/reel-vex/config.yaml (commercially sensitive, lives
#                    only on the VPS). It is carried forward by the snapshot, so
#                    rebuilds are lossless. If the box ever gains real local
#                    state (persisted user data, counters, billing logs), STOP —
#                    cattle-rebuilds would lose it.
#
# DESIGN: staged, with a manual gate before the swap.
#   preflight              — report prod disk/free/DB-size/staleness; recommend box size
#   prepare <image:tag>    — snapshot prod -> new server -> fix resolver -> stop
#                            sidecar -> wipe stale DB -> deploy image -> fresh
#                            ingest. Prints the new box IP for MANUAL TESTING.
#   status                 — ingest progress + validation checks on the new box
#   swap                   — (gated) re-validate, then move primary IP old->new
#   decommission           — after soak: delete old server + the snapshot
#
# Requires: HETZNER_API_TOKEN. Curl + ssh. No hcloud CLI needed.
set -euo pipefail

# ---- config (override via env) ----------------------------------------------
: "${HETZNER_API_TOKEN:?Set HETZNER_API_TOKEN (see ~/.env.test)}"
API="https://api.hetzner.cloud/v1"
PRIMARY_IP="${PRIMARY_IP:-178.105.11.208}"     # the IP that DEFINES prod; survives swaps
DOMAIN="${DOMAIN:-vex.getreel.dev}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_rsa_macbook_intel}"
HETZNER_SSH_KEY_NAME="${HETZNER_SSH_KEY_NAME:-andrea-macbook-intel}"
IMAGE_REPO="${IMAGE_REPO:-getreel/vex-hub}"
DATA_DIR="/opt/reel-vex/data"
# A product almost certainly present, used to smoke-test broad mode.
VALIDATION_PRODUCT="${VALIDATION_PRODUCT:-pkg:rpm/redhat/kernel}"
STATE_FILE="${STATE_FILE:-/tmp/vex-rebuild-swap.state}"

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -i "$SSH_KEY")

hapi() { # hapi METHOD PATH [json]
  local m=$1 p=$2 body=${3:-}
  if [ -n "$body" ]; then
    curl -fsS -X "$m" -H "Authorization: Bearer $HETZNER_API_TOKEN" -H "Content-Type: application/json" -d "$body" "$API$p"
  else
    curl -fsS -X "$m" -H "Authorization: Bearer $HETZNER_API_TOKEN" "$API$p"
  fi
}
rssh() { ssh "${SSH_OPTS[@]}" "root@$1" "$2"; }
jget() { python3 -c "import json,sys;d=json.load(sys.stdin);print(eval(sys.argv[1]))" "$1"; }
log()  { printf '\033[1;36m[%s]\033[0m %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# Resolve the server currently holding the prod primary IP.
prod_server_id() {
  hapi GET "/primary_ips" | python3 -c '
import json,sys,os
ip=os.environ["PRIMARY_IP"]
for p in json.load(sys.stdin)["primary_ips"]:
    if p["ip"]==ip: print(p["assignee_id"] or ""); break
'
}
primary_ip_id() {
  hapi GET "/primary_ips" | python3 -c '
import json,sys,os
ip=os.environ["PRIMARY_IP"]
for p in json.load(sys.stdin)["primary_ips"]:
    if p["ip"]==ip: print(p["id"]); break
'
}
server_ip()    { hapi GET "/servers/$1" | jget 'd["server"]["public_net"]["ipv4"]["ip"]'; }
server_field() { hapi GET "/servers/$1" | jget "d[\"server\"][\"$2\"]"; }

wait_action() { # wait_action ACTION_ID LABEL
  local id=$1 label=$2 st
  for _ in $(seq 1 120); do
    st=$(hapi GET "/actions/$id" | jget 'd["action"]["status"]')
    [ "$st" = success ] && { log "$label: done"; return 0; }
    [ "$st" = error ]   && die "$label: action failed"
    sleep 5
  done
  die "$label: timed out"
}
wait_ssh() { # wait_ssh IP
  for _ in $(seq 1 60); do
    rssh "$1" 'echo ok' 2>/dev/null | grep -q ok && { log "ssh up on $1"; return 0; }
    sleep 8
  done
  die "ssh never came up on $1"
}

# Pick the cheapest x86 server type whose disk fits the given byte size. The
# caller passes the current (possibly bloated) DB size, which is a conservative
# floor since a fresh rebuild is smaller.
recommend_type() { # recommend_type DB_BYTES
  hapi GET "/server_types?per_page=100" | python3 -c '
import json,sys
need_gb=float(sys.argv[1])/1e9
rows=[(t["name"],t["cores"],t["disk"]) for t in json.load(sys.stdin)["server_types"]
      if t["disk"]>=need_gb and t["architecture"]=="x86" and not t.get("deprecated")]
rows.sort(key=lambda r:r[2])
print(rows[0][0] if rows else "NONE-FITS")
' "$1"
}

# ---- stages -----------------------------------------------------------------

cmd_preflight() {
  log "PREFLIGHT — release-time check on live prod ($PRIMARY_IP)"
  local stats stale_days dbbytes free pct rec
  stats=$(curl -fsS --max-time 10 "https://$DOMAIN/v1/stats")
  echo "  stats: $stats"
  stale_days=$(echo "$stats" | python3 -c '
import json,sys,datetime
lu=json.load(sys.stdin).get("last_updated","")
if lu:
    d=datetime.datetime.fromisoformat(lu.replace("Z","+00:00"))
    print(round((datetime.datetime.now(datetime.timezone.utc)-d).total_seconds()/86400,1))
else: print("?")')
  echo "  data staleness: ${stale_days} days  (if large, prod ingest is failing — likely full disk)"
  local ip info free_b used_pct db_b rec
  ip=$(server_ip "$(prod_server_id)")
  info=$(rssh "$ip" '
    echo "free_b=$(df -B1 --output=avail '"$DATA_DIR"' | tail -1 | tr -dc 0-9)"
    echo "used_pct=$(df --output=pcent '"$DATA_DIR"' | tail -1 | tr -dc 0-9)"
    echo "db_b=$(stat -c %s '"$DATA_DIR"'/vex.db 2>/dev/null || echo 0)"')
  free_b=$(echo "$info" | sed -n 's/free_b=//p')
  used_pct=$(echo "$info" | sed -n 's/used_pct=//p')
  db_b=$(echo "$info" | sed -n 's/db_b=//p')
  awk -v f="${free_b:-0}" -v d="${db_b:-0}" -v p="${used_pct:-0}" \
    'BEGIN{printf "  disk: %.1f GB free, %s%% used | vex.db %.1f GB\n", f/1e9, p, d/1e9}'
  # Disk floor = current on-disk DB size. A clean rebuild is SMALLER than the
  # (possibly bloated) live DB, so sizing to the current size is conservative.
  # Recommendation is disk-only — keep the CPU/RAM class similar to prod.
  rec=$(recommend_type "${db_b:-0}")
  echo "  new-box disk floor = current DB size; cheapest x86 type that fits: $rec"
  [ "${used_pct:-0}" -ge 90 ] && echo "  ⚠️  prod disk >=90% — rebuild is overdue."
}

cmd_prepare() {
  local image="${1:?usage: prepare <image:tag>}"
  cmd_preflight
  local old_id old_ip; old_id=$(prod_server_id); old_ip=$(server_ip "$old_id")
  log "snapshotting current prod (server $old_id) ..."
  local snap; snap=$(hapi POST "/servers/$old_id/actions/create_image" \
    "{\"type\":\"snapshot\",\"description\":\"vex-rebuild $(date -u +%FT%TZ)\"}")
  local snap_img snap_act
  snap_img=$(echo "$snap" | jget 'd["image"]["id"]'); snap_act=$(echo "$snap" | jget 'd["action"]["id"]')
  wait_action "$snap_act" "snapshot"

  local stype; stype=$(server_field "$old_id" server_type | python3 -c 'import json,sys;print(json.load(sys.stdin)["name"])' 2>/dev/null || echo "$(server_field "$old_id" server_type)")
  log "creating new server from snapshot (type ${VEX_NEW_TYPE:-$stype}) ..."
  local newjson new_id new_ip
  for loc in nbg1 fsn1 hel1; do
    if newjson=$(hapi POST "/servers" "{\"name\":\"vex-hub-candidate\",\"server_type\":\"${VEX_NEW_TYPE:-$stype}\",\"location\":\"$loc\",\"image\":$snap_img,\"ssh_keys\":[\"$HETZNER_SSH_KEY_NAME\"],\"start_after_create\":true}" 2>/dev/null); then break; fi
    log "  $loc unavailable, trying next..."
  done
  new_id=$(echo "$newjson" | jget 'd["server"]["id"]'); new_ip=$(echo "$newjson" | jget 'd["server"]["public_net"]["ipv4"]["ip"]')
  log "new server $new_id @ $new_ip"
  printf 'OLD_ID=%s\nNEW_ID=%s\nNEW_IP=%s\nSNAP_IMG=%s\nIMAGE=%s\n' "$old_id" "$new_id" "$new_ip" "$snap_img" "$image" > "$STATE_FILE"

  wait_ssh "$new_ip"
  log "fixing resolver + stopping sidecar + wiping stale DB + deploying $image ..."
  local token; token=$(rssh "$old_ip" 'docker inspect reel-vex --format "{{json .Config.Cmd}}"' | python3 -c '
import json,sys
c=json.load(sys.stdin)
print(c[c.index("-admin-token")+1] if "-admin-token" in c else "")')
  rssh "$new_ip" '
    systemctl restart systemd-resolved 2>/dev/null || true
    docker rm -f reel-vex 2>/dev/null || true
    # Pause (not remove) the sidecar so it does not ship the candidate box to
    # PostHog during ingest/testing; swap restarts it on the new prod.
    docker stop vex-hub-vector 2>/dev/null || true
    rm -f '"$DATA_DIR"'/vex.db '"$DATA_DIR"'/vex.db-wal '"$DATA_DIR"'/vex.db-shm
    docker image prune -af >/dev/null 2>&1 || true
    docker pull '"$image"'
    docker run -d --name reel-vex --restart unless-stopped --network host \
      -v /opt/reel-vex/data:/data -v /opt/reel-vex/config.yaml:/config.yaml:ro \
      '"$image"' -db /data/vex.db -config /config.yaml -addr 127.0.0.1:8080 \
      -admin-token "'"$token"'" -ingest-interval 4h serve'
  log "DONE. Fresh ingest started on $new_ip."
  echo
  echo "  Next:  $0 status         # watch ingest + validation"
  echo "         (manually test https://$DOMAIN against $new_ip, e.g. curl --resolve)"
  echo "         $0 swap           # when happy, move the IP"
}

cmd_status() {
  [ -f "$STATE_FILE" ] || die "no in-flight rebuild ($STATE_FILE missing)"
  . "$STATE_FILE"
  log "ingest/validation on candidate $NEW_IP"
  rssh "$NEW_IP" 'curl -s localhost:8080/v1/stats; echo; docker logs reel-vex 2>&1 | grep -E "ingest (started|completed)" | tail -3'
}

# Smoke-test the candidate before we trust it with the IP.
validate() { # validate IP
  local ip=$1 ok=1
  log "validating candidate $ip"
  rssh "$ip" 'curl -s -o /dev/null -w "%{http_code}" localhost:8080/healthz' | grep -q 200 || { echo "  healthz FAIL"; ok=0; }
  local n; n=$(rssh "$ip" 'curl -s localhost:8080/v1/stats' | jget 'd["statements"]')
  echo "  statements: $n"; [ "${n:-0}" -gt 1000000 ] || { echo "  stats too low — ingest incomplete?"; ok=0; }
  local bc; bc=$(rssh "$ip" 'curl -s -o /dev/null -w "%{http_code}" -X POST localhost:8080/v1/statements -H "Content-Type: application/json" -d "{\"products\":[\"'"$VALIDATION_PRODUCT"'\"]}"')
  echo "  broad mode ($VALIDATION_PRODUCT): HTTP $bc"; [ "$bc" = 200 ] || { echo "  broad mode FAIL"; ok=0; }
  local gz; gz=$(rssh "$ip" 'curl -s -D- -o /dev/null -H "Accept-Encoding: gzip" -X POST localhost:8080/v1/statements -H "Content-Type: application/json" -d "{\"cves\":[\"CVE-2021-44228\"]}" | grep -i content-encoding')
  echo "  gzip: ${gz:-<none>}"; echo "$gz" | grep -qi gzip || { echo "  gzip FAIL"; ok=0; }
  [ "$ok" = 1 ] || die "validation failed — NOT safe to swap"
  log "validation PASSED"
}

cmd_swap() {
  [ -f "$STATE_FILE" ] || die "no in-flight rebuild"
  . "$STATE_FILE"
  validate "$NEW_IP"
  local ipid; ipid=$(primary_ip_id)
  log "SWAP: power off both, move primary IP $PRIMARY_IP -> server $NEW_ID (brief downtime) ..."
  wait_action "$(hapi POST "/servers/$OLD_ID/actions/poweroff" | jget 'd["action"]["id"]')" "poweroff old"
  wait_action "$(hapi POST "/servers/$NEW_ID/actions/poweroff" | jget 'd["action"]["id"]')" "poweroff new"
  wait_action "$(hapi POST "/primary_ips/$ipid/actions/unassign" | jget 'd["action"]["id"]')" "unassign IP"
  wait_action "$(hapi POST "/primary_ips/$ipid/actions/assign" "{\"assignee_id\":$NEW_ID,\"assignee_type\":\"server\"}" | jget 'd["action"]["id"]')" "assign IP"
  wait_action "$(hapi POST "/servers/$NEW_ID/actions/poweron" | jget 'd["action"]["id"]')" "poweron new"
  wait_ssh "$PRIMARY_IP"
  # Resume telemetry on the new prod (paused during prepare; unless-stopped does
  # not auto-start an explicitly-stopped container across the reboot).
  rssh "$PRIMARY_IP" 'docker start vex-hub-vector 2>/dev/null || echo "(no sidecar to start — recreate via Path 2)"'
  log "swapped. Verifying public endpoint ..."
  sleep 5
  curl -fsS --max-time 15 "https://$DOMAIN/v1/stats" && echo
  echo "  OLD server $OLD_ID is powered off and kept as rollback."
  echo "  Rollback = re-assign IP to $OLD_ID and power it on."
  echo "  When confident: $0 decommission"
}

cmd_decommission() {
  [ -f "$STATE_FILE" ] || die "no in-flight rebuild"
  . "$STATE_FILE"
  read -rp "Delete OLD server $OLD_ID and snapshot $SNAP_IMG? [yes/NO] " a
  [ "$a" = yes ] || die "aborted"
  hapi DELETE "/servers/$OLD_ID" >/dev/null && log "deleted old server $OLD_ID"
  hapi DELETE "/images/$SNAP_IMG" >/dev/null && log "deleted snapshot $SNAP_IMG"
  rm -f "$STATE_FILE"
}

case "${1:-help}" in
  preflight)     cmd_preflight ;;
  prepare)       shift; cmd_prepare "$@" ;;
  status)        cmd_status ;;
  swap)          cmd_swap ;;
  decommission)  cmd_decommission ;;
  *) sed -n '2,40p' "$0" ;;
esac

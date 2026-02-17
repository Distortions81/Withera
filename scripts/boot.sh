#!/usr/bin/env bash
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

NUM_NODES="${NUM_NODES:-3}"
NUM_CLIENTS="${NUM_CLIENTS:-2}"
BASE_PORT="${BASE_PORT:-9101}"
WEB_BASE_PORT="${WEB_BASE_PORT:-8080}"
SID_PREFIX="${SID_PREFIX:-peer}"
# Bind on all interfaces by default, but keep advertise/dial defaults local for
# local multi-node boot behavior unless explicitly overridden.
BIND_HOST="${BIND_HOST:-${HOST:-0.0.0.0}}"
ADVERTISE_HOST="${ADVERTISE_HOST:-127.0.0.1}"
WEB_URL_HOST="${WEB_URL_HOST:-$ADVERTISE_HOST}"
CLIENT_WEB_OPEN="${CLIENT_WEB_OPEN:-0}"

NODES_RUNTIME_DIR="$ROOT_DIR/.run/nodes"
CLIENTS_RUNTIME_DIR="$ROOT_DIR/.run/clients"
BIN_DIR="$ROOT_DIR/.run/bin"
NODE_PID_DIR="$NODES_RUNTIME_DIR/pids"
CLIENT_PID_DIR="$CLIENTS_RUNTIME_DIR/pids"
NODE_INSTANCES_DIR="$NODES_RUNTIME_DIR/instances"
CLIENT_INSTANCES_DIR="$CLIENTS_RUNTIME_DIR/instances"
CLIENT_LOG_DIR="$CLIENTS_RUNTIME_DIR/logs"
NODE_BIN="$BIN_DIR/withera-node"
CLIENT_WEB_BIN="$BIN_DIR/withera-client-web"

mkdir -p "$NODE_PID_DIR" "$CLIENT_PID_DIR" "$NODE_INSTANCES_DIR" "$CLIENT_INSTANCES_DIR" "$CLIENT_LOG_DIR" "$BIN_DIR"

cleanup_done=0

is_running() {
  local pid="$1"
  kill -0 "$pid" 2>/dev/null
}

stop_pid() {
  local pid="$1"
  if ! is_running "$pid"; then
    return
  fi

  kill "$pid" 2>/dev/null || true
  for _ in {1..30}; do
    if ! is_running "$pid"; then
      return
    fi
    sleep 0.1
  done

  kill -9 "$pid" 2>/dev/null || true
}

stop_from_pid_file() {
  local sid="$1"
  local pid_file="$2"

  if [[ ! -f "$pid_file" ]]; then
    return
  fi

  local pid
  pid="$(cat "$pid_file" || true)"
  if [[ -n "$pid" ]]; then
    if is_running "$pid"; then
      stop_pid "$pid"
      echo "stopped stale $sid (pid $pid)"
    else
      echo "$sid had stale pid $pid"
    fi
  fi

  rm -f "$pid_file"
}

cleanup() {
  if (( cleanup_done == 1 )); then
    return
  fi
  cleanup_done=1
  trap - EXIT INT TERM HUP
  set +e

  echo
  echo "stopping launched clients and nodes..."
  cleanup_pid_dir "client" "$CLIENT_PID_DIR"
  cleanup_pid_dir "node" "$NODE_PID_DIR"
}

cleanup_pid_dir() {
  local kind="$1"
  local pid_dir="$2"
  local pid_files=()

  if [[ ! -d "$pid_dir" ]]; then
    return
  fi

  shopt -s nullglob
  pid_files=("$pid_dir"/*.pid)
  shopt -u nullglob
  if (( ${#pid_files[@]} == 0 )); then
    return
  fi

  for pid_file in "${pid_files[@]}"; do
    local sid
    local pid
    sid="$(basename "$pid_file" .pid)"
    pid="$(cat "$pid_file" || true)"
    if [[ -n "$pid" ]] && is_running "$pid"; then
      stop_pid "$pid"
      echo "stopped $kind $sid (pid $pid)"
    fi
    rm -f "$pid_file"
  done
}

trap cleanup EXIT INT TERM HUP

peer_addr() {
  local idx="$1"
  local port=$((BASE_PORT + idx - 1))
  printf '%s:%s' "$ADVERTISE_HOST" "$port"
}

wait_for_tcp() {
  local host="$1"
  local port="$2"
  local timeout_sec="${3:-15}"
  local waited=0
  while (( waited < timeout_sec )); do
    if (echo >"/dev/tcp/$host/$port") >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

start_node() {
  local idx="$1"
  local sid="${SID_PREFIX}${idx}"
  local node_dir="$NODE_INSTANCES_DIR/$sid"
  local config_dir="$node_dir/config"
  local data_dir="$node_dir/data"
  local log_dir="$node_dir/logs"
  local config_file="$config_dir/node.toml"
  local key_file="$config_dir/owner-key.json"
  local db_file="$data_dir/state.sqlite"
  local log_file="$log_dir/node.log"
  local listen_addr="${BIND_HOST}:$((BASE_PORT + idx - 1))"
  local advertise_addr="$(peer_addr "$idx")"
  local pid_file="$NODE_PID_DIR/$sid.pid"

  mkdir -p "$config_dir" "$data_dir" "$log_dir"

  stop_from_pid_file "$sid" "$pid_file"

  peers=()
  if (( idx > 1 )); then
    peers+=("$(peer_addr 1)")
    if (( idx > 2 )); then
      peers+=("$(peer_addr $((idx - 1)))")
    fi
  fi

  {
    echo "listen = \"$listen_addr\""
    echo "advertise = \"$advertise_addr\""
    echo "sid = \"$sid\""
    echo "key = \"$key_file\""
    echo "persistence_mode = \"persist\""
    echo "persistence_db = \"$db_file\""
    echo "persist_public_topology = true"
    echo "persist_chat_messages = false"
    if (( ${#peers[@]} > 0 )); then
      printf "peers = ["
      for ((p=0; p<${#peers[@]}; p++)); do
        if (( p > 0 )); then printf ", "; fi
        printf "\"%s\"" "${peers[$p]}"
      done
      printf "]\n"
    fi
  } > "$config_file"

  "$NODE_BIN" -config "$config_file" >"$log_file" 2>&1 &
  local pid="$!"

  echo "$pid" > "$pid_file"

  echo "started $sid (pid $pid)"
  echo "  bind: $listen_addr"
  echo "  node: $advertise_addr"
}

start_client() {
  local idx="$1"
  local sid="web${idx}"
  local node_addr="$ADVERTISE_HOST:$((BASE_PORT + idx - 1))"
  local web_addr="$BIND_HOST:$((WEB_BASE_PORT + idx - 1))"
  local web_url="http://${WEB_URL_HOST}:$((WEB_BASE_PORT + idx - 1))"
  local pid_file="$CLIENT_PID_DIR/$sid.pid"
  local log_file="$CLIENT_LOG_DIR/$sid.log"
  local client_dir="$CLIENT_INSTANCES_DIR/$sid"
  local client_home="$client_dir/home"

  stop_from_pid_file "$sid" "$pid_file"

  mkdir -p "$client_home"
  HOME="$client_home" "$CLIENT_WEB_BIN" \
    -addr "$node_addr" \
    -web "$web_addr" \
    -open="$CLIENT_WEB_OPEN" \
    >"$log_file" 2>&1 &
  local pid="$!"

  echo "$pid" > "$pid_file"

  echo "started $sid (pid $pid)"
  echo "  web: $web_url"
  echo "  node: $node_addr"
  echo "  data: $client_home/.withera"
}

echo "building node binary..."
go build -o "$NODE_BIN" "$ROOT_DIR/node"
echo "building web client binary..."
go build -o "$CLIENT_WEB_BIN" "$ROOT_DIR/client-web"

for ((i=1; i<=NUM_NODES; i++)); do
  start_node "$i"
done

echo "waiting for node ports..."
for ((i=1; i<=NUM_NODES; i++)); do
  node_port=$((BASE_PORT + i - 1))
  if wait_for_tcp "$ADVERTISE_HOST" "$node_port" 20; then
    echo "  node ready: $ADVERTISE_HOST:$node_port"
  else
    echo "  node not ready yet: $ADVERTISE_HOST:$node_port"
  fi
done

for ((i=1; i<=NUM_CLIENTS; i++)); do
  start_client "$i"
done

echo
echo "running. press Ctrl+C to stop all launched clients and nodes."
wait

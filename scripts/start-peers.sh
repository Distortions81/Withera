#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

NUM_PEERS="${NUM_PEERS:-3}"
BASE_PORT="${BASE_PORT:-9101}"
SID_PREFIX="${SID_PREFIX:-peer}"
HOST="${HOST:-127.0.0.1}"

RUNTIME_DIR="$ROOT_DIR/.run/peers"
BIN_DIR="$ROOT_DIR/.run/bin"
PID_DIR="$RUNTIME_DIR/pids"
LOG_DIR="$RUNTIME_DIR/logs"
KEY_DIR="$RUNTIME_DIR/keys"
STATE_DIR="$RUNTIME_DIR/state"
CONFIG_DIR="$RUNTIME_DIR/config"
SERVER_BIN="$BIN_DIR/goaccord-server"

mkdir -p "$PID_DIR" "$LOG_DIR" "$KEY_DIR" "$BIN_DIR" "$STATE_DIR" "$CONFIG_DIR"

# Build once per start to pick up latest node code.
go build -o "$SERVER_BIN" "$ROOT_DIR/server"

is_running() {
  local pid="$1"
  kill -0 "$pid" 2>/dev/null
}

peer_addr() {
  local idx="$1"
  local port=$((BASE_PORT + idx - 1))
  printf '%s:%s' "$HOST" "$port"
}

start_node() {
  local sid="$1"
  local config_file="$2"
  local log_file="$3"

  local pid_file="$PID_DIR/$sid.pid"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(cat "$pid_file")"
    if [[ -n "$pid" ]] && is_running "$pid"; then
      echo "$sid already running (pid $pid)"
      return
    fi
    rm -f "$pid_file"
  fi

  local cmd=(
    "$SERVER_BIN"
    -config "$config_file"
  )
  nohup "${cmd[@]}" >"$log_file" 2>&1 &
  local pid="$!"
  echo "$pid" > "$pid_file"
  echo "started $sid using $config_file (pid $pid)"
}

for ((i=1; i<=NUM_PEERS; i++)); do
  sid="${SID_PREFIX}${i}"
  log_file="$LOG_DIR/$sid.log"
  key_file="$KEY_DIR/$sid-owner-key.json"
  listen_addr=":$((BASE_PORT + i - 1))"
  advertise_addr="$(peer_addr "$i")"
  config_file="$CONFIG_DIR/$sid.toml"

  peers=()
  if (( i > 1 )); then
    peers+=("$(peer_addr 1)")
    if (( i > 2 )); then
      peers+=("$(peer_addr $((i-1)))")
    fi
  fi

  {
    echo "listen = \"$listen_addr\""
    echo "advertise = \"$advertise_addr\""
    echo "sid = \"$sid\""
    echo "key = \"$key_file\""
    if (( ${#peers[@]} > 0 )); then
      printf "peers = ["
      for ((p=0; p<${#peers[@]}; p++)); do
        if (( p > 0 )); then printf ", "; fi
        printf "\"%s\"" "${peers[$p]}"
      done
      printf "]\n"
    fi
  } > "$config_file"

  start_node "$sid" "$config_file" "$log_file"

done

echo "runtime dir: $RUNTIME_DIR"

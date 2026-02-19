# Withera

Withera is a decentralized chat prototype with these components:
- `node/`: network nodes that authenticate users/peers, relay messages, and optionally persist selected state.
- `client-web/`: local web client served from a local Go process.
- `client-tui/`: terminal client.
- `client-fyne/`: native desktop client (in-progress).

## Prerequisites

- Go `1.24.x` (see `go.mod` for the `toolchain` directive).
- Optional for `client-fyne`: platform-specific GUI dependencies required by Fyne.

## How It Works (End User View)

1. You create or restore an identity in a client.
2. The client connects to a node over TLS.
3. The node sends a challenge nonce.
4. Your client signs the challenge with your identity key.
5. After auth, you can DM friends or join/send in groups/channels.
6. Nodes relay signed actions across the node mesh.
7. If persistence is enabled on a node, selected state may be stored based on node policy.

## Node Features

- Ed25519 challenge-response authentication for user logins.
- Owner-scoped node identity for node-to-node trust (`<owner_login_id>:<sid>`).
- TLS for all connections.
- Signed packet actions for message integrity/authenticity.
- Peer discovery and background dialing (`getaddr`/`addr`).
- Relay mesh with dedupe and route hints.
- Client access policy modes: `public`, `private`, `disabled`.
- Persistence modes: `live` and `persist` (SQLite).
- Allowlist-based persistence policy.
- Optional public topology persistence override.
- Offline chat queue persistence is available but default-off (`persist_chat_messages = false`).
- Group/channel guardrails (max channel count, max name lengths).
- Rate and size limits (msg bytes, decompress bounds, per-conn rate/burst).
- Local stats HTTP endpoint.
- TOML config support with CLI override precedence.

## Client Features

### `client-web`

- Browser login/setup flow for identity select/create/restore.
- Base58-style recovery key formatting and restore UX.
- Backup/export for identities.
- QR code for account recovery display.
- Logout/switch identity flow.
- DM + friends workflow.
- Group/channel create, join, invite, and messaging.
- Group profile editor for owned groups (text + icon).
- Public group invite code support.
- Presence and profile UX.
- E2EE DM key management and rotation.

### `client-tui`

- Terminal command-driven interface.
- Identity switch/create helpers.
- DM, friends, profile, and presence commands.
- Group/channel commands and invite handling.
- E2EE key status and rotation commands.
- Local UI context persistence.

### `client-fyne` (current)

- Native desktop UI scaffold.
- Login/setup flow and active chat window foundation.
- Ongoing parity work toward `client-web` features.

## Running

### Boot local servers + clients

```bash
./scripts/boot.sh
```

This is the main quick-iteration command:
- Starts local nodes and web clients.
- Stays attached to your terminal.
- Shuts down all launched processes when you exit (for example `Ctrl+C` or terminal close).

Web client ports are stable (`127.0.0.1:8080`, `127.0.0.1:8081`, ...), so you can keep tabs open and refresh quickly.

Boot customization (via env vars):
- `NUM_NODES` (default `3`)
- `NUM_CLIENTS` (default `2`)
- `BASE_PORT` (default `9101`)
- `WEB_BASE_PORT` (default `8080`)
- `BIND_HOST` (default `0.0.0.0`) and `ADVERTISE_HOST` (default `127.0.0.1`)
- `CLIENT_WEB_OPEN=1` to auto-open browsers for launched web clients

Runtime state is written under:
- `.run/nodes/instances/<sid>/config/node.toml`
- `.run/nodes/instances/<sid>/data/state.sqlite`
- `.run/nodes/instances/<sid>/logs/node.log`
- `.run/clients/logs/<sid>.log`

### Run clients

```bash
go run ./client-web -addr 127.0.0.1:9101 -web 127.0.0.1:8080 -open=false
go run ./client-tui -addr 127.0.0.1:9101
go run ./client-fyne
```

`client-web` defaults now use a fixed web port (`127.0.0.1:8080`) and no
browser auto-open unless `-open=true` is passed.

## Notes

- This repository is in prototype phase and intentionally allows clean protocol/API breaks.
- For deeper implementation detail, see `NODES_CURRENT_STATE.md`, `CLIENTS_CURRENT_STATE.md`, and `PROTOCOL.md`.

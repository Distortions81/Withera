# client-web

Simple local web UI client for Withera.

## Run

```bash
go run ./client-web -addr 127.0.0.1:9101
```

Options:

- `-addr` protocol node address (default `127.0.0.1:9101`)
- `-web` local HTTP listen address for the web UI (default `127.0.0.1:8080`)
- `-key` identity key path (default `~/.withera/ed25519_key.json`, or legacy `~/.goaccord/ed25519_key.json`)
- `-contacts` contacts file path (default `~/.withera/contacts.json`, or legacy `~/.goaccord/contacts.json`)
- `-profile` profile file path (default is derived from the key filename under `~/.withera/profiles/`)
- `-open` auto-open browser (default `false`)

On startup it:

1. Starts local HTTP listener and serves a browser UI.
2. Uses the most recently-used identity by default (unless `-key` is explicitly set), and lets you choose/create/restore identities in the web UI.
3. Connects/authenticates to a Withera node after identity selection.

## UI capabilities

- DM send
- Friend add / friend accept
- Profile update (display name + profile text)
- Profile fetch for target
- Live chat/info event polling
- DM target list from contacts/friends
- DM target E2EE state (`e2ee_ready` + `e2ee_status` in target payload), including multi-key readiness for multi-device peers
- Presence mode (`visible`/`invisible`) with periodic keepalive and TTL-based friend status checks
- E2EE key rotation endpoint (`POST /api/e2ee/rotate`)

## Notes

- Uses same signed message/auth model as `client-tui`.
- Uses same compression behavior (`none` or `zlib`) for outgoing text payloads.
- Uses local read-merge-atomic-write for contacts/profile files to reduce multi-instance clobbering.
- Persists verified peer E2EE keys and seen friend-key nonces under `~/.withera/e2ee/` (or legacy `~/.goaccord/e2ee/`).

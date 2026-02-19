# client-fyne

Native desktop client using Fyne.

## Current baseline
- Identity selection UI (create/restore/backup)
- Connect/authenticate to a server with Ed25519 identity key
- Friends: add/accept/ignore + contacts/aliases persistence
- End-to-end encrypted DMs (X25519 + AES-GCM) with multi-device recipient support
- E2EE key rotation + re-share to friends
- Groups/channels: create/join/leave/invite + invite accept/ignore/reject
- Profile editor + profile image (data URL) + peer profile viewing
- Group profile editor (text + icon)
- Presence controls + periodic keepalive
- Automatic reconnect on transport drop
- UI context persistence (last DM/group/channel)

## Run
```bash
go run ./client-fyne
```

Options:
- `-addr` server address (default `127.0.0.1:9101`)
- `-key` identity key path (default `~/.withera/ed25519_key.json`, or legacy locations via the identity picker)
- `-contacts` contacts file path (default `~/.withera/contacts.json`)

Default values:
- server: `127.0.0.1:9101`
- key file: `~/.withera/ed25519_key.json` (or legacy `~/.goaccord/ed25519_key.json`)
 
Persistence:
- Profile: `~/.withera/profiles/profile-<keyfile>.json`
- UI state: `<profile>.ui.json`
- E2EE keys/state: `~/.withera/e2ee/`

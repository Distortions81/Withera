# Withera Clients (Current State)

This document describes the current shipped client implementations in this repository.

## Client set

Current clients:
- Terminal client: `./client-tui`
- Local web client: `./client-web`
- Desktop GUI client: `./client-fyne`

All clients use the same signed user identity model and the same node protocol.

## Shared client behavior

- Identity key: Ed25519 key file; `login_id` is derived from public key.
- Startup identity UX supports selecting or creating identities.
- Login uses challenge/response signature auth.
- Outgoing signed actions include direct messages, friend actions, profile, presence, and group/channel actions.
- Group profile support via signed `group_profile_set` / `group_profile_get` (for owned groups).
- Incoming packet handling includes direct/group delivery, friend updates, invites, profile/presence responses, and ping/pong.
- Automatic reconnect is built in for connection drops.

## End-to-end encrypted DM support

Both clients support DM body encryption with X25519-based E2EE keys:
- Local X25519 keypair is generated/loaded per identity.
- Friend key exchange is signed by the sender's Ed25519 identity key.
- Replay resistance uses tracked friend-key nonces.
- Multi-device recipients are handled by storing multiple verified peer E2EE keys per login.
- If verified recipient E2EE keys are missing, encrypted DM send is blocked.

## Local data persisted by clients

Common local persistence under `~/.withera/` (or legacy `~/.goaccord/`) includes:
- Identity key files (Ed25519)
- E2EE key file(s) and E2EE state (verified peer keys + seen nonces)
- Contacts/aliases
- Profile cache and peer profile snapshots
- UI context state (`.ui.json` style state)

## `client-tui` current state

Primary characteristics:
- Bubble Tea TUI with command-driven interaction.
- Panels for chats/info and context switching between DM and group/channel.
- Commands include:
  - DM targeting and contacts management
  - Friend add/accept
  - Profile set/get
  - Presence set/check
  - Group/channel create/invite/join/leave/send
  - Invite listing and acceptance
  - E2EE key status and key rotation
  - Identity helper commands (`/identities`, `/switchid`)
- Persists known nodes/channels and last context to profile UI state.
- Reconnect behavior restores active session behavior after transport interruptions.

## `client-web` current state

Primary characteristics:
- Local HTTP listener + browser UI.
- Sidebar model for friends and nodes/groups/channels.
- Group/channel UX supports create, invite, join, send, and invite accept/ignore/reject flows.
- Group profile editor for owned groups (text + icon).
- Profile editor and profile card viewing.
- Presence controls (`visible`/`invisible` + TTL) and periodic keepalive.
- Event polling endpoint drives incremental UI updates.
- Context persistence tracks current DM/group/channel view.

Representative API surface used by the web UI includes:
- `/api/bootstrap`, `/api/events`
- `/api/send`, `/api/group/send`
- `/api/friend/add`, `/api/friend/accept`, `/api/friend/ignore`
- `/api/group/create`, `/api/group/invite`, `/api/group/join`, `/api/group/remove`
- `/api/group/profile/set`
- `/api/invite/accept`, `/api/invite/ignore`, `/api/invite/reject`
- `/api/profile/set`, `/api/profile/card`
- `/api/presence/set`, `/api/presence/check`
- `/api/context/set`
- `/api/e2ee/rotate`

## `client-fyne` current state

Primary characteristics:
- Fyne native desktop UI with identity selection, DM, friends, groups, and profile controls.
- DM E2EE (X25519 + AES-GCM) with multi-device recipient support and key rotation.
- Presence controls with periodic keepalive.
- Group profile editor (text + icon) and peer profile viewing.
- Automatic reconnect on transport drops.
- Local persistence for contacts (`contacts.json`), profile, E2EE state, and UI context (`.ui.json`).

## Known current constraints

- Durability depends on node policy and mode (`live` vs `persist`).
- Client-side persistence is local convenience/cache, not global authority.
- Group/channel and delivery semantics depend on reachable relay-capable nodes.

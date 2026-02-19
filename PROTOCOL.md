# Withera Protocol (Current)

This document describes the protocol currently implemented in `node/app.go`.
It is implementation-first and may change during prototype phase.

## Transport

- Transport: TLS over TCP.
- Framing: newline-delimited JSON packets.
- Oversized or malformed lines are dropped.
- Per-connection token-bucket rate limiting is applied after parse.

## Identities

- User identity (`login_id`) is derived as `sha256(pubkey)` (hex string in current implementation).
- Node identity (`node_id`) is `<owner_login_id>:<sid>`.
- User auth proof signs: `"login:<nonce>"`.
- Node auth proof signs: `"server:<node_id>"` (string kept for wire compatibility).

## Packet Envelope

All protocol messages use this JSON shape (fields are optional unless required by type):

- `type`
- `role`
- `id`
- `from`
- `to`
- `body`
- `compression` (`none` or `zlib`)
- `usize` (uncompressed size when `compression=zlib`)
- `group`
- `channel`
- `public`
- `origin`
- `nonce`
- `pub_key` (base64 Ed25519 public key)
- `sig` (base64 Ed25519 signature)
- `listen`
- `addrs` (address list)
- `max_msg_bytes`, `max_msgs_per_sec`, `burst`
- `caps`
- `created_at`
- `hops`

## Session Handshake

### User -> Node

1. Client sends `{"type":"hello","role":"user","pub_key":"..."}`.
2. Node replies `{"type":"challenge","nonce":"..."}`.
3. Client replies `{"type":"auth","pub_key":"...","sig":"..."}` where sig is Ed25519 over `login:<nonce>`.
4. Node replies `{"type":"ok","id":"<login_id>","body":"authenticated"}` or `{"type":"error",...}`.

### Node -> Node

1. Dialer sends `hello` with `role:"server"`, `id`, `pub_key`, `sig`, limits, caps, and optional `listen`.
2. Receiver verifies node identity proof.
3. Receiver replies `ok` with its own identity proof and limits/caps, or `error`.
4. After acceptance, peers can exchange `getaddr` / `addr` and signed action packets.

## Signed Actions

Action types currently accepted as signed actions:
- `send`
- `ping`
- `pong`
- `friend_add`
- `friend_accept`
- `channel_create`
- `group_invite`
- `group_invite_reject`
- `channel_join`
- `channel_leave`
- `channel_send`
- `profile_set`
- `profile_get`
- `group_profile_set`
- `group_profile_get`
- `presence_keepalive`

Signature is verified against canonical JSON of:
- `type`, `id`, `from`, `to`, `body`, `compression`, `usize`, `group`, `channel`, `public`, `created_at`

Validation rules include:
- `id` and `from` required for all signed actions.
- `from` must match authenticated sender (for user-originated packets).
- `pub_key` must hash to `from`.
- Type-specific required fields (for example, `send` requires `to` + `body`, `channel_send` requires `group` + `channel` + `body`).

## Compression Rules

- `compression=none`: `body` is plain UTF-8 text.
- `compression=zlib`: `body` is base64(zlib(data)); `usize` is required.
- Node enforces max compressed size, max uncompressed size, and max expansion ratio.

On accept, node normalizes local processing to uncompressed body.

## Core Flows

### Direct message

- Client sends signed `send`.
- Target online: node emits `deliver` to target sessions.
- Target offline: optional queue storage only if persist mode allows it and `persist_chat_messages=true`.

### Group/channel

- `channel_create`: create channel in group; creator becomes member.
- `group_invite`: invite into group scope.
- `channel_join`: join one/all joinable channels in group.
- `channel_leave`: leave channel.
- `channel_send`: fanout as `channel_deliver` to members.

### Friends

- `friend_add`: sends `friend_request` until mutual acceptance path is met.
- `friend_accept`: establishes mutual edge and emits `friend_update`.

### Profile/presence

- `profile_set` / `profile_get` produce `profile_data`.
- `group_profile_set` / `group_profile_get` produce `group_profile_data`.
- `profile_set` payload may include `profile_image` as an image data URL (`data:image/...;base64,...`).
- Node enforces `profile_image` decoded size limit: max `16384` bytes (16 KiB); oversized payloads are rejected with protocol `error`.
- `presence_keepalive` updates visibility state.
- `presence_get` (non-signed request) returns `presence_data`.

## Relay Behavior

- Signed actions can be forwarded to peers when relay is enabled.
- Deduplication is keyed by `id`.
- Route hints are learned from peer-origin traffic.
- `hops` trail is appended by each node.

## Persistence-Aware Behavior

In `persist` mode:
- Topology metadata persistence follows allowlist policy.
- Offline chat queue persistence is separate and default-off.
- Replay of queued direct messages occurs after user authentication.

## Errors

Nodes may send `{"type":"error","body":"..."}` for:
- handshake/auth failures
- invalid identity proof
- malformed signed packets
- unauthorized access by policy
- invalid channel/group operations

## Compatibility

- Prototype policy is clean-break friendly.
- This document tracks current behavior, not a frozen stable protocol.

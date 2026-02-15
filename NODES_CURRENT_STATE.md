# Open Accord Nodes (Current State)

This document describes how server nodes currently behave in this repository.

## What a node is

A node is a Go server process (`./server`) that:
- Authenticates user clients with signature-based login (no password/account DB).
- Authenticates peer servers with owner-bound server identity proofs.
- Relays signed actions across the peer mesh.
- Optionally persists selected state when run in `persist` mode.

## Identity model

- User identity is `login_id = sha256(pubkey)`.
- Server identity is owner-scoped: `server_id = <owner_login_id>:<sid>`.
- Peer servers must prove they control the owner key for their advertised `server_id`.
- Clients prove identity by signing a per-connection challenge (`login:<nonce>`).

## Transport and security

- TLS is required for all inbound/outbound node traffic.
- If cert/key flags are omitted, a self-signed cert/key pair is generated/used next to the owner key.
- Message actions are additionally signed at the packet level.

## Mesh behavior

- Nodes maintain a known-address set and attempt peer dialing in the background.
- Relay can be enabled/disabled with `-relay`.
- Relay forwarding is route-aware when possible and falls back to broader forwarding when route/channel certainty is missing.
- Dedupe IDs are tracked in memory to avoid re-processing/re-forwarding repeats.

## Client access modes

- `public`: clients may connect unless blocked by other policy.
- `private`: only `login_id`s in `-client-allow` may connect.
- `disabled`: user client logins are rejected.

## Persistence modes

- `live` (default): in-memory state only.
- `persist`: enables SQLite-backed storage (`server/persist_sqlite.go`).

Current persisted tables include:
- `hosted_users`
- `pending_messages`
- `groups_meta`
- `channels_meta`
- `servers_meta`
- `meta`

## Persistence allowlist policy (current)

In `persist` mode, persistence is restricted to identities in `-client-allow`.

Current behavior:
- Non-whitelisted users can still connect in `client-mode=public`.
- Whitelisted users are eligible for hosting/auto-hosting.
- Offline queued delivery is only stored/replayed for whitelisted identities.
- Group/channel topology metadata is only persisted when the acting identity is whitelisted.

Operationally, this means users who want server-backed durability for groups/messages need:
- A node that whitelists their `login_id`, or
- Their own node configured to whitelist themselves.

## Persist hosting behavior

`persist-auto-host=true`:
- Whitelisted authenticated users are auto-added to `hosted_users` on login.

`persist-auto-host=false`:
- User must already exist in `hosted_users` to be treated as hosted.

## Presence/profile/channel handling

Nodes currently support signed actions and relay for:
- Direct messages and ping/pong.
- Friend add/accept workflow.
- Group/channel create/invite/join/leave/send flows.
- Profile set/get.
- Presence keepalive/get with TTL clamping.

## Important flags

Common flags on `go run ./server`:
- `-listen`, `-advertise`, `-peers`
- `-sid`, `-key`, `-owner`
- `-client-mode`, `-client-allow`
- `-persistence-mode`, `-persistence-db`, `-persist-auto-host`, `-max-pending-msgs`
- `-relay`
- Limits: `-max-msg-bytes`, `-max-uncompressed-bytes`, `-max-expand-ratio`, `-max-msgs-per-sec`, `-burst`
- `-stats-http`, `-stats-addr`

## Runtime introspection

When enabled, the node serves local stats HTTP with:
- Summary/runtime metrics
- Peer list, negotiated caps, and ping checks


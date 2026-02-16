# Far Future Plan: Sharded + Mirrored Persistent Storage

## Why This Exists
This document is a long-horizon architecture plan for scaling persisted social/group/profile state beyond single-node SQLite while keeping operational complexity staged and manageable.

Current persistent domains:
- Friend graph edges
- Group/channel state
- User channel memberships
- Profile/avatar cache
- Optional queued/offline messages

## Goals
- Horizontally split storage across many nodes.
- Keep ownership/routing deterministic for each data key.
- Support optional mirroring by percentage (for durability/perf tradeoffs).
- Rebalance automatically as nodes join/leave.
- Preserve bounded storage policies (TTL + per-user caps).

## Non-Goals (Initial)
- Global cross-region strong consistency.
- Arbitrary multi-key transactions across shards.
- Full SQL federation.

## Data Model Split (By Keyspace)
Use separate logical keyspaces with independent shard maps:
- `friends` (user -> friend edges)
- `profiles` (user -> profile/avatar cache)
- `group_meta` (group/channel ownership + visibility)
- `memberships` (user -> group/channel memberships)
- `messages` (optional, if offline queues become distributed)

Reason: each keyspace has different access patterns and retention costs.

## Sharding Strategy
### Placement
- Use Rendezvous Hashing (HRW) per keyspace for simple membership changes.
- Key examples:
  - `friends:<login_id>`
  - `profiles:<login_id>`
  - `memberships:<login_id>`
  - `group_meta:<group>/<channel>`
- Each key resolves to an ordered node list (ranked by hash score).
- Rank 0 = primary owner.

### Unit of Movement
- Introduce virtual buckets (`bucket_id = hash(key) % B`) to make rebalance granular.
- Buckets map to owners; keys map to buckets.

## Mirroring Model (Percentage-Based)
Support **mirror percentage** `M` in `[0, 100]` per keyspace.

### Policy
- Base replication factor is always 1 primary.
- A deterministic subset of buckets gets an additional replica.
- For bucket `b`: mirror enabled if `hash(b, keyspace, epoch) % 100 < M`.
- If enabled:
  - replica node = next ranked owner (rank 1).
- Optional future extension: multiple mirrors by tiers (hot/cold keyspaces).

### Example
- `M=0`: primary only.
- `M=25`: ~25% of buckets have 1 mirror (RF=2), ~75% remain RF=1.
- `M=100`: all buckets mirrored once (RF=2 for all).

This provides linear durability/cost tuning without full RF inflation.

## Write Path (Target)
1. Client/API node computes primary owner from shard map.
2. Write sent to primary.
3. If bucket is mirror-enabled, primary forwards to mirror owner.
4. Ack modes:
   - `primary` (low latency)
   - `primary+mirror` (higher durability)
5. Conflict policy: last-write-wins with server timestamp + tie-breaker by node ID.

## Read Path (Target)
- Read from primary by default.
- Fallback to mirror if primary unavailable.
- Optional read-repair: if primary/mirror diverge, reconcile and write back.

## Rebalance + Membership Changes
- Shard map versioned and distributed via control plane gossip.
- On version change:
  - New owner starts pull of affected buckets.
  - Dual-write window from old owner to new owner.
  - Cutover once checksums converge.
- Keep per-bucket checksums for fast verification.

## Failure Handling
- Primary down:
  - If mirrored bucket: promote mirror for reads/writes until primary returns.
  - If non-mirrored: best-effort retry + queue (or temporary unavailable).
- Mirror down:
  - Continue primary writes; emit degraded durability metrics.

## Retention + Limits (Still Enforced)
Even after sharding, keep hard controls:
- Profile cache TTL: 90 days.
- Per-user friend edge cap.
- Per-user membership cap.
- Profile/avatar max sizes.

These limits are required for predictable per-node disk growth.

## Rollout Phases
1. **Phase 0: Single-node SQLite (current + hardened)**
   - Already in place with caps/TTL.
2. **Phase 1: Logical keyspace abstraction**
   - Introduce storage interface by keyspace.
3. **Phase 2: Bucketed ownership map (single owner)**
   - No mirroring yet, just shard split.
4. **Phase 3: Percentage mirroring**
   - Enable `M` per keyspace with deterministic bucket selection.
5. **Phase 4: Rebalance automation + repair**
   - Add migration orchestration and anti-entropy checks.
6. **Phase 5: Multi-region strategy**
   - Optional cross-region mirror tiers for critical keyspaces.

## Operational Metrics
Track per keyspace + shard:
- write/read latency p50/p95/p99
- rebalance lag
- mirror coverage achieved vs configured `M`
- stale replica count
- checksum mismatch rate
- bytes per user and per bucket

## Suggested Defaults (First Distributed Version)
- `friends`: `M=100` (high durability, small data)
- `profiles`: `M=50` (medium durability, larger footprint)
- `group_meta`: `M=100` (critical routing metadata)
- `memberships`: `M=100` (critical user continuity)
- `messages` (if enabled): `M=25` initially

## Open Questions
- Whether mirror policy should be bucket-based (this doc) or key-based.
- Whether `messages` should use same shard map or dedicated queue nodes.
- Whether promotion/failover should be automatic or operator-gated at first.

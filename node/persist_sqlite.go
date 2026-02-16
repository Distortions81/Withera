package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type storedMessage struct {
	ID      string
	From    string
	To      string
	Body    string
	Group   string
	Channel string
	Origin  string
	PubKey  string
	Sig     string
}

type sqliteStore struct {
	db              *sql.DB
	maxPendingUser  int
	maxFriendsUser  int
	maxChannelsUser int
}

func openSQLiteStore(path string, serverID string, ownerID string, maxPendingUser int, maxFriendsUser int, maxChannelsUser int) (*sqliteStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("sqlite path is required")
	}
	if err := ensureDir(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &sqliteStore{
		db:              db,
		maxPendingUser:  maxPendingUser,
		maxFriendsUser:  maxFriendsUser,
		maxChannelsUser: maxChannelsUser,
	}
	if store.maxPendingUser <= 0 {
		store.maxPendingUser = 500
	}
	if store.maxFriendsUser <= 0 {
		store.maxFriendsUser = 256
	}
	if store.maxChannelsUser <= 0 {
		store.maxChannelsUser = 512
	}
	if err := store.initSchema(serverID, ownerID); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.touchServer(serverID, ownerID); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return mkdirAll700(dir)
}

func mkdirAll700(path string) error {
	return os.MkdirAll(path, 0o700)
}

func (s *sqliteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *sqliteStore) initSchema(serverID string, ownerID string) error {
	schema := []string{
		`PRAGMA journal_mode=WAL;`,
		`CREATE TABLE IF NOT EXISTS meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS hosted_users (
			login_id TEXT PRIMARY KEY,
			created_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS pending_messages (
			seq INTEGER PRIMARY KEY AUTOINCREMENT,
			to_id TEXT NOT NULL,
			msg_id TEXT NOT NULL,
			from_id TEXT NOT NULL,
			body TEXT NOT NULL,
			group_name TEXT,
			channel_name TEXT,
			origin TEXT,
			pub_key TEXT,
			sig TEXT,
			created_at INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_pending_to_seq ON pending_messages(to_id, seq);`,
		`CREATE TABLE IF NOT EXISTS groups_meta (
			group_name TEXT PRIMARY KEY,
			creator_login_id TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS channels_meta (
			group_name TEXT NOT NULL,
			channel_name TEXT NOT NULL,
			creator_login_id TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(group_name, channel_name)
		);`,
		`CREATE TABLE IF NOT EXISTS servers_meta (
			server_id TEXT PRIMARY KEY,
			owner_login_id TEXT NOT NULL,
			seen_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS friend_edges (
			login_id TEXT NOT NULL,
			friend_login_id TEXT NOT NULL,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(login_id, friend_login_id)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_friend_edges_login_updated ON friend_edges(login_id, updated_at);`,
		`CREATE TABLE IF NOT EXISTS channels_state (
			group_name TEXT NOT NULL,
			channel_name TEXT NOT NULL,
			owner_login_id TEXT NOT NULL,
			is_public INTEGER NOT NULL,
			private_member_cap INTEGER NOT NULL DEFAULT 256,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(group_name, channel_name)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_channels_state_group ON channels_state(group_name);`,
		`CREATE TABLE IF NOT EXISTS user_channel_memberships (
			login_id TEXT NOT NULL,
			group_name TEXT NOT NULL,
			channel_name TEXT NOT NULL,
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(login_id, group_name, channel_name)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_user_memberships_login_updated ON user_channel_memberships(login_id, updated_at);`,
		`CREATE TABLE IF NOT EXISTS profile_cache (
			login_id TEXT PRIMARY KEY,
			nickname TEXT NOT NULL,
			profile_text TEXT NOT NULL,
			profile_image TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_profile_cache_updated ON profile_cache(updated_at);`,
		`CREATE TABLE IF NOT EXISTS group_profile_cache (
			group_name TEXT PRIMARY KEY,
			profile_text TEXT NOT NULL,
			profile_image TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_group_profile_cache_updated ON group_profile_cache(updated_at);`,
	}
	for _, stmt := range schema {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(`ALTER TABLE channels_state ADD COLUMN private_member_cap INTEGER NOT NULL DEFAULT 256`); err != nil {
		msg := strings.ToLower(strings.TrimSpace(err.Error()))
		if !strings.Contains(msg, "duplicate column name") {
			return err
		}
	}

	if err := s.setMetaIfMissing("server_id", serverID); err != nil {
		return err
	}
	if err := s.setMetaIfMissing("owner_id", ownerID); err != nil {
		return err
	}

	gotServerID, err := s.getMeta("server_id")
	if err != nil {
		return err
	}
	if gotServerID != serverID {
		return fmt.Errorf("sqlite db belongs to server_id=%s, expected=%s", gotServerID, serverID)
	}
	gotOwnerID, err := s.getMeta("owner_id")
	if err != nil {
		return err
	}
	if gotOwnerID != ownerID {
		return fmt.Errorf("sqlite db belongs to owner_id=%s, expected=%s", gotOwnerID, ownerID)
	}
	return nil
}

func (s *sqliteStore) setMetaIfMissing(key string, value string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)`, key, value)
	return err
}

func (s *sqliteStore) getMeta(key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("meta key %s missing", key)
		}
		return "", err
	}
	return value, nil
}

func (s *sqliteStore) touchServer(serverID string, ownerID string) error {
	if strings.TrimSpace(serverID) == "" || strings.TrimSpace(ownerID) == "" {
		return nil
	}
	now := time.Now().Unix()
	_, err := s.db.Exec(`
		INSERT INTO servers_meta(server_id, owner_login_id, seen_at)
		VALUES(?, ?, ?)
		ON CONFLICT(server_id) DO UPDATE SET
			owner_login_id = excluded.owner_login_id,
			seen_at = excluded.seen_at
	`, serverID, ownerID, now)
	return err
}

func (s *sqliteStore) addHostedUser(loginID string) error {
	if strings.TrimSpace(loginID) == "" {
		return nil
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO hosted_users(login_id, created_at) VALUES(?, ?)`, loginID, time.Now().Unix())
	return err
}

func (s *sqliteStore) isHostedUser(loginID string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM hosted_users WHERE login_id = ?`, loginID).Scan(&one)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *sqliteStore) rememberGroup(group string, creator string) error {
	group = strings.TrimSpace(group)
	if group == "" {
		return nil
	}
	now := time.Now().Unix()
	_, err := s.db.Exec(`
		INSERT INTO groups_meta(group_name, creator_login_id, created_at, updated_at)
		VALUES(?, ?, ?, ?)
		ON CONFLICT(group_name) DO UPDATE SET
			updated_at = excluded.updated_at
	`, group, creator, now, now)
	return err
}

func (s *sqliteStore) rememberChannel(group string, channel string, creator string) error {
	group = strings.TrimSpace(group)
	channel = strings.TrimSpace(channel)
	if group == "" || channel == "" {
		return nil
	}
	now := time.Now().Unix()
	_, err := s.db.Exec(`
		INSERT INTO channels_meta(group_name, channel_name, creator_login_id, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(group_name, channel_name) DO UPDATE SET
			updated_at = excluded.updated_at
	`, group, channel, creator, now, now)
	return err
}

func (s *sqliteStore) rememberChannelState(group string, channel string, owner string, public bool, privateCap int) error {
	group = strings.TrimSpace(group)
	channel = strings.TrimSpace(channel)
	owner = strings.TrimSpace(owner)
	if group == "" || channel == "" || owner == "" {
		return nil
	}
	now := time.Now().Unix()
	pub := 0
	if public {
		pub = 1
		privateCap = 0
	}
	if privateCap < 0 {
		privateCap = 0
	}
	_, err := s.db.Exec(`
		INSERT INTO channels_state(group_name, channel_name, owner_login_id, is_public, private_member_cap, updated_at)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(group_name, channel_name) DO UPDATE SET
			owner_login_id = excluded.owner_login_id,
			is_public = excluded.is_public,
			private_member_cap = excluded.private_member_cap,
			updated_at = excluded.updated_at
	`, group, channel, owner, pub, privateCap, now)
	return err
}

func (s *sqliteStore) rememberUserChannelMembership(loginID string, group string, channel string) error {
	loginID = strings.TrimSpace(loginID)
	group = strings.TrimSpace(group)
	channel = strings.TrimSpace(channel)
	if loginID == "" || group == "" || channel == "" {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Unix()
	_, err = tx.Exec(`
		INSERT INTO user_channel_memberships(login_id, group_name, channel_name, updated_at)
		VALUES(?, ?, ?, ?)
		ON CONFLICT(login_id, group_name, channel_name) DO UPDATE SET
			updated_at = excluded.updated_at
	`, loginID, group, channel, now)
	if err != nil {
		return err
	}

	var count int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM user_channel_memberships WHERE login_id = ?`, loginID).Scan(&count); err != nil {
		return err
	}
	over := count - s.maxChannelsUser
	if over > 0 {
		_, err = tx.Exec(`
			DELETE FROM user_channel_memberships
			WHERE rowid IN (
				SELECT rowid FROM user_channel_memberships
				WHERE login_id = ?
				ORDER BY updated_at ASC, group_name ASC, channel_name ASC
				LIMIT ?
			)
		`, loginID, over)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *sqliteStore) removeUserChannelMembership(loginID string, group string, channel string) error {
	loginID = strings.TrimSpace(loginID)
	group = strings.TrimSpace(group)
	channel = strings.TrimSpace(channel)
	if loginID == "" || group == "" || channel == "" {
		return nil
	}
	_, err := s.db.Exec(`
		DELETE FROM user_channel_memberships
		WHERE login_id = ? AND group_name = ? AND channel_name = ?
	`, loginID, group, channel)
	return err
}

type persistedChannelState struct {
	Group            string
	Channel          string
	Owner            string
	Public           bool
	PrivateMemberCap int
}

type persistedUserMembership struct {
	LoginID string
	Group   string
	Channel string
}

func (s *sqliteStore) loadAllChannelStates() ([]persistedChannelState, error) {
	rows, err := s.db.Query(`
		SELECT group_name, channel_name, owner_login_id, is_public, COALESCE(private_member_cap, 0)
		FROM channels_state
		ORDER BY group_name ASC, channel_name ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]persistedChannelState, 0)
	for rows.Next() {
		var st persistedChannelState
		var isPublic int
		if err := rows.Scan(&st.Group, &st.Channel, &st.Owner, &isPublic, &st.PrivateMemberCap); err != nil {
			return nil, err
		}
		st.Group = strings.TrimSpace(st.Group)
		st.Channel = strings.TrimSpace(st.Channel)
		st.Owner = strings.TrimSpace(st.Owner)
		st.Public = isPublic != 0
		if st.Group == "" || st.Channel == "" {
			continue
		}
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *sqliteStore) loadAllUserChannelMemberships() ([]persistedUserMembership, error) {
	rows, err := s.db.Query(`
		SELECT login_id, group_name, channel_name
		FROM user_channel_memberships
		ORDER BY login_id ASC, group_name ASC, channel_name ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]persistedUserMembership, 0)
	for rows.Next() {
		var m persistedUserMembership
		if err := rows.Scan(&m.LoginID, &m.Group, &m.Channel); err != nil {
			return nil, err
		}
		m.LoginID = strings.TrimSpace(m.LoginID)
		m.Group = strings.TrimSpace(m.Group)
		m.Channel = strings.TrimSpace(m.Channel)
		if m.LoginID == "" || m.Group == "" || m.Channel == "" {
			continue
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *sqliteStore) loadUserMembershipsWithChannelState(loginID string, limit int) ([]persistedChannelState, error) {
	loginID = strings.TrimSpace(loginID)
	if loginID == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = s.maxChannelsUser
		if limit <= 0 {
			limit = 512
		}
	}

	rows, err := s.db.Query(`
		SELECT m.group_name, m.channel_name,
		       COALESCE(cs.owner_login_id, ''), COALESCE(cs.is_public, 1), COALESCE(cs.private_member_cap, 0)
		FROM user_channel_memberships m
		LEFT JOIN channels_state cs
		  ON cs.group_name = m.group_name AND cs.channel_name = m.channel_name
		WHERE m.login_id = ?
		ORDER BY m.updated_at DESC, m.group_name ASC, m.channel_name ASC
		LIMIT ?
	`, loginID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]persistedChannelState, 0)
	for rows.Next() {
		var st persistedChannelState
		var isPublic int
		if err := rows.Scan(&st.Group, &st.Channel, &st.Owner, &isPublic, &st.PrivateMemberCap); err != nil {
			return nil, err
		}
		st.Group = strings.TrimSpace(st.Group)
		st.Channel = strings.TrimSpace(st.Channel)
		st.Owner = strings.TrimSpace(st.Owner)
		st.Public = isPublic != 0
		if st.Group == "" || st.Channel == "" {
			continue
		}
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type persistedProfileCacheEntry struct {
	LoginID   string
	Payload   profilePayload
	UpdatedAt int64
}

type persistedGroupProfileCacheEntry struct {
	Group     string
	Payload   groupProfilePayload
	UpdatedAt int64
}

func (s *sqliteStore) rememberProfileCache(loginID string, payload profilePayload) error {
	loginID = strings.TrimSpace(loginID)
	if loginID == "" {
		return nil
	}
	now := time.Now().Unix()
	_, err := s.db.Exec(`
		INSERT INTO profile_cache(login_id, nickname, profile_text, profile_image, updated_at)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(login_id) DO UPDATE SET
			nickname = excluded.nickname,
			profile_text = excluded.profile_text,
			profile_image = excluded.profile_image,
			updated_at = excluded.updated_at
	`, loginID, payload.Nickname, payload.ProfileText, payload.ProfileImage, now)
	return err
}

func (s *sqliteStore) loadProfileCache(maxAge time.Duration) ([]persistedProfileCacheEntry, error) {
	cutoff := int64(0)
	if maxAge > 0 {
		cutoff = time.Now().Add(-maxAge).Unix()
	}
	if cutoff > 0 {
		if _, err := s.db.Exec(`DELETE FROM profile_cache WHERE updated_at < ?`, cutoff); err != nil {
			return nil, err
		}
	}

	rows, err := s.db.Query(`
		SELECT login_id, nickname, profile_text, profile_image, updated_at
		FROM profile_cache
		ORDER BY updated_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]persistedProfileCacheEntry, 0)
	for rows.Next() {
		var e persistedProfileCacheEntry
		if err := rows.Scan(&e.LoginID, &e.Payload.Nickname, &e.Payload.ProfileText, &e.Payload.ProfileImage, &e.UpdatedAt); err != nil {
			return nil, err
		}
		e.LoginID = strings.TrimSpace(e.LoginID)
		e.Payload.Nickname = strings.TrimSpace(e.Payload.Nickname)
		e.Payload.ProfileText = strings.TrimSpace(e.Payload.ProfileText)
		e.Payload.ProfileImage = strings.TrimSpace(e.Payload.ProfileImage)
		if e.LoginID == "" {
			continue
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *sqliteStore) rememberGroupProfileCache(group string, payload groupProfilePayload) error {
	group = strings.TrimSpace(group)
	if group == "" {
		return nil
	}
	now := time.Now().Unix()
	_, err := s.db.Exec(`
		INSERT INTO group_profile_cache(group_name, profile_text, profile_image, updated_at)
		VALUES(?, ?, ?, ?)
		ON CONFLICT(group_name) DO UPDATE SET
			profile_text = excluded.profile_text,
			profile_image = excluded.profile_image,
			updated_at = excluded.updated_at
	`, group, payload.ProfileText, payload.ProfileImage, now)
	return err
}

func (s *sqliteStore) loadGroupProfileCache(maxAge time.Duration) ([]persistedGroupProfileCacheEntry, error) {
	cutoff := int64(0)
	if maxAge > 0 {
		cutoff = time.Now().Add(-maxAge).Unix()
	}
	if cutoff > 0 {
		if _, err := s.db.Exec(`DELETE FROM group_profile_cache WHERE updated_at < ?`, cutoff); err != nil {
			return nil, err
		}
	}

	rows, err := s.db.Query(`
		SELECT group_name, profile_text, profile_image, updated_at
		FROM group_profile_cache
		ORDER BY updated_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]persistedGroupProfileCacheEntry, 0)
	for rows.Next() {
		var e persistedGroupProfileCacheEntry
		if err := rows.Scan(&e.Group, &e.Payload.ProfileText, &e.Payload.ProfileImage, &e.UpdatedAt); err != nil {
			return nil, err
		}
		e.Group = strings.TrimSpace(e.Group)
		e.Payload.Group = e.Group
		e.Payload.ProfileText = strings.TrimSpace(e.Payload.ProfileText)
		e.Payload.ProfileImage = strings.TrimSpace(e.Payload.ProfileImage)
		if e.Group == "" {
			continue
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *sqliteStore) rememberFriendEdge(loginID string, friendID string) error {
	loginID = strings.TrimSpace(loginID)
	friendID = strings.TrimSpace(friendID)
	if loginID == "" || friendID == "" || loginID == friendID {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Unix()
	_, err = tx.Exec(`
		INSERT INTO friend_edges(login_id, friend_login_id, updated_at)
		VALUES(?, ?, ?)
		ON CONFLICT(login_id, friend_login_id) DO UPDATE SET
			updated_at = excluded.updated_at
	`, loginID, friendID, now)
	if err != nil {
		return err
	}

	var count int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM friend_edges WHERE login_id = ?`, loginID).Scan(&count); err != nil {
		return err
	}
	over := count - s.maxFriendsUser
	if over > 0 {
		_, err = tx.Exec(`
			DELETE FROM friend_edges
			WHERE rowid IN (
				SELECT rowid FROM friend_edges
				WHERE login_id = ?
				ORDER BY updated_at ASC, friend_login_id ASC
				LIMIT ?
			)
		`, loginID, over)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *sqliteStore) loadFriendEdges() ([][2]string, error) {
	rows, err := s.db.Query(`
		SELECT login_id, friend_login_id
		FROM friend_edges
		ORDER BY login_id ASC, friend_login_id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([][2]string, 0)
	for rows.Next() {
		var loginID string
		var friendID string
		if err := rows.Scan(&loginID, &friendID); err != nil {
			return nil, err
		}
		loginID = strings.TrimSpace(loginID)
		friendID = strings.TrimSpace(friendID)
		if loginID == "" || friendID == "" || loginID == friendID {
			continue
		}
		out = append(out, [2]string{loginID, friendID})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *sqliteStore) queueMessageForUser(toID string, msg storedMessage) error {
	toID = strings.TrimSpace(toID)
	if toID == "" {
		return nil
	}
	hosted, err := s.isHostedUser(toID)
	if err != nil {
		return err
	}
	if !hosted {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(`
		INSERT INTO pending_messages(to_id, msg_id, from_id, body, group_name, channel_name, origin, pub_key, sig, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, toID, msg.ID, msg.From, msg.Body, msg.Group, msg.Channel, msg.Origin, msg.PubKey, msg.Sig, time.Now().Unix())
	if err != nil {
		return err
	}

	var count int
	if err := tx.QueryRow(`SELECT COUNT(1) FROM pending_messages WHERE to_id = ?`, toID).Scan(&count); err != nil {
		return err
	}
	over := count - s.maxPendingUser
	if over > 0 {
		_, err = tx.Exec(`
			DELETE FROM pending_messages
			WHERE seq IN (
				SELECT seq FROM pending_messages WHERE to_id = ? ORDER BY seq ASC LIMIT ?
			)
		`, toID, over)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *sqliteStore) popPendingForUser(loginID string, limit int) ([]storedMessage, error) {
	if limit <= 0 {
		limit = 500
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.Query(`
		SELECT seq, msg_id, from_id, to_id, body, group_name, channel_name, origin, pub_key, sig
		FROM pending_messages
		WHERE to_id = ?
		ORDER BY seq ASC
		LIMIT ?
	`, loginID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type rowMsg struct {
		seq int64
		msg storedMessage
	}
	buf := make([]rowMsg, 0, limit)
	for rows.Next() {
		var r rowMsg
		if err := rows.Scan(&r.seq, &r.msg.ID, &r.msg.From, &r.msg.To, &r.msg.Body, &r.msg.Group, &r.msg.Channel, &r.msg.Origin, &r.msg.PubKey, &r.msg.Sig); err != nil {
			return nil, err
		}
		buf = append(buf, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(buf) == 0 {
		return nil, tx.Commit()
	}

	seqs := make([]int64, 0, len(buf))
	out := make([]storedMessage, 0, len(buf))
	for _, r := range buf {
		seqs = append(seqs, r.seq)
		out = append(out, r.msg)
	}

	q := `DELETE FROM pending_messages WHERE seq IN (` + placeholders(len(seqs)) + `)`
	args := make([]any, 0, len(seqs))
	for _, seq := range seqs {
		args = append(args, seq)
	}
	if _, err := tx.Exec(q, args...); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "?"
	}
	return strings.Join(parts, ",")
}

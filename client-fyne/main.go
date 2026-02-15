package main

import (
	"bytes"
	"compress/zlib"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"goaccord/internal/netsec"
)

type Packet struct {
	Type        string `json:"type"`
	Role        string `json:"role,omitempty"`
	ID          string `json:"id,omitempty"`
	From        string `json:"from,omitempty"`
	To          string `json:"to,omitempty"`
	Body        string `json:"body,omitempty"`
	Compression string `json:"compression,omitempty"`
	USize       int    `json:"usize,omitempty"`
	Group       string `json:"group,omitempty"`
	Channel     string `json:"channel,omitempty"`
	Public      bool   `json:"public,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
	PubKey      string `json:"pub_key,omitempty"`
	Sig         string `json:"sig,omitempty"`
	CreatedAt   int64  `json:"created_at,omitempty"`
}

type signedAction struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	From        string `json:"from"`
	To          string `json:"to,omitempty"`
	Body        string `json:"body,omitempty"`
	Compression string `json:"compression,omitempty"`
	USize       int    `json:"usize,omitempty"`
	Group       string `json:"group,omitempty"`
	Channel     string `json:"channel,omitempty"`
	Public      bool   `json:"public,omitempty"`
	CreatedAt   int64  `json:"created_at,omitempty"`
}

type keyFile struct {
	PrivateKey string `json:"private_key"`
}

type profileFile struct {
	DisplayName string `json:"display_name"`
	ProfileText string `json:"profile_text"`
}

type profilePayload struct {
	Nickname    string `json:"nickname,omitempty"`
	ProfileText string `json:"profile_text,omitempty"`
}

type presenceDataPayload struct {
	State     string `json:"state"`
	TTLSec    int    `json:"ttl_sec"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

type identityCandidate struct {
	Path    string
	LoginID string
	Name    string
}

type Conn struct {
	conn net.Conn
	enc  *json.Encoder
	mu   sync.Mutex
}

func (c *Conn) Send(p Packet) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enc.Encode(p)
}

type netMsg struct {
	pkt Packet
	err error
}

type chatMode string

const (
	chatModeDM      chatMode = "dm"
	chatModeGroup   chatMode = "group"
	compressionNone          = "none"
	compressionZlib          = "zlib"
)

type appState struct {
	mu sync.RWMutex

	conn    net.Conn
	sender  *Conn
	priv    ed25519.PrivateKey
	loginID string

	counter atomic.Uint64

	friends       map[string]struct{}
	pendingFriend map[string]struct{}
	groups        map[string]map[string]struct{}
	pendingInvite map[string]inviteEntry
	nicknames     map[string]string
	presence      map[string]string
	presenceTTL   map[string]int

	mode        chatMode
	targetDM    string
	targetGroup string
	targetChan  string
}

type inviteEntry struct {
	From    string
	Group   string
	Channel string
}

func newAppState() *appState {
	return &appState{
		friends:       make(map[string]struct{}),
		pendingFriend: make(map[string]struct{}),
		groups:        make(map[string]map[string]struct{}),
		pendingInvite: make(map[string]inviteEntry),
		nicknames:     make(map[string]string),
		presence:      make(map[string]string),
		presenceTTL:   make(map[string]int),
		mode:          chatModeDM,
	}
}

func (s *appState) setConn(conn net.Conn, sender *Conn, priv ed25519.PrivateKey, loginID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil && s.conn != conn {
		_ = s.conn.Close()
	}
	s.conn = conn
	s.sender = sender
	s.priv = priv
	s.loginID = strings.TrimSpace(loginID)
	s.counter.Store(0)
}

func (s *appState) closeConn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.conn = nil
	s.sender = nil
	s.priv = nil
	s.loginID = ""
}

func (s *appState) snapshotConn() (*Conn, ed25519.PrivateKey, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sender, s.priv, s.loginID
}

func (s *appState) nextMessageID() string {
	n := s.counter.Add(1)
	s.mu.RLock()
	prefix := s.loginID
	s.mu.RUnlock()
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	if strings.TrimSpace(prefix) == "" {
		prefix = "fyne"
	}
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), n)
}

func (s *appState) setDMTarget(target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = chatModeDM
	s.targetDM = strings.TrimSpace(target)
}

func (s *appState) setGroupTarget(group string, channel string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = chatModeGroup
	s.targetGroup = strings.TrimSpace(group)
	if strings.TrimSpace(channel) == "" {
		channel = "default"
	}
	s.targetChan = strings.TrimSpace(channel)
}

func (s *appState) currentTarget() (chatMode, string, string, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode, s.targetDM, s.targetGroup, s.targetChan
}

func (s *appState) addFriend(id string) {
	id = strings.TrimSpace(id)
	if !looksLikeLoginID(id) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.friends[id] = struct{}{}
	delete(s.pendingFriend, id)
}

func (s *appState) setNickname(id string, nickname string) {
	id = strings.TrimSpace(id)
	nickname = strings.TrimSpace(nickname)
	if !looksLikeLoginID(id) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if nickname == "" {
		delete(s.nicknames, id)
		return
	}
	s.nicknames[id] = nickname
}

func (s *appState) setPresence(id string, value string, ttl int) {
	id = strings.TrimSpace(id)
	value = strings.TrimSpace(strings.ToLower(value))
	if !looksLikeLoginID(id) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if value == "" {
		delete(s.presence, id)
		delete(s.presenceTTL, id)
		return
	}
	s.presence[id] = value
	if ttl > 0 {
		s.presenceTTL[id] = ttl
	}
}

func (s *appState) friendLabel(id string) string {
	id = strings.TrimSpace(id)
	s.mu.RLock()
	defer s.mu.RUnlock()
	label := shortID(id)
	if nick := strings.TrimSpace(s.nicknames[id]); nick != "" {
		label = nick + " (" + shortID(id) + ")"
	}
	if p := strings.TrimSpace(s.presence[id]); p != "" {
		label += " [" + p + "]"
	}
	return label
}

func (s *appState) addPendingFriend(id string) {
	id = strings.TrimSpace(id)
	if !looksLikeLoginID(id) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.friends[id]; ok {
		return
	}
	s.pendingFriend[id] = struct{}{}
}

func (s *appState) friendIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.friends))
	for id := range s.friends {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (s *appState) pendingFriendIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.pendingFriend))
	for id := range s.pendingFriend {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (s *appState) rememberGroup(group string, channel string) {
	group = normalizeGroupName(group)
	channel = strings.TrimSpace(channel)
	if group == "" {
		return
	}
	if channel == "" {
		channel = "default"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.groups[group] == nil {
		s.groups[group] = make(map[string]struct{})
	}
	s.groups[group][channel] = struct{}{}
}

func (s *appState) groupNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.groups))
	for group := range s.groups {
		out = append(out, group)
	}
	sort.Strings(out)
	return out
}

func (s *appState) channelsFor(group string) []string {
	group = normalizeGroupName(group)
	s.mu.RLock()
	defer s.mu.RUnlock()
	chset := s.groups[group]
	out := make([]string, 0, len(chset))
	for ch := range chset {
		out = append(out, ch)
	}
	sort.Strings(out)
	return out
}

func (s *appState) addInvite(from string, group string, channel string) {
	from = strings.TrimSpace(from)
	group = normalizeGroupName(group)
	channel = strings.TrimSpace(channel)
	if !looksLikeLoginID(from) || group == "" {
		return
	}
	if channel == "" {
		channel = "default"
	}
	key := from + "|" + group + "|" + channel
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingInvite[key] = inviteEntry{From: from, Group: group, Channel: channel}
}

func (s *appState) removeInvite(from string, group string, channel string) {
	from = strings.TrimSpace(from)
	group = normalizeGroupName(group)
	channel = strings.TrimSpace(channel)
	if channel == "" {
		channel = "default"
	}
	key := from + "|" + group + "|" + channel
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pendingInvite, key)
}

func (s *appState) invites() []inviteEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]inviteEntry, 0, len(s.pendingInvite))
	for _, inv := range s.pendingInvite {
		out = append(out, inv)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Group == out[j].Group {
			if out[i].Channel == out[j].Channel {
				return out[i].From < out[j].From
			}
			return out[i].Channel < out[j].Channel
		}
		return out[i].Group < out[j].Group
	})
	return out
}

func loginIDForPubKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

func looksLikeLoginID(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, ch := range v {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func shortID(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func normalizeGroupName(v string) string {
	v = strings.TrimSpace(v)
	v = strings.ToLower(v)
	if strings.HasPrefix(v, "grp.") {
		v = strings.TrimPrefix(v, "grp.")
	}
	return strings.TrimSpace(v)
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(kf.PrivateKey)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}
	return ed25519.PrivateKey(raw), nil
}

func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if _, err := os.Stat(path); err == nil {
		return loadKey(path)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := saveIdentityKey(path, priv); err != nil {
		return nil, err
	}
	return priv, nil
}

func saveIdentityKey(path string, priv ed25519.PrivateKey) error {
	payload, err := json.MarshalIndent(keyFile{PrivateKey: base64.StdEncoding.EncodeToString(priv)}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, payload, 0o600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func profilePathForKey(home string, keyPath string) string {
	return filepath.Join(home, ".goaccord", "profiles", "profile-"+filepath.Base(strings.TrimSpace(keyPath))+".json")
}

func loadDisplayName(home string, keyPath string) string {
	data, err := os.ReadFile(profilePathForKey(home, keyPath))
	if err != nil {
		return ""
	}
	var p profileFile
	if json.Unmarshal(data, &p) != nil {
		return ""
	}
	return strings.TrimSpace(p.DisplayName)
}

func loadLocalProfile(home string, keyPath string) (string, string) {
	data, err := os.ReadFile(profilePathForKey(home, keyPath))
	if err != nil {
		return "", ""
	}
	var p profileFile
	if json.Unmarshal(data, &p) != nil {
		return "", ""
	}
	return strings.TrimSpace(p.DisplayName), strings.TrimSpace(p.ProfileText)
}

func saveLocalProfile(home string, keyPath string, displayName string, profileText string) error {
	path := profilePathForKey(home, keyPath)
	raw := make(map[string]any)
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &raw)
	}
	raw["display_name"] = strings.TrimSpace(displayName)
	raw["profile_text"] = strings.TrimSpace(profileText)
	payload, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, payload, 0o600)
}

func listIdentityCandidates(home string, currentPath string) []identityCandidate {
	seen := make(map[string]struct{})
	paths := make([]string, 0)
	addPath := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		paths = append(paths, p)
	}
	addPath(currentPath)
	legacy := filepath.Join(home, ".goaccord", "ed25519_key.json")
	addPath(legacy)
	idsDir := filepath.Join(home, ".goaccord", "identities")
	if entries, err := os.ReadDir(idsDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
				continue
			}
			addPath(filepath.Join(idsDir, e.Name()))
		}
	}

	out := make([]identityCandidate, 0, len(paths))
	for _, p := range paths {
		priv, err := loadOrCreateKey(p)
		if err != nil {
			continue
		}
		pub := priv.Public().(ed25519.PublicKey)
		out = append(out, identityCandidate{
			Path:    p,
			LoginID: loginIDForPubKey(pub),
			Name:    loadDisplayName(home, p),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == currentPath {
			return true
		}
		if out[j].Path == currentPath {
			return false
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func copyIdentityFile(srcPath string, dstPath string) (string, error) {
	srcPath = strings.TrimSpace(srcPath)
	dstPath = strings.TrimSpace(dstPath)
	if srcPath == "" || dstPath == "" {
		return "", fmt.Errorf("source and destination are required")
	}
	if strings.HasSuffix(dstPath, string(os.PathSeparator)) {
		dstPath = filepath.Join(dstPath, filepath.Base(srcPath))
	} else if st, err := os.Stat(dstPath); err == nil && st.IsDir() {
		dstPath = filepath.Join(dstPath, filepath.Base(srcPath))
	}
	if filepath.Clean(srcPath) == filepath.Clean(dstPath) {
		return "", fmt.Errorf("backup path must be different from identity path")
	}
	raw, err := os.ReadFile(srcPath)
	if err != nil {
		return "", err
	}
	if err := writeFileAtomic(dstPath, raw, 0o600); err != nil {
		return "", err
	}
	return dstPath, nil
}

func base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	mod := new(big.Int)
	out := make([]byte, 0, len(input)*2)
	for x.Sign() > 0 {
		x.DivMod(x, base, mod)
		out = append(out, alphabet[mod.Int64()])
	}
	for i := 0; i < len(input) && input[i] == 0; i++ {
		out = append(out, alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func base58Decode(input string) ([]byte, error) {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	idx := make(map[rune]int, len(alphabet))
	for i, c := range alphabet {
		idx[c] = i
	}

	input = strings.Map(func(r rune) rune {
		switch r {
		case '-', ' ', '\t', '\n', '\r':
			return -1
		default:
			return r
		}
	}, strings.TrimSpace(input))
	if input == "" {
		return nil, fmt.Errorf("empty recovery text")
	}

	n := big.NewInt(0)
	base := big.NewInt(58)
	for _, c := range input {
		v, ok := idx[c]
		if !ok {
			return nil, fmt.Errorf("invalid base58 character: %q", c)
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(v)))
	}
	decoded := n.Bytes()
	leadingZeros := 0
	for _, c := range input {
		if c == '1' {
			leadingZeros++
			continue
		}
		break
	}
	if leadingZeros > 0 {
		decoded = append(make([]byte, leadingZeros), decoded...)
	}
	return decoded, nil
}

func groupedToken(s string, group int) string {
	if group <= 0 || len(s) <= group {
		return s
	}
	parts := make([]string, 0, (len(s)+group-1)/group)
	for i := 0; i < len(s); i += group {
		end := i + group
		if end > len(s) {
			end = len(s)
		}
		parts = append(parts, s[i:end])
	}
	return strings.Join(parts, "-")
}

func decodeTextBodyForClient(p Packet) (string, error) {
	comp := strings.ToLower(strings.TrimSpace(p.Compression))
	if comp == "" {
		comp = compressionNone
	}
	switch comp {
	case compressionNone:
		if p.USize > 0 && p.USize != len(p.Body) {
			return "", fmt.Errorf("usize mismatch")
		}
		return p.Body, nil
	case compressionZlib:
		if p.USize <= 0 {
			return "", fmt.Errorf("usize required")
		}
		raw, err := base64.StdEncoding.DecodeString(p.Body)
		if err != nil {
			return "", err
		}
		zr, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return "", err
		}
		defer zr.Close()
		decoded, err := io.ReadAll(io.LimitReader(zr, int64(p.USize)+1))
		if err != nil {
			return "", err
		}
		if len(decoded) != p.USize {
			return "", fmt.Errorf("decoded size mismatch")
		}
		return string(decoded), nil
	default:
		return "", fmt.Errorf("unsupported compression")
	}
}

func signAction(priv ed25519.PrivateKey, p Packet) (string, error) {
	msg, err := json.Marshal(signedAction{
		Type:        p.Type,
		ID:          p.ID,
		From:        p.From,
		To:          p.To,
		Body:        p.Body,
		Compression: p.Compression,
		USize:       p.USize,
		Group:       p.Group,
		Channel:     p.Channel,
		Public:      p.Public,
		CreatedAt:   p.CreatedAt,
	})
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, msg)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func runAuth(addr string, priv ed25519.PrivateKey) (net.Conn, *Conn, <-chan netMsg, string, error) {
	pub := priv.Public().(ed25519.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	conn, err := tls.Dial("tcp", addr, netsec.ClientTLSConfigInsecure())
	if err != nil {
		return nil, nil, nil, "", err
	}
	enc := &Conn{conn: conn, enc: json.NewEncoder(conn)}
	dec := json.NewDecoder(conn)

	if err := enc.Send(Packet{Type: "hello", Role: "user", PubKey: pubB64}); err != nil {
		_ = conn.Close()
		return nil, nil, nil, "", err
	}

	var challenge Packet
	if err := dec.Decode(&challenge); err != nil {
		_ = conn.Close()
		return nil, nil, nil, "", err
	}
	if challenge.Type != "challenge" || strings.TrimSpace(challenge.Nonce) == "" {
		_ = conn.Close()
		return nil, nil, nil, "", fmt.Errorf("invalid challenge")
	}

	loginSig := ed25519.Sign(priv, []byte("login:"+challenge.Nonce))
	if err := enc.Send(Packet{Type: "auth", PubKey: pubB64, Sig: base64.StdEncoding.EncodeToString(loginSig)}); err != nil {
		_ = conn.Close()
		return nil, nil, nil, "", err
	}

	var resp Packet
	if err := dec.Decode(&resp); err != nil {
		_ = conn.Close()
		return nil, nil, nil, "", err
	}
	if resp.Type != "ok" || strings.TrimSpace(resp.ID) == "" {
		_ = conn.Close()
		if resp.Type == "error" {
			return nil, nil, nil, "", fmt.Errorf("auth failed: %s", resp.Body)
		}
		return nil, nil, nil, "", fmt.Errorf("invalid auth response")
	}

	loginID := strings.TrimSpace(resp.ID)
	if expected := loginIDForPubKey(pub); expected != loginID {
		_ = conn.Close()
		return nil, nil, nil, "", fmt.Errorf("login id mismatch")
	}

	events := make(chan netMsg, 64)
	go func() {
		defer close(events)
		for {
			var p Packet
			if err := dec.Decode(&p); err != nil {
				events <- netMsg{err: err}
				return
			}
			events <- netMsg{pkt: p}
		}
	}()

	return conn, enc, events, loginID, nil
}

func sendSigned(s *appState, p Packet) error {
	sender, priv, from := s.snapshotConn()
	if sender == nil || len(priv) == 0 || strings.TrimSpace(from) == "" {
		return fmt.Errorf("not connected")
	}
	p.From = from
	p.ID = s.nextMessageID()
	p.CreatedAt = time.Now().UnixMilli()
	sig, err := signAction(priv, p)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	p.PubKey = base64.StdEncoding.EncodeToString(pub)
	p.Sig = sig
	return sender.Send(p)
}

func sendRaw(s *appState, p Packet) error {
	sender, _, _ := s.snapshotConn()
	if sender == nil {
		return fmt.Errorf("not connected")
	}
	return sender.Send(p)
}

func main() {
	home, _ := os.UserHomeDir()
	defaultKeyPath := filepath.Join(home, ".goaccord", "ed25519_key.json")

	fy := app.NewWithID("io.goaccord.client.fyne")
	state := newAppState()

	showLoginWindow(fy, home, defaultKeyPath, state)
	fy.Run()
}

func showLoginWindow(fy fyne.App, home string, defaultKeyPath string, state *appState) {
	w := fy.NewWindow("goAccord Login")
	w.Resize(fyne.NewSize(880, 620))

	title := widget.NewRichTextFromMarkdown("# Open Accord")
	subtitle := widget.NewLabel("Choose an identity, or create/restore one, then connect to a node.")

	serverEntry := widget.NewEntry()
	serverEntry.SetText("127.0.0.1:9101")
	serverEntry.SetPlaceHolder("node address")

	identitySelect := widget.NewSelect([]string{}, nil)
	identitySelect.PlaceHolder = "Select an identity"
	identityInfo := widget.NewLabel("")
	identityInfo.Wrapping = fyne.TextWrapWord

	var candidates []identityCandidate
	selectedPath := ""

	reloadIdentities := func(preferredPath string) {
		candidates = listIdentityCandidates(home, defaultKeyPath)
		opts := make([]string, 0, len(candidates))
		labelForPath := make(map[string]string, len(candidates))
		for _, c := range candidates {
			display := fmt.Sprintf("%s [%s]", shortID(c.LoginID), c.Path)
			if strings.TrimSpace(c.Name) != "" {
				display = fmt.Sprintf("%s (%s) [%s]", c.Name, shortID(c.LoginID), c.Path)
			}
			opts = append(opts, display)
			labelForPath[c.Path] = display
		}
		identitySelect.Options = opts
		identitySelect.ClearSelected()
		selectedPath = ""
		identityInfo.SetText("")
		if len(candidates) == 0 {
			identitySelect.Refresh()
			return
		}
		pick := candidates[0].Path
		if strings.TrimSpace(preferredPath) != "" {
			pick = strings.TrimSpace(preferredPath)
		}
		for _, c := range candidates {
			if c.Path == pick {
				selectedPath = c.Path
				identitySelect.SetSelected(labelForPath[c.Path])
				identityInfo.SetText(fmt.Sprintf("Login ID: %s\nPath: %s", c.LoginID, c.Path))
				break
			}
		}
		identitySelect.Refresh()
	}

	identitySelect.OnChanged = func(choice string) {
		for _, c := range candidates {
			display := fmt.Sprintf("%s [%s]", shortID(c.LoginID), c.Path)
			if strings.TrimSpace(c.Name) != "" {
				display = fmt.Sprintf("%s (%s) [%s]", c.Name, shortID(c.LoginID), c.Path)
			}
			if display == choice {
				selectedPath = c.Path
				identityInfo.SetText(fmt.Sprintf("Login ID: %s\nPath: %s", c.LoginID, c.Path))
				return
			}
		}
	}

	status := widget.NewLabel("Ready")
	status.Wrapping = fyne.TextWrapWord

	showError := func(err error) {
		if err == nil {
			return
		}
		dialog.ShowError(err, w)
		status.SetText(err.Error())
	}

	createBtn := widget.NewButton("Create Identity", func() {
		idsDir := filepath.Join(home, ".goaccord", "identities")
		if err := os.MkdirAll(idsDir, 0o700); err != nil {
			showError(err)
			return
		}
		path := filepath.Join(idsDir, fmt.Sprintf("id-%d.json", time.Now().UnixNano()))
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			showError(err)
			return
		}
		if err := saveIdentityKey(path, priv); err != nil {
			showError(err)
			return
		}

		recoveryRaw := base58Encode(priv.Seed())
		recoveryPretty := groupedToken(recoveryRaw, 5)
		dlgText := widget.NewMultiLineEntry()
		dlgText.SetText(recoveryPretty)
		dlgText.Disable()
		dlgText.SetMinRowsVisible(4)
		dialog.ShowCustom("Identity Created", "Close", container.NewVBox(
			widget.NewLabel("Identity created. Save this recovery key offline."),
			widget.NewLabel(path),
			dlgText,
			widget.NewLabel("Dashes are formatting only; ignore them when restoring."),
		), w)

		reloadIdentities(path)
		status.SetText("Created identity: " + path)
	})

	restoreBtn := widget.NewButton("Restore Identity", func() {
		recoveryEntry := widget.NewMultiLineEntry()
		recoveryEntry.SetPlaceHolder("Base58 recovery key (dashes/spaces ignored)")
		recoveryEntry.SetMinRowsVisible(3)
		form := dialog.NewForm("Restore Identity", "Restore", "Cancel", []*widget.FormItem{
			widget.NewFormItem("Recovery key", recoveryEntry),
		}, func(ok bool) {
			if !ok {
				return
			}
			seed, err := base58Decode(recoveryEntry.Text)
			if err != nil {
				showError(err)
				return
			}
			if len(seed) != ed25519.SeedSize {
				showError(fmt.Errorf("invalid recovery seed length: got %d bytes, expected %d", len(seed), ed25519.SeedSize))
				return
			}
			priv := ed25519.NewKeyFromSeed(seed)
			idsDir := filepath.Join(home, ".goaccord", "identities")
			if err := os.MkdirAll(idsDir, 0o700); err != nil {
				showError(err)
				return
			}
			path := filepath.Join(idsDir, fmt.Sprintf("id-%d.json", time.Now().UnixNano()))
			if err := saveIdentityKey(path, priv); err != nil {
				showError(err)
				return
			}
			reloadIdentities(path)
			status.SetText("Restored identity: " + path)
		}, w)
		form.Resize(fyne.NewSize(640, 360))
		form.Show()
	})

	backupBtn := widget.NewButton("Backup Identity", func() {
		if strings.TrimSpace(selectedPath) == "" {
			showError(fmt.Errorf("select an identity first"))
			return
		}
		dstEntry := widget.NewEntry()
		dstEntry.SetPlaceHolder("destination file or directory")
		form := dialog.NewForm("Backup Identity", "Save", "Cancel", []*widget.FormItem{
			widget.NewFormItem("Source", widget.NewLabel(selectedPath)),
			widget.NewFormItem("Destination", dstEntry),
		}, func(ok bool) {
			if !ok {
				return
			}
			savedPath, err := copyIdentityFile(selectedPath, dstEntry.Text)
			if err != nil {
				showError(err)
				return
			}
			status.SetText("Backup saved: " + savedPath)
		}, w)
		form.Resize(fyne.NewSize(640, 300))
		form.Show()
	})

	connectBtn := widget.NewButton("Connect", func() {
		addr := strings.TrimSpace(serverEntry.Text)
		if addr == "" {
			showError(fmt.Errorf("server address required"))
			return
		}
		if strings.TrimSpace(selectedPath) == "" {
			showError(fmt.Errorf("select an identity"))
			return
		}

		priv, err := loadOrCreateKey(selectedPath)
		if err != nil {
			showError(err)
			return
		}
		conn, sender, events, loginID, err := runAuth(addr, priv)
		if err != nil {
			showError(err)
			return
		}
		state.setConn(conn, sender, priv, loginID)
		state.setDMTarget("")
		status.SetText("Connected: " + shortID(loginID))

		showAppWindow(fy, home, addr, selectedPath, state, events, w)
		w.Hide()
	})

	reloadBtn := widget.NewButton("Reload", func() {
		reloadIdentities(selectedPath)
	})

	identityPanel := container.NewVBox(
		widget.NewLabel("Identity"),
		identitySelect,
		identityInfo,
		container.NewGridWithColumns(2, createBtn, restoreBtn),
		container.NewGridWithColumns(2, backupBtn, reloadBtn),
	)

	connectPanel := container.NewVBox(
		widget.NewLabel("Server"),
		serverEntry,
		connectBtn,
	)

	hero := container.NewVBox(
		title,
		subtitle,
		widget.NewSeparator(),
		widget.NewLabel("Flow"),
		widget.NewLabel("1. Choose/create/restore identity"),
		widget.NewLabel("2. Backup identity and recovery key"),
		widget.NewLabel("3. Connect and use chat UI"),
	)

	content := container.New(
		layout.NewGridLayoutWithColumns(2),
		container.NewPadded(hero),
		container.NewPadded(container.NewVBox(identityPanel, widget.NewSeparator(), connectPanel, widget.NewSeparator(), status)),
	)

	w.SetContent(content)
	w.SetCloseIntercept(func() {
		w.Close()
	})
	reloadIdentities(defaultKeyPath)
	w.Show()
}

func showAppWindow(fy fyne.App, home string, serverAddr string, keyPath string, state *appState, events <-chan netMsg, loginWindow fyne.Window) {
	w := fy.NewWindow("goAccord")
	w.Resize(fyne.NewSize(1180, 760))
	_, _, ownLoginID := state.snapshotConn()
	ownDisplayName, ownProfileText := loadLocalProfile(home, keyPath)
	if ownDisplayName == "" {
		ownDisplayName = "user-" + shortID(ownLoginID)
	}

	var chatMu sync.Mutex
	chatLines := make([]string, 0, 1000)
	appendChat := func(line string, chatEntry *widget.Entry) {
		chatMu.Lock()
		chatLines = append(chatLines, fmt.Sprintf("%s %s", time.Now().Format("15:04:05"), line))
		if len(chatLines) > 1200 {
			chatLines = chatLines[len(chatLines)-1200:]
		}
		joined := strings.Join(chatLines, "\n")
		chatMu.Unlock()
		fyne.Do(func() {
			chatEntry.SetText(joined)
			chatEntry.CursorRow = 1 << 20
			chatEntry.CursorColumn = 0
		})
	}

	var infoMu sync.Mutex
	infoLines := make([]string, 0, 300)
	appendInfo := func(line string, infoEntry *widget.Entry) {
		infoMu.Lock()
		infoLines = append(infoLines, fmt.Sprintf("%s %s", time.Now().Format("15:04:05"), line))
		if len(infoLines) > 300 {
			infoLines = infoLines[len(infoLines)-300:]
		}
		joined := strings.Join(infoLines, "\n")
		infoMu.Unlock()
		fyne.Do(func() {
			infoEntry.SetText(joined)
			infoEntry.CursorRow = 1 << 20
			infoEntry.CursorColumn = 0
		})
	}

	infoEntry := widget.NewMultiLineEntry()
	infoEntry.Disable()
	infoEntry.SetMinRowsVisible(7)

	friendIDs := make([]string, 0)
	friendLabels := make([]string, 0)
	friendsList := widget.NewList(
		func() int { return len(friendLabels) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(friendLabels[i])
		},
	)
	targetLabel := widget.NewLabel("DM: choose a friend")
	targetLabel.Wrapping = fyne.TextWrapWord

	requestFriendMetadata := func(id string) {
		id = strings.TrimSpace(id)
		if !looksLikeLoginID(id) {
			return
		}
		_ = sendSigned(state, Packet{Type: "profile_get", To: id})
		_ = sendRaw(state, Packet{Type: "presence_get", To: id})
	}

	setDMContext := func(id string) {
		id = strings.TrimSpace(id)
		if !looksLikeLoginID(id) {
			return
		}
		state.setDMTarget(id)
		targetLabel.SetText("DM: " + state.friendLabel(id))
		appendInfo("chat mode: dm -> "+shortID(id), infoEntry)
		requestFriendMetadata(id)
	}

	setGroupContext := func(group string, channel string) {
		group = normalizeGroupName(group)
		channel = strings.TrimSpace(channel)
		if group == "" {
			return
		}
		if channel == "" {
			channel = "default"
		}
		state.setGroupTarget(group, channel)
		targetLabel.SetText("Group: " + group + "/" + channel)
		appendInfo("chat mode: group -> "+group+"/"+channel, infoEntry)
	}

	friendsList.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(friendIDs) {
			return
		}
		setDMContext(friendIDs[id])
	}

	pendingIDs := make([]string, 0)
	pendingLabels := make([]string, 0)
	selectedPending := -1
	pendingList := widget.NewList(
		func() int { return len(pendingLabels) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(pendingLabels[i])
		},
	)
	pendingList.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(pendingIDs) {
			return
		}
		selectedPending = id
		appendInfo("pending friend selected: "+shortID(pendingIDs[id]), infoEntry)
	}

	groupsData := make([]string, 0)
	groupsList := widget.NewList(
		func() int { return len(groupsData) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(groupsData[i])
		},
	)

	channelsData := make([]string, 0)
	channelsList := widget.NewList(
		func() int { return len(channelsData) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(channelsData[i])
		},
	)

	selectedGroup := ""

	refreshChannels := func() {
		channelsData = state.channelsFor(selectedGroup)
		channelsList.Refresh()
	}

	groupsList.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(groupsData) {
			return
		}
		selectedGroup = groupsData[id]
		refreshChannels()
		if len(channelsData) > 0 {
			setGroupContext(selectedGroup, channelsData[0])
		}
	}

	channelsList.OnSelected = func(id widget.ListItemID) {
		if strings.TrimSpace(selectedGroup) == "" || id < 0 || id >= len(channelsData) {
			return
		}
		setGroupContext(selectedGroup, channelsData[id])
	}

	invitesData := make([]inviteEntry, 0)
	selectedInvite := -1
	invitesList := widget.NewList(
		func() int { return len(invitesData) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			inv := invitesData[i]
			o.(*widget.Label).SetText(fmt.Sprintf("%s: %s/%s", shortID(inv.From), inv.Group, inv.Channel))
		},
	)
	invitesList.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(invitesData) {
			return
		}
		selectedInvite = id
	}

	chatEntry := widget.NewMultiLineEntry()
	chatEntry.Disable()
	chatEntry.SetMinRowsVisible(24)

	messageEntry := widget.NewMultiLineEntry()
	messageEntry.SetMinRowsVisible(3)
	messageEntry.SetPlaceHolder("Type message")

	refreshLists := func() {
		friendIDs = state.friendIDs()
		friendLabels = make([]string, 0, len(friendIDs))
		for _, id := range friendIDs {
			friendLabels = append(friendLabels, state.friendLabel(id))
		}
		pendingIDs = state.pendingFriendIDs()
		pendingLabels = make([]string, 0, len(pendingIDs))
		for _, id := range pendingIDs {
			pendingLabels = append(pendingLabels, state.friendLabel(id))
		}
		groupsData = state.groupNames()
		invitesData = state.invites()
		if selectedPending >= len(pendingIDs) {
			selectedPending = -1
		}
		if selectedInvite >= len(invitesData) {
			selectedInvite = -1
		}
		if selectedGroup == "" && len(groupsData) > 0 {
			selectedGroup = groupsData[0]
		}
		refreshChannels()
		friendsList.Refresh()
		pendingList.Refresh()
		groupsList.Refresh()
		invitesList.Refresh()
	}

	sendBtn := widget.NewButton("Send", func() {
		body := strings.TrimSpace(messageEntry.Text)
		if body == "" {
			appendInfo("message is empty", infoEntry)
			return
		}
		mode, dm, group, channel := state.currentTarget()
		var err error
		switch mode {
		case chatModeGroup:
			if strings.TrimSpace(group) == "" {
				appendInfo("select a group/channel first", infoEntry)
				return
			}
			err = sendSigned(state, Packet{Type: "channel_send", Group: group, Channel: channel, Body: body})
			if err == nil {
				appendChat(fmt.Sprintf("you -> %s/%s: %s", group, channel, body), chatEntry)
			}
		default:
			if !looksLikeLoginID(dm) {
				appendInfo("select a friend for DM", infoEntry)
				return
			}
			err = sendSigned(state, Packet{Type: "send", To: dm, Body: body})
			if err == nil {
				appendChat(fmt.Sprintf("you -> %s: %s", state.friendLabel(dm), body), chatEntry)
			}
		}
		if err != nil {
			appendInfo("send failed: "+err.Error(), infoEntry)
			return
		}
		messageEntry.SetText("")
	})

	addFriendBtn := widget.NewButton("Add", func() {
		entry := widget.NewEntry()
		entry.SetPlaceHolder("friend login_id")
		form := dialog.NewForm("Friend Add", "Send", "Cancel", []*widget.FormItem{
			widget.NewFormItem("Login ID", entry),
		}, func(ok bool) {
			if !ok {
				return
			}
			target := strings.TrimSpace(entry.Text)
			if !looksLikeLoginID(target) {
				dialog.ShowError(fmt.Errorf("invalid login_id"), w)
				return
			}
			if err := sendSigned(state, Packet{Type: "friend_add", To: target}); err != nil {
				dialog.ShowError(err, w)
				return
			}
			appendInfo("friend request sent to "+shortID(target), infoEntry)
		}, w)
		form.Show()
	})

	acceptFriendBtn := widget.NewButton("Accept", func() {
		id := selectedPending
		if id < 0 || id >= len(pendingIDs) {
			appendInfo("select a pending friend", infoEntry)
			return
		}
		target := strings.TrimSpace(pendingIDs[id])
		if !looksLikeLoginID(target) {
			appendInfo("invalid pending friend", infoEntry)
			return
		}
		if err := sendSigned(state, Packet{Type: "friend_accept", To: target}); err != nil {
			appendInfo("accept failed: "+err.Error(), infoEntry)
			return
		}
		state.addFriend(target)
		refreshLists()
		appendInfo("friend accepted: "+shortID(target), infoEntry)
		setDMContext(target)
	})

	createGroupBtn := widget.NewButton("Create", func() {
		g := widget.NewEntry()
		g.SetPlaceHolder("group")
		ch := widget.NewEntry()
		ch.SetPlaceHolder("channel (default)")
		publicChk := widget.NewCheck("public", nil)
		form := dialog.NewForm("Create Group/Channel", "Create", "Cancel", []*widget.FormItem{
			widget.NewFormItem("Group", g),
			widget.NewFormItem("Channel", ch),
			widget.NewFormItem("Visibility", publicChk),
		}, func(ok bool) {
			if !ok {
				return
			}
			group := normalizeGroupName(g.Text)
			channel := strings.TrimSpace(ch.Text)
			if group == "" {
				dialog.ShowError(fmt.Errorf("group required"), w)
				return
			}
			if channel == "" {
				channel = "default"
			}
			if err := sendSigned(state, Packet{Type: "channel_create", Group: group, Channel: channel, Public: publicChk.Checked}); err != nil {
				dialog.ShowError(err, w)
				return
			}
			state.rememberGroup(group, channel)
			selectedGroup = group
			refreshLists()
			setGroupContext(group, channel)
			appendInfo("created channel "+group+"/"+channel, infoEntry)
		}, w)
		form.Resize(fyne.NewSize(520, 320))
		form.Show()
	})

	joinGroupBtn := widget.NewButton("Join", func() {
		g := widget.NewEntry()
		g.SetPlaceHolder("group")
		ch := widget.NewEntry()
		ch.SetPlaceHolder("channel (default)")
		form := dialog.NewForm("Join Group/Channel", "Join", "Cancel", []*widget.FormItem{
			widget.NewFormItem("Group", g),
			widget.NewFormItem("Channel", ch),
		}, func(ok bool) {
			if !ok {
				return
			}
			group := normalizeGroupName(g.Text)
			channel := strings.TrimSpace(ch.Text)
			if group == "" {
				dialog.ShowError(fmt.Errorf("group required"), w)
				return
			}
			if channel == "" {
				channel = "default"
			}
			if err := sendSigned(state, Packet{Type: "channel_join", Group: group, Channel: channel}); err != nil {
				dialog.ShowError(err, w)
				return
			}
			state.rememberGroup(group, channel)
			selectedGroup = group
			refreshLists()
			setGroupContext(group, channel)
			appendInfo("joined channel "+group+"/"+channel, infoEntry)
		}, w)
		form.Show()
	})

	inviteBtn := widget.NewButton("Invite", func() {
		group := selectedGroup
		if group == "" {
			appendInfo("select a group first", infoEntry)
			return
		}
		target := widget.NewEntry()
		target.SetPlaceHolder("friend login_id")
		form := dialog.NewForm("Invite To Group", "Invite", "Cancel", []*widget.FormItem{
			widget.NewFormItem("Target", target),
			widget.NewFormItem("Group", widget.NewLabel(group)),
		}, func(ok bool) {
			if !ok {
				return
			}
			id := strings.TrimSpace(target.Text)
			if !looksLikeLoginID(id) {
				dialog.ShowError(fmt.Errorf("invalid login_id"), w)
				return
			}
			if err := sendSigned(state, Packet{Type: "group_invite", To: id, Group: group}); err != nil {
				dialog.ShowError(err, w)
				return
			}
			appendInfo("invited "+shortID(id)+" to "+group, infoEntry)
		}, w)
		form.Show()
	})

	acceptInviteBtn := widget.NewButton("Accept", func() {
		id := selectedInvite
		if id < 0 || id >= len(invitesData) {
			appendInfo("select an invite", infoEntry)
			return
		}
		inv := invitesData[id]
		if err := sendSigned(state, Packet{Type: "channel_join", Group: inv.Group, Channel: inv.Channel}); err != nil {
			appendInfo("invite accept failed: "+err.Error(), infoEntry)
			return
		}
		state.rememberGroup(inv.Group, inv.Channel)
		state.removeInvite(inv.From, inv.Group, inv.Channel)
		selectedGroup = inv.Group
		refreshLists()
		setGroupContext(inv.Group, inv.Channel)
		appendInfo("invite accepted for "+inv.Group+"/"+inv.Channel, infoEntry)
	})

	rejectInviteBtn := widget.NewButton("Reject", func() {
		id := selectedInvite
		if id < 0 || id >= len(invitesData) {
			appendInfo("select an invite", infoEntry)
			return
		}
		inv := invitesData[id]
		if err := sendSigned(state, Packet{Type: "group_invite_reject", To: inv.From, Group: inv.Group}); err != nil {
			appendInfo("invite reject failed: "+err.Error(), infoEntry)
			return
		}
		state.removeInvite(inv.From, inv.Group, inv.Channel)
		refreshLists()
		appendInfo("invite rejected for "+inv.Group+" from "+shortID(inv.From), infoEntry)
	})

	profileBtn := widget.NewButton("Profile", func() {
		nameEntry := widget.NewEntry()
		nameEntry.SetText(strings.TrimSpace(ownDisplayName))
		textEntry := widget.NewMultiLineEntry()
		textEntry.SetText(strings.TrimSpace(ownProfileText))
		textEntry.SetMinRowsVisible(4)
		form := dialog.NewForm("Edit Profile", "Save", "Cancel", []*widget.FormItem{
			widget.NewFormItem("Display name", nameEntry),
			widget.NewFormItem("Profile text", textEntry),
		}, func(ok bool) {
			if !ok {
				return
			}
			payload, err := json.Marshal(profilePayload{
				Nickname:    strings.TrimSpace(nameEntry.Text),
				ProfileText: strings.TrimSpace(textEntry.Text),
			})
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if err := sendSigned(state, Packet{Type: "profile_set", Body: string(payload)}); err != nil {
				dialog.ShowError(err, w)
				return
			}
			ownDisplayName = strings.TrimSpace(nameEntry.Text)
			ownProfileText = strings.TrimSpace(textEntry.Text)
			if err := saveLocalProfile(home, keyPath, ownDisplayName, ownProfileText); err != nil {
				appendInfo("profile save warning: "+err.Error(), infoEntry)
			}
			appendInfo("profile updated", infoEntry)
		}, w)
		form.Resize(fyne.NewSize(620, 380))
		form.Show()
	})

	presenceBtn := widget.NewButton("Presence", func() {
		modeSel := widget.NewSelect([]string{"visible", "invisible"}, nil)
		modeSel.SetSelected("visible")
		ttlEntry := widget.NewEntry()
		ttlEntry.SetText("300")
		form := dialog.NewForm("Presence", "Update", "Cancel", []*widget.FormItem{
			widget.NewFormItem("Mode", modeSel),
			widget.NewFormItem("TTL sec", ttlEntry),
		}, func(ok bool) {
			if !ok {
				return
			}
			mode := strings.TrimSpace(modeSel.Selected)
			ttl := 300
			if strings.TrimSpace(ttlEntry.Text) != "" {
				if _, err := fmt.Sscanf(strings.TrimSpace(ttlEntry.Text), "%d", &ttl); err != nil || ttl < 180 || ttl > 900 {
					dialog.ShowError(fmt.Errorf("ttl must be a number between 180 and 900"), w)
					return
				}
			}
			payload, err := json.Marshal(map[string]any{
				"visible": mode == "visible",
				"ttl_sec": ttl,
			})
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if err := sendSigned(state, Packet{Type: "presence_keepalive", Body: string(payload)}); err != nil {
				dialog.ShowError(err, w)
				return
			}
			appendInfo("presence updated: "+mode, infoEntry)
		}, w)
		form.Show()
	})

	pingBtn := widget.NewButton("Ping", func() {
		mode, dm, _, _ := state.currentTarget()
		if mode != chatModeDM || !looksLikeLoginID(dm) {
			appendInfo("switch to a DM target to ping", infoEntry)
			return
		}
		if err := sendSigned(state, Packet{Type: "ping", To: dm}); err != nil {
			appendInfo("ping failed: "+err.Error(), infoEntry)
			return
		}
		appendInfo("ping sent to "+state.friendLabel(dm), infoEntry)
	})

	logoutBtn := widget.NewButton("Logout", func() {
		state.closeConn()
		w.Close()
		loginWindow.Show()
	})

	topBar := container.NewGridWithColumns(4, profileBtn, presenceBtn, pingBtn, logoutBtn)

	leftCol := container.NewVBox(
		topBar,
		widget.NewLabel("Friends"),
		container.NewGridWithColumns(2, addFriendBtn, acceptFriendBtn),
		container.NewVSplit(container.NewVScroll(friendsList), container.NewVScroll(pendingList)),
		widget.NewSeparator(),
		widget.NewLabel("Groups"),
		container.NewGridWithColumns(2, createGroupBtn, joinGroupBtn),
		inviteBtn,
		container.NewVSplit(container.NewVScroll(groupsList), container.NewVScroll(channelsList)),
		widget.NewSeparator(),
		widget.NewLabel("Invites"),
		container.NewGridWithColumns(2, acceptInviteBtn, rejectInviteBtn),
		container.NewVScroll(invitesList),
	)

	composer := container.NewBorder(nil, nil, nil, sendBtn, messageEntry)
	rightCol := container.NewBorder(
		container.NewVBox(widget.NewLabel("Context"), targetLabel, widget.NewLabel("Info"), infoEntry),
		composer,
		nil, nil,
		container.NewVBox(widget.NewLabel("Chat"), chatEntry),
	)

	root := container.NewHSplit(leftCol, rightCol)
	root.Offset = 0.31

	w.SetContent(root)
	w.SetCloseIntercept(func() {
		state.closeConn()
		w.Close()
		loginWindow.Show()
	})

	appendInfo("connected to "+serverAddr, infoEntry)
	appendInfo("key file: "+keyPath, infoEntry)
	if _, _, loginID := state.snapshotConn(); loginID != "" {
		appendInfo("login_id: "+loginID, infoEntry)
	}
	appendInfo("display name: "+ownDisplayName, infoEntry)
	_ = sendSigned(state, Packet{Type: "profile_set", Body: fmt.Sprintf("{\"nickname\":%q,\"profile_text\":%q}", ownDisplayName, ownProfileText)})
	refreshLists()

	go func() {
		for ev := range events {
			if ev.err != nil {
				appendInfo("connection closed: "+ev.err.Error(), infoEntry)
				state.closeConn()
				fyne.Do(func() {
					w.Close()
					loginWindow.Show()
				})
				return
			}
			p := ev.pkt
			switch p.Type {
			case "deliver":
				if looksLikeLoginID(p.From) && p.From != ownLoginID {
					state.addFriend(p.From)
					requestFriendMetadata(p.From)
				}
				actor := p.From
				if strings.TrimSpace(actor) == strings.TrimSpace(ownLoginID) {
					actor = p.To
				}
				appendChat(fmt.Sprintf("dm %s: %s", state.friendLabel(actor), p.Body), chatEntry)
			case "channel_deliver":
				state.rememberGroup(p.Group, p.Channel)
				appendChat(fmt.Sprintf("%s/%s %s: %s", p.Group, p.Channel, state.friendLabel(p.From), p.Body), chatEntry)
			case "friend_request":
				state.addPendingFriend(p.From)
				requestFriendMetadata(p.From)
				appendInfo("friend request from "+shortID(p.From), infoEntry)
			case "friend_update":
				other := strings.TrimSpace(p.From)
				if strings.TrimSpace(other) == strings.TrimSpace(ownLoginID) {
					other = p.To
				}
				if looksLikeLoginID(other) {
					state.addFriend(other)
					requestFriendMetadata(other)
				}
				appendInfo("friend update from="+shortID(p.From)+" to="+shortID(p.To), infoEntry)
			case "group_invite":
				state.addInvite(p.From, p.Group, p.Channel)
				appendInfo("group invite from "+shortID(p.From)+" to "+p.Group, infoEntry)
			case "group_invite_rejected":
				appendInfo("group invite rejected by "+shortID(p.From)+" for "+p.Group, infoEntry)
			case "channel_update", "channel_joined":
				state.rememberGroup(p.Group, p.Channel)
				appendInfo(p.Type+": "+p.Group+"/"+p.Channel+" "+strings.TrimSpace(p.Body), infoEntry)
			case "profile_data":
				decoded, err := decodeTextBodyForClient(p)
				if err != nil {
					appendInfo("profile decode failed: "+err.Error(), infoEntry)
					break
				}
				var prof profilePayload
				if err := json.Unmarshal([]byte(decoded), &prof); err != nil {
					appendInfo("profile parse failed", infoEntry)
					break
				}
				nick := strings.TrimSpace(prof.Nickname)
				if nick != "" {
					state.setNickname(p.From, nick)
				}
				appendInfo("profile from "+shortID(p.From)+" nick="+nick, infoEntry)
			case "presence_data":
				var pd presenceDataPayload
				if err := json.Unmarshal([]byte(strings.TrimSpace(p.Body)), &pd); err == nil {
					state.setPresence(p.From, pd.State, pd.TTLSec)
				} else {
					state.setPresence(p.From, p.Body, 0)
				}
			case "error":
				appendInfo("server error: "+p.Body, infoEntry)
			default:
				raw, _ := json.Marshal(p)
				appendInfo("event: "+string(raw), infoEntry)
			}
			refreshLists()
		}
	}()

	w.Show()
}

package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"withera/internal/apphome"
	"withera/internal/netsec"
)

const (
	friendKeyMaxAge     = 30 * 24 * time.Hour
	maxPeerKeysPerLogin = 8
)

type e2eeKeyFile struct {
	PrivateKey string `json:"private_key"`
}

type e2eeStateFile struct {
	PeerKeys []savedPeerE2EE    `json:"peer_keys,omitempty"`
	Nonces   []savedFriendNonce `json:"nonces,omitempty"`
}

type savedPeerE2EE struct {
	LoginID string `json:"login_id"`
	E2EEPub string `json:"e2ee_pub"`
	SeenAt  int64  `json:"seen_at,omitempty"`
}

type savedFriendNonce struct {
	LoginID string `json:"login_id"`
	Nonce   string `json:"nonce"`
	TS      int64  `json:"ts"`
}

type friendKeyPayload struct {
	E2EEPub string `json:"e2ee_pub"`
	PubKey  string `json:"pub_key"`
	Sig     string `json:"sig"`
	TS      int64  `json:"ts"`
	Nonce   string `json:"nonce"`
}

func e2eePathForKey(home string, keyPath string) string {
	return filepath.Join(apphome.BaseDirForKeyPath(home, keyPath), "e2ee", "e2ee-"+filepath.Base(strings.TrimSpace(keyPath))+".json")
}

func e2eeStatePathForKey(home string, keyPath string) string {
	return filepath.Join(apphome.BaseDirForKeyPath(home, keyPath), "e2ee", "e2ee-state-"+filepath.Base(strings.TrimSpace(keyPath))+".json")
}

func loadOrCreateE2EEKey(path string) (*ecdh.PrivateKey, string, error) {
	if data, err := os.ReadFile(path); err == nil {
		var kf e2eeKeyFile
		if err := json.Unmarshal(data, &kf); err != nil {
			return nil, "", err
		}
		priv, pubB64, err := netsec.ParseX25519PrivateKeyB64(kf.PrivateKey)
		if err != nil {
			return nil, "", err
		}
		return priv, pubB64, nil
	}
	priv, pubB64, err := netsec.NewX25519Identity()
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, "", err
	}
	payload, err := json.MarshalIndent(e2eeKeyFile{PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes())}, "", "  ")
	if err != nil {
		return nil, "", err
	}
	if err := writeFileAtomic(path, payload, 0o600); err != nil {
		return nil, "", err
	}
	return priv, pubB64, nil
}

func loadE2EEState(path string) (map[string][]string, map[string]map[string]int64, error) {
	peerKeys := make(map[string][]string)
	nonces := make(map[string]map[string]int64)
	if strings.TrimSpace(path) == "" {
		return peerKeys, nonces, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return peerKeys, nonces, nil
		}
		return nil, nil, err
	}
	var f e2eeStateFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, nil, err
	}
	for _, p := range f.PeerKeys {
		id := strings.TrimSpace(p.LoginID)
		pub := strings.TrimSpace(p.E2EEPub)
		if looksLikeLoginID(id) && pub != "" {
			_ = addPeerKeyWithLimit(peerKeys, id, pub, maxPeerKeysPerLogin)
		}
	}
	for _, n := range f.Nonces {
		id := strings.TrimSpace(n.LoginID)
		nonce := strings.TrimSpace(n.Nonce)
		if !looksLikeLoginID(id) || nonce == "" || n.TS <= 0 {
			continue
		}
		if nonces[id] == nil {
			nonces[id] = make(map[string]int64)
		}
		nonces[id][nonce] = n.TS
	}
	return peerKeys, nonces, nil
}

func saveE2EEState(path string, peerKeys map[string][]string, nonces map[string]map[string]int64) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	ids := make([]string, 0, len(peerKeys))
	for id := range peerKeys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := e2eeStateFile{
		PeerKeys: make([]savedPeerE2EE, 0, len(ids)),
	}
	for _, id := range ids {
		if !looksLikeLoginID(id) {
			continue
		}
		for _, key := range peerKeys[id] {
			pub := strings.TrimSpace(key)
			if pub == "" {
				continue
			}
			out.PeerKeys = append(out.PeerKeys, savedPeerE2EE{LoginID: id, E2EEPub: pub, SeenAt: time.Now().Unix()})
		}
	}
	nonceRows := make([]savedFriendNonce, 0)
	nonceIDs := make([]string, 0, len(nonces))
	for id := range nonces {
		nonceIDs = append(nonceIDs, id)
	}
	sort.Strings(nonceIDs)
	for _, id := range nonceIDs {
		byNonce := nonces[id]
		if !looksLikeLoginID(id) || len(byNonce) == 0 {
			continue
		}
		keys := make([]string, 0, len(byNonce))
		for nonce := range byNonce {
			keys = append(keys, nonce)
		}
		sort.Strings(keys)
		for _, nonce := range keys {
			ts := byNonce[nonce]
			if strings.TrimSpace(nonce) == "" || ts <= 0 {
				continue
			}
			nonceRows = append(nonceRows, savedFriendNonce{LoginID: id, Nonce: nonce, TS: ts})
		}
	}
	out.Nonces = nonceRows
	payload, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, payload, 0o600)
}

func addPeerKeyWithLimit(m map[string][]string, loginID string, key string, limit int) bool {
	loginID = strings.TrimSpace(loginID)
	key = strings.TrimSpace(key)
	if loginID == "" || key == "" {
		return false
	}
	keys := m[loginID]
	for i, k := range keys {
		if k == key {
			if i == 0 {
				return false
			}
			copy(keys[1:i+1], keys[0:i])
			keys[0] = key
			m[loginID] = keys
			return true
		}
	}
	keys = append([]string{key}, keys...)
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	m[loginID] = keys
	return true
}

func randomNonceB64(n int) (string, error) {
	if n <= 0 {
		n = 16
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func friendKeyMessage(e2eePub string, ts int64, nonce string) []byte {
	return []byte(fmt.Sprintf("friend-e2ee-key-v1:%s:%d:%s", strings.TrimSpace(e2eePub), ts, strings.TrimSpace(nonce)))
}

func friendKeyBody(e2eePubB64 string, signingPriv ed25519.PrivateKey, signingPubB64 string) string {
	pub := strings.TrimSpace(e2eePubB64)
	if pub == "" {
		return ""
	}
	ts := time.Now().UnixMilli()
	nonce, err := randomNonceB64(16)
	if err != nil {
		return ""
	}
	sig := ed25519.Sign(signingPriv, friendKeyMessage(pub, ts, nonce))
	b, err := json.Marshal(friendKeyPayload{
		E2EEPub: pub,
		PubKey:  strings.TrimSpace(signingPubB64),
		Sig:     base64.StdEncoding.EncodeToString(sig),
		TS:      ts,
		Nonce:   nonce,
	})
	if err != nil {
		return ""
	}
	return string(b)
}

func parseFriendKey(body string, from string) (friendKeyPayload, bool, error) {
	var payload friendKeyPayload
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &payload); err != nil {
		return friendKeyPayload{}, false, nil
	}
	e2eePub := strings.TrimSpace(payload.E2EEPub)
	signingPubB64 := strings.TrimSpace(payload.PubKey)
	sigB64 := strings.TrimSpace(payload.Sig)
	nonce := strings.TrimSpace(payload.Nonce)
	if e2eePub == "" && signingPubB64 == "" && sigB64 == "" && nonce == "" && payload.TS == 0 {
		return friendKeyPayload{}, false, nil
	}
	if e2eePub == "" || signingPubB64 == "" || sigB64 == "" || nonce == "" || payload.TS <= 0 {
		return friendKeyPayload{}, true, fmt.Errorf("incomplete key payload")
	}
	pubRaw, err := base64.StdEncoding.DecodeString(signingPubB64)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return friendKeyPayload{}, true, fmt.Errorf("invalid pubkey")
	}
	if loginIDForPubKey(pubRaw) != strings.TrimSpace(from) {
		return friendKeyPayload{}, true, fmt.Errorf("identity mismatch")
	}
	sigRaw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sigRaw) != ed25519.SignatureSize {
		return friendKeyPayload{}, true, fmt.Errorf("invalid signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), friendKeyMessage(e2eePub, payload.TS, nonce), sigRaw) {
		return friendKeyPayload{}, true, fmt.Errorf("signature verify failed")
	}
	if payload.TS > time.Now().Add(5*time.Minute).UnixMilli() {
		return friendKeyPayload{}, true, fmt.Errorf("timestamp too far in future")
	}
	if payload.TS < time.Now().Add(-friendKeyMaxAge).UnixMilli() {
		return friendKeyPayload{}, true, fmt.Errorf("timestamp too old")
	}
	payload.E2EEPub = e2eePub
	payload.Nonce = nonce
	return payload, true, nil
}

func cloneMultiStringMap(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, v := range in {
		cp := append([]string(nil), v...)
		out[k] = cp
	}
	return out
}

func cloneNonceMap(in map[string]map[string]int64) map[string]map[string]int64 {
	out := make(map[string]map[string]int64, len(in))
	for id, byNonce := range in {
		row := make(map[string]int64, len(byNonce))
		for n, ts := range byNonce {
			row[n] = ts
		}
		out[id] = row
	}
	return out
}

func (s *appState) friendKeyBody() string {
	s.mu.RLock()
	e2eePub := strings.TrimSpace(s.e2eePubB64)
	signingPriv := s.priv
	signingPub := ""
	if len(signingPriv) > 0 {
		signingPub = base64.StdEncoding.EncodeToString(signingPriv.Public().(ed25519.PublicKey))
	}
	s.mu.RUnlock()
	if e2eePub == "" || len(signingPriv) == 0 || strings.TrimSpace(signingPub) == "" {
		return ""
	}
	return friendKeyBody(e2eePub, signingPriv, signingPub)
}

func (s *appState) consumeFriendKey(from string, body string) (string, bool, error) {
	from = strings.TrimSpace(from)
	payload, present, err := parseFriendKey(body, from)
	if err != nil {
		s.mu.Lock()
		s.e2eeIssues[from] = err.Error()
		s.mu.Unlock()
		return "", true, err
	}
	if !present {
		return "", false, nil
	}
	s.mu.Lock()
	if s.friendKeyNonces[from] == nil {
		s.friendKeyNonces[from] = make(map[string]int64)
	}
	if _, exists := s.friendKeyNonces[from][payload.Nonce]; exists {
		s.e2eeIssues[from] = "replayed key payload"
		s.mu.Unlock()
		return "", true, fmt.Errorf("replayed key payload")
	}
	if len(s.friendKeyNonces[from]) > 512 {
		s.friendKeyNonces[from] = make(map[string]int64)
	}
	s.friendKeyNonces[from][payload.Nonce] = payload.TS
	_ = addPeerKeyWithLimit(s.peerE2EEMulti, from, payload.E2EEPub, maxPeerKeysPerLogin)
	delete(s.e2eeIssues, from)
	statePath := strings.TrimSpace(s.e2eeStatePath)
	peer := cloneMultiStringMap(s.peerE2EEMulti)
	nonces := cloneNonceMap(s.friendKeyNonces)
	s.mu.Unlock()

	if statePath != "" {
		if err := saveE2EEState(statePath, peer, nonces); err != nil {
			return payload.E2EEPub, true, err
		}
	}
	return payload.E2EEPub, true, nil
}

func (s *appState) encryptDirectMessage(target string, plaintext string) (string, error) {
	target = strings.TrimSpace(target)
	s.mu.RLock()
	recipientPubs := append([]string(nil), s.peerE2EEMulti[target]...)
	e2eePriv := s.e2eePriv
	s.mu.RUnlock()
	if len(recipientPubs) == 0 {
		return "", fmt.Errorf("unable to send: recipient encryption key is missing or not verified; send/accept a friend request to exchange keys")
	}
	encrypted, err := netsec.EncryptDMMulti(e2eePriv, recipientPubs, plaintext)
	if err == nil {
		return encrypted, nil
	}
	msg := strings.TrimSpace(err.Error())
	switch {
	case strings.Contains(msg, "invalid recipient e2ee key"), strings.Contains(msg, "no recipient keys"):
		return "", fmt.Errorf("unable to send: recipient encryption key is invalid; re-run friend handshake (send/accept friend request) to refresh keys")
	default:
		return "", err
	}
}

func (s *appState) rotateE2EEKey() (int, error) {
	s.mu.Lock()
	path := strings.TrimSpace(s.e2eePath)
	statePath := strings.TrimSpace(s.e2eeStatePath)
	s.mu.Unlock()
	if path == "" {
		return 0, fmt.Errorf("missing e2ee key path")
	}
	priv, pubB64, err := netsec.NewX25519Identity()
	if err != nil {
		return 0, err
	}
	payload, err := json.MarshalIndent(e2eeKeyFile{PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes())}, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := writeFileAtomic(path, payload, 0o600); err != nil {
		return 0, err
	}

	s.mu.Lock()
	s.e2eePriv = priv
	s.e2eePubB64 = pubB64
	peer := cloneMultiStringMap(s.peerE2EEMulti)
	nonces := cloneNonceMap(s.friendKeyNonces)
	friends := make([]string, 0, len(s.friends))
	for id := range s.friends {
		friends = append(friends, id)
	}
	s.mu.Unlock()

	if statePath != "" {
		_ = saveE2EEState(statePath, peer, nonces)
	}

	shared := 0
	body := s.friendKeyBody()
	for _, id := range friends {
		if err := sendSigned(s, Packet{Type: "friend_add", To: id, Body: body}); err == nil {
			shared++
		}
	}
	return shared, nil
}

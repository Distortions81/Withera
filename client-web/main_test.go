package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func buildSignedFriendKeyBody(t *testing.T, priv ed25519.PrivateKey, e2eePub string, ts int64, nonce string) string {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, friendKeyMessage(e2eePub, ts, nonce))
	payload := friendKeyPayload{
		E2EEPub: e2eePub,
		PubKey:  base64.StdEncoding.EncodeToString(pub),
		Sig:     base64.StdEncoding.EncodeToString(sig),
		TS:      ts,
		Nonce:   nonce,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	return string(b)
}

func TestParseFriendKeyValid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	from := loginIDForPubKey(pub)
	body := buildSignedFriendKeyBody(t, priv, "test-e2ee-pub", time.Now().UnixMilli(), "nonce-1")

	payload, present, err := parseFriendKey(body, from)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !present {
		t.Fatalf("expected payload to be present")
	}
	if payload.E2EEPub != "test-e2ee-pub" {
		t.Fatalf("unexpected e2ee pub: %s", payload.E2EEPub)
	}
}

func TestParseFriendKeyRejectsBadSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	from := loginIDForPubKey(pub)
	body := buildSignedFriendKeyBody(t, priv, "test-e2ee-pub", time.Now().UnixMilli(), "nonce-2")

	var payload friendKeyPayload
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	payload.Sig = base64.StdEncoding.EncodeToString([]byte("bad-sig"))
	bad, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	_, present, err := parseFriendKey(string(bad), from)
	if !present {
		t.Fatalf("expected malformed payload to still count as present")
	}
	if err == nil {
		t.Fatalf("expected signature error")
	}
}

func TestConsumeFriendKeyRejectsReplayNonce(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	from := loginIDForPubKey(pub)
	body := buildSignedFriendKeyBody(t, priv, "test-e2ee-pub", time.Now().UnixMilli(), "nonce-replay")

	c := &webClient{
		peerE2EEMulti:   make(map[string][]string),
		friendKeyNonces: make(map[string]map[string]int64),
	}
	if _, err := c.consumeFriendKey(from, body); err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	if _, err := c.consumeFriendKey(from, body); err == nil {
		t.Fatalf("expected replay rejection")
	}
}

func TestAddPeerKeyWithLimitCapsAndMovesToFront(t *testing.T) {
	m := make(map[string][]string)
	loginID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if !addPeerKeyWithLimit(m, loginID, "k1", 2) {
		t.Fatalf("expected insert")
	}
	_ = addPeerKeyWithLimit(m, loginID, "k2", 2)
	_ = addPeerKeyWithLimit(m, loginID, "k3", 2)
	if len(m[loginID]) != 2 {
		t.Fatalf("expected capped length 2, got %d", len(m[loginID]))
	}
	if m[loginID][0] != "k3" || m[loginID][1] != "k2" {
		t.Fatalf("unexpected order after cap: %#v", m[loginID])
	}
	_ = addPeerKeyWithLimit(m, loginID, "k2", 2)
	if m[loginID][0] != "k2" {
		t.Fatalf("expected existing key moved to front: %#v", m[loginID])
	}
}

func TestParseFriendKeyRejectsIdentityMismatch(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	body := buildSignedFriendKeyBody(t, priv, "test-e2ee-pub", time.Now().UnixMilli(), "nonce-mismatch")
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("other keygen failed: %v", err)
	}

	_, present, err := parseFriendKey(body, loginIDForPubKey(otherPub))
	if !present {
		t.Fatalf("expected payload to be present")
	}
	if err == nil {
		t.Fatalf("expected identity mismatch error")
	}
}

func TestParseFriendKeyRejectsTooFarFutureTimestamp(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	from := loginIDForPubKey(pub)
	body := buildSignedFriendKeyBody(t, priv, "test-e2ee-pub", time.Now().Add(6*time.Minute).UnixMilli(), "nonce-future")

	_, present, err := parseFriendKey(body, from)
	if !present {
		t.Fatalf("expected payload to be present")
	}
	if err == nil {
		t.Fatalf("expected future timestamp rejection")
	}
}

func TestParseFriendKeyRejectsOldTimestamp(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	from := loginIDForPubKey(pub)
	body := buildSignedFriendKeyBody(t, priv, "test-e2ee-pub", time.Now().Add(-friendKeyMaxAge-time.Minute).UnixMilli(), "nonce-old")

	_, present, err := parseFriendKey(body, from)
	if !present {
		t.Fatalf("expected payload to be present")
	}
	if err == nil {
		t.Fatalf("expected old timestamp rejection")
	}
}

func TestParseFriendKeyRejectsIncompletePayload(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	from := loginIDForPubKey(pub)
	body := `{"e2ee_pub":"abc"}`

	_, present, err := parseFriendKey(body, from)
	if !present {
		t.Fatalf("expected payload to be present")
	}
	if err == nil {
		t.Fatalf("expected incomplete payload rejection")
	}
}

func TestUserIDRoundTrip(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	loginID := hex.EncodeToString(raw)
	userID := userIDForLoginID(loginID)
	if strings.TrimSpace(userID) == "" {
		t.Fatalf("expected non-empty user id")
	}
	got, ok := loginIDForUserID(userID)
	if !ok {
		t.Fatalf("expected successful decode")
	}
	if got != loginID {
		t.Fatalf("roundtrip mismatch: got=%s want=%s", got, loginID)
	}
}

func TestParseLoginIDTokenAcceptsBase58UserID(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(255 - i)
	}
	loginID := hex.EncodeToString(raw)
	userID := userIDForLoginID(loginID)
	if userID == "" {
		t.Fatalf("expected non-empty user id")
	}
	got, ok := parseLoginIDToken(userID)
	if !ok {
		t.Fatalf("expected parse ok")
	}
	if got != loginID {
		t.Fatalf("parsed login id mismatch: got=%s want=%s", got, loginID)
	}
}

func TestPublicGroupInviteCodeRoundTrip(t *testing.T) {
	code, err := makePublicGroupInviteCode("dev", "127.0.0.1:9101")
	if err != nil {
		t.Fatalf("make code failed: %v", err)
	}
	if strings.TrimSpace(code) == "" {
		t.Fatalf("expected non-empty code")
	}
	parsed, err := parsePublicGroupInviteCode(code)
	if err != nil {
		t.Fatalf("parse code failed: %v", err)
	}
	if parsed.Group != "dev" {
		t.Fatalf("group mismatch: got=%s want=dev", parsed.Group)
	}
	if parsed.Addr != "127.0.0.1:9101" {
		t.Fatalf("addr mismatch: got=%s", parsed.Addr)
	}
	if parsed.Scope != "public_group" {
		t.Fatalf("scope mismatch: got=%s", parsed.Scope)
	}
}

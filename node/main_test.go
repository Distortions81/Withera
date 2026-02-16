package main

import (
	"bytes"
	"compress/zlib"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goaccord/internal/netsec"
)

type testClient struct {
	conn    net.Conn
	enc     *json.Encoder
	dec     *json.Decoder
	priv    ed25519.PrivateKey
	pubB64  string
	loginID string
	counter uint64
}

type testServerConfig struct {
	maxMessageBytes       int
	maxMsgsPerSec         int
	burstMessages         int
	maxSeenEntries        int
	maxKnownAddrs         int
	knownAddrTTL          time.Duration
	clientAllow           []string
	persistenceMode       string
	persistenceDB         string
	persistAutoHost       bool
	persistPublicTopology bool
	persistChatMessages   bool
	maxChannelsPerGroup   int
	maxGroupNameLen       int
	maxChannelNameLen     int
	maxPendingMsgs        int
	preHostedUsers        []string
}

func defaultTestServerConfig() testServerConfig {
	return testServerConfig{
		maxMessageBytes:       defaultMaxMessageBytes,
		maxMsgsPerSec:         defaultMaxMsgsPerSec,
		burstMessages:         defaultBurstMessages,
		maxSeenEntries:        defaultMaxSeenEntries,
		maxKnownAddrs:         defaultMaxKnownAddrs,
		knownAddrTTL:          defaultKnownAddrTTL,
		persistenceMode:       persistenceModeLive,
		persistAutoHost:       true,
		persistPublicTopology: false,
		persistChatMessages:   false,
		maxChannelsPerGroup:   defaultMaxChannelsPerGroup,
		maxGroupNameLen:       defaultMaxGroupNameRunes,
		maxChannelNameLen:     defaultMaxChannelNameRunes,
		maxPendingMsgs:        500,
	}
}

func signTestMessage(priv ed25519.PrivateKey, id, from, to, body string) (string, error) {
	msg, err := json.Marshal(signedAction{Type: "send", ID: id, From: from, To: to, Body: body})
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, msg)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func startTestServer(t *testing.T, localSID, advertise string, seedAddrs []string, cfg testServerConfig) (string, *Server, func()) {
	t.Helper()

	ownerPub, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key generation failed: %v", err)
	}
	ownerLoginID := loginIDForPubKey(ownerPub)
	id, err := composeServerID(ownerLoginID, localSID)
	if err != nil {
		t.Fatalf("composeServerID failed: %v", err)
	}

	s := NewServer(
		id,
		base64.StdEncoding.EncodeToString(ownerPub),
		ownerPriv,
		advertise,
		16,
		cfg.maxMessageBytes,
		cfg.maxMsgsPerSec,
		cfg.burstMessages,
		cfg.maxSeenEntries,
		cfg.maxKnownAddrs,
		cfg.knownAddrTTL,
	)
	s.persistenceMode = cfg.persistenceMode
	s.persistAutoHost = cfg.persistAutoHost
	s.persistPublicTopology = cfg.persistPublicTopology
	s.persistChatMessages = cfg.persistChatMessages
	if cfg.maxChannelsPerGroup > 0 {
		s.maxChannelsPerGroup = cfg.maxChannelsPerGroup
	}
	if cfg.maxGroupNameLen > 0 {
		s.maxGroupNameRunes = cfg.maxGroupNameLen
	}
	if cfg.maxChannelNameLen > 0 {
		s.maxChannelNameRunes = cfg.maxChannelNameLen
	}
	s.maxPendingMsgs = cfg.maxPendingMsgs
	for _, id := range cfg.clientAllow {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		s.clientAllow[id] = struct{}{}
	}
	if s.persistenceMode == persistenceModePersist {
		store, err := openSQLiteStore(cfg.persistenceDB, s.id, ownerLoginID, s.maxPendingMsgs)
		if err != nil {
			t.Fatalf("openSQLiteStore failed: %v", err)
		}
		s.store = store
		for _, u := range cfg.preHostedUsers {
			if err := s.store.addHostedUser(u); err != nil {
				t.Fatalf("pre-host user failed: %v", err)
			}
		}
	}
	for _, seed := range seedAddrs {
		s.addKnownAddr(seed)
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key")
	if err := netsec.EnsureSelfSignedCert(certPath, keyPath, []string{"127.0.0.1", "localhost"}); err != nil {
		t.Fatalf("tls cert setup failed: %v", err)
	}
	tcfg, err := netsec.ServerTLSConfig(certPath, keyPath)
	if err != nil {
		t.Fatalf("tls config failed: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tcfg)
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serveConn(conn)
		}
	}()
	go s.peerManager()

	stop := func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("server did not stop")
		}
		if s.store != nil {
			if err := s.store.Close(); err != nil {
				t.Fatalf("store close failed: %v", err)
			}
		}
	}

	return ln.Addr().String(), s, stop
}

func newTestClient(t *testing.T, addr string) *testClient {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	return newTestClientWithKey(t, addr, priv)
}

func newTestClientWithKey(t *testing.T, addr string, priv ed25519.PrivateKey) *testClient {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	conn, err := tls.Dial("tcp", addr, netsec.ClientTLSConfigInsecure())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}

	c := &testClient{conn: conn, enc: json.NewEncoder(conn), dec: json.NewDecoder(conn), priv: priv, pubB64: pubB64}

	if err := c.enc.Encode(Packet{Type: "hello", Role: "user", PubKey: pubB64}); err != nil {
		t.Fatalf("hello send failed: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var challenge Packet
	if err := c.dec.Decode(&challenge); err != nil {
		t.Fatalf("challenge read failed: %v", err)
	}
	if challenge.Type != "challenge" || challenge.Nonce == "" {
		t.Fatalf("unexpected challenge: %+v", challenge)
	}

	sig := ed25519.Sign(priv, []byte("login:"+challenge.Nonce))
	if err := c.enc.Encode(Packet{Type: "auth", PubKey: pubB64, Sig: base64.StdEncoding.EncodeToString(sig)}); err != nil {
		t.Fatalf("auth send failed: %v", err)
	}

	var ok Packet
	if err := c.dec.Decode(&ok); err != nil {
		t.Fatalf("auth response read failed: %v", err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	if ok.Type != "ok" || ok.ID == "" {
		t.Fatalf("unexpected auth response: %+v", ok)
	}
	if want := loginIDForPubKey(pub); ok.ID != want {
		t.Fatalf("login id mismatch: got=%s want=%s", ok.ID, want)
	}
	c.loginID = ok.ID

	return c
}

func loginWithKey(t *testing.T, addr string, priv ed25519.PrivateKey) (Packet, error) {
	t.Helper()

	pub := priv.Public().(ed25519.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	conn, err := tls.Dial("tcp", addr, netsec.ClientTLSConfigInsecure())
	if err != nil {
		return Packet{}, err
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	if err := enc.Encode(Packet{Type: "hello", Role: "user", PubKey: pubB64}); err != nil {
		return Packet{}, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var challenge Packet
	if err := dec.Decode(&challenge); err != nil {
		return Packet{}, err
	}
	if challenge.Type != "challenge" {
		return challenge, nil
	}

	loginSig := ed25519.Sign(priv, []byte("login:"+challenge.Nonce))
	if err := enc.Encode(Packet{Type: "auth", PubKey: pubB64, Sig: base64.StdEncoding.EncodeToString(loginSig)}); err != nil {
		return Packet{}, err
	}

	var resp Packet
	err = dec.Decode(&resp)
	return resp, err
}

func waitForPeerCount(t *testing.T, s *Server, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		got := len(s.peers)
		s.mu.RUnlock()
		if got >= want {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("peer count did not reach %d", want)
}

func waitForUserDisconnected(t *testing.T, s *Server, loginID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		conns, ok := s.users[loginID]
		s.mu.RUnlock()
		if !ok || len(conns) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("user %s did not disconnect in time", loginID)
}

func (c *testClient) close() {
	_ = c.conn.Close()
}

func (c *testClient) sendAction(t *testing.T, p Packet) {
	t.Helper()
	c.counter++
	prefix := c.loginID
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	id := fmt.Sprintf("%s-test-%d", prefix, c.counter)
	p.ID = id
	p.From = c.loginID
	p.PubKey = c.pubB64
	sig, err := signAction(c.priv, p)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	p.Sig = sig
	if err := c.enc.Encode(p); err != nil {
		t.Fatalf("send failed: %v", err)
	}
}

func (c *testClient) send(t *testing.T, to, body string) {
	c.sendAction(t, Packet{Type: "send", To: to, Body: body})
}

func (c *testClient) recv(t *testing.T, timeout time.Duration) Packet {
	t.Helper()
	p, err := c.recvMaybe(timeout)
	if err != nil {
		t.Fatalf("recv failed: %v", err)
	}
	return p
}

func (c *testClient) recvMaybe(timeout time.Duration) (Packet, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()
	var p Packet
	err := c.dec.Decode(&p)
	return p, err
}

func TestMessageDeliveryBetweenClients(t *testing.T) {
	cfg := defaultTestServerConfig()
	addr, _, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	alice := newTestClient(t, addr)
	defer alice.close()
	bob := newTestClient(t, addr)
	defer bob.close()

	const body = "hello from alice"
	alice.send(t, bob.loginID, body)

	p := bob.recv(t, 2*time.Second)
	if p.Type != "deliver" {
		t.Fatalf("expected deliver, got: %+v", p)
	}
	if p.From != alice.loginID || p.To != bob.loginID || p.Body != body {
		t.Fatalf("unexpected payload: %+v", p)
	}
}

func TestMessageRelayAcrossPeers(t *testing.T) {
	cfg := defaultTestServerConfig()
	addrA, srvA, stopA := startTestServer(t, "s1", "", nil, cfg)
	defer stopA()
	addrB, _, stopB := startTestServer(t, "s1", "", []string{addrA}, cfg)
	defer stopB()

	srvA.addKnownAddr(addrB)
	go srvA.dialPeer(addrB)

	alice := newTestClient(t, addrA)
	defer alice.close()
	bob := newTestClient(t, addrB)
	defer bob.close()

	const body = "hello over peer link"
	alice.send(t, bob.loginID, body)

	p := bob.recv(t, 3*time.Second)
	if p.Type != "deliver" {
		t.Fatalf("expected deliver, got: %+v", p)
	}
	if p.From != alice.loginID || p.To != bob.loginID || p.Body != body {
		t.Fatalf("unexpected payload: %+v", p)
	}
}

func TestRelayTargetsKnownDMRoute(t *testing.T) {
	cfg := defaultTestServerConfig()
	addrA, srvA, stopA := startTestServer(t, "s1", "", nil, cfg)
	defer stopA()
	addrB, _, stopB := startTestServer(t, "s1", "", nil, cfg)
	defer stopB()
	addrC, _, stopC := startTestServer(t, "s1", "", nil, cfg)
	defer stopC()

	srvA.addKnownAddr(addrB)
	srvA.addKnownAddr(addrC)
	go srvA.dialPeer(addrB)
	go srvA.dialPeer(addrC)
	waitForPeerCount(t, srvA, 2, 2*time.Second)

	alice := newTestClient(t, addrA)
	defer alice.close()

	_, bobPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("bob key generation failed: %v", err)
	}
	bobOnB := newTestClientWithKey(t, addrB, bobPriv)
	defer bobOnB.close()
	bobOnC := newTestClientWithKey(t, addrC, bobPriv)
	defer bobOnC.close()

	bobOnB.send(t, alice.loginID, "prime-route")
	prime := alice.recv(t, 2*time.Second)
	if prime.Type != "deliver" {
		t.Fatalf("expected prime deliver, got %+v", prime)
	}

	alice.send(t, bobOnB.loginID, "only-b")
	onB := bobOnB.recv(t, 2*time.Second)
	if onB.Type != "deliver" || onB.Body != "only-b" {
		t.Fatalf("expected targeted deliver on route peer, got %+v", onB)
	}
	if p, err := bobOnC.recvMaybe(500 * time.Millisecond); err == nil {
		t.Fatalf("non-target peer session should not receive routed dm, got %+v", p)
	}
}

func TestOversizedPacketDropped(t *testing.T) {
	cfg := defaultTestServerConfig()
	cfg.maxMessageBytes = 512
	addr, _, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	alice := newTestClient(t, addr)
	defer alice.close()
	bob := newTestClient(t, addr)
	defer bob.close()

	hugeBody := strings.Repeat("X", 2000)
	alice.send(t, bob.loginID, hugeBody)

	if p, err := bob.recvMaybe(400 * time.Millisecond); err == nil {
		t.Fatalf("expected no delivery for oversized packet, got: %+v", p)
	}
}

func TestRateLimitDropsBurst(t *testing.T) {
	cfg := defaultTestServerConfig()
	cfg.maxMsgsPerSec = 1
	cfg.burstMessages = 1
	addr, _, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	alice := newTestClient(t, addr)
	defer alice.close()
	bob := newTestClient(t, addr)
	defer bob.close()

	alice.send(t, bob.loginID, "m1")
	alice.send(t, bob.loginID, "m2")
	alice.send(t, bob.loginID, "m3")

	got := 0
	for i := 0; i < 3; i++ {
		if _, err := bob.recvMaybe(300 * time.Millisecond); err == nil {
			got++
		}
	}
	if got > 1 {
		t.Fatalf("expected rate limiter to allow at most 1 immediate message, got %d", got)
	}
}

func TestClientModeDisabledRejectsLogins(t *testing.T) {
	cfg := defaultTestServerConfig()
	addr, s, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	s.clientMode = clientModeDisabled

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	resp, err := loginWithKey(t, addr, priv)
	if err != nil {
		t.Fatalf("login flow failed: %v", err)
	}
	if resp.Type != "error" {
		t.Fatalf("expected error, got %+v", resp)
	}
	if !strings.Contains(resp.Body, "client access not allowed") {
		t.Fatalf("unexpected error body: %q", resp.Body)
	}
}

func TestClientModePrivateAllowlist(t *testing.T) {
	cfg := defaultTestServerConfig()
	addr, s, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	s.clientMode = clientModePrivate

	allowedPub, allowedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("allowed key generation failed: %v", err)
	}
	s.clientAllow[loginIDForPubKey(allowedPub)] = struct{}{}

	_, blockedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("blocked key generation failed: %v", err)
	}

	allowedResp, err := loginWithKey(t, addr, allowedPriv)
	if err != nil {
		t.Fatalf("allowed login flow failed: %v", err)
	}
	if allowedResp.Type != "ok" {
		t.Fatalf("allowed login expected ok, got %+v", allowedResp)
	}

	blockedResp, err := loginWithKey(t, addr, blockedPriv)
	if err != nil {
		t.Fatalf("blocked login flow failed: %v", err)
	}
	if blockedResp.Type != "error" {
		t.Fatalf("blocked login expected error, got %+v", blockedResp)
	}
}

func TestNonRelayPeerDoesNotReceiveRelayedTraffic(t *testing.T) {
	cfg := defaultTestServerConfig()
	addrA, srvA, stopA := startTestServer(t, "s1", "", nil, cfg)
	defer stopA()
	addrB, srvB, stopB := startTestServer(t, "s1", "", nil, cfg)
	defer stopB()
	addrC, srvC, stopC := startTestServer(t, "s1", "", nil, cfg)
	defer stopC()

	srvA.relayEnabled = true
	srvB.relayEnabled = true
	srvC.relayEnabled = false

	srvA.addKnownAddr(addrB)
	srvA.addKnownAddr(addrC)
	go srvA.dialPeer(addrB)
	go srvA.dialPeer(addrC)
	waitForPeerCount(t, srvA, 2, 2*time.Second)

	alice := newTestClient(t, addrA)
	defer alice.close()
	bobRelay := newTestClient(t, addrB)
	defer bobRelay.close()
	bobNoRelay := newTestClient(t, addrC)
	defer bobNoRelay.close()

	alice.send(t, bobRelay.loginID, "to relay peer")
	relayMsg := bobRelay.recv(t, 2*time.Second)
	if relayMsg.Type != "deliver" {
		t.Fatalf("relay peer expected deliver, got %+v", relayMsg)
	}

	alice.send(t, bobNoRelay.loginID, "to non-relay peer")
	if p, err := bobNoRelay.recvMaybe(500 * time.Millisecond); err == nil {
		t.Fatalf("non-relay peer should not receive relayed traffic, got %+v", p)
	}
}

func TestPersistModeQueuesAndReplaysOfflineMessages(t *testing.T) {
	cfg := defaultTestServerConfig()
	cfg.persistenceMode = persistenceModePersist
	cfg.persistAutoHost = true
	cfg.persistChatMessages = true
	tempDir := t.TempDir()
	cfg.persistenceDB = tempDir + "/state.sqlite"

	_, alicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("alice key generation failed: %v", err)
	}
	_, bobPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("bob key generation failed: %v", err)
	}
	cfg.clientAllow = []string{
		loginIDForPubKey(alicePriv.Public().(ed25519.PublicKey)),
		loginIDForPubKey(bobPriv.Public().(ed25519.PublicKey)),
	}

	addr, s, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	alice := newTestClientWithKey(t, addr, alicePriv)
	defer alice.close()

	bob1 := newTestClientWithKey(t, addr, bobPriv)
	bobID := bob1.loginID
	bob1.close()
	waitForUserDisconnected(t, s, bobID, 2*time.Second)

	alice.send(t, bobID, "queued-1")

	bob2 := newTestClientWithKey(t, addr, bobPriv)
	defer bob2.close()

	msg := bob2.recv(t, 2*time.Second)
	if msg.Type != "deliver" {
		t.Fatalf("expected deliver, got %+v", msg)
	}
	if msg.Body != "queued-1" || msg.To != bobID {
		t.Fatalf("unexpected replay payload: %+v", msg)
	}
}

func TestPersistModeCanRequirePreHostedUsers(t *testing.T) {
	cfg := defaultTestServerConfig()
	cfg.persistenceMode = persistenceModePersist
	cfg.persistAutoHost = false
	cfg.persistChatMessages = true
	tempDir := t.TempDir()
	cfg.persistenceDB = tempDir + "/state.sqlite"

	_, blockedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("blocked key generation failed: %v", err)
	}
	allowedPub, allowedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("allowed key generation failed: %v", err)
	}
	blockedPub := blockedPriv.Public().(ed25519.PublicKey)
	allowedID := loginIDForPubKey(allowedPub)
	cfg.preHostedUsers = []string{allowedID}
	cfg.clientAllow = []string{allowedID, loginIDForPubKey(blockedPub)}

	addr, _, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	allowedResp, err := loginWithKey(t, addr, allowedPriv)
	if err != nil {
		t.Fatalf("allowed login flow failed: %v", err)
	}
	if allowedResp.Type != "ok" {
		t.Fatalf("allowed user expected ok, got %+v", allowedResp)
	}

	blockedResp, err := loginWithKey(t, addr, blockedPriv)
	if err != nil {
		t.Fatalf("blocked login flow failed: %v", err)
	}
	if blockedResp.Type != "error" {
		t.Fatalf("blocked user expected error, got %+v", blockedResp)
	}
	if !strings.Contains(blockedResp.Body, "client access not allowed") {
		t.Fatalf("unexpected blocked response: %+v", blockedResp)
	}
}

func TestPersistModeStoresTopologyOnlyForWhitelistedIdentities(t *testing.T) {
	cfg := defaultTestServerConfig()
	cfg.persistenceMode = persistenceModePersist
	cfg.persistAutoHost = true
	tempDir := t.TempDir()
	cfg.persistenceDB = tempDir + "/state.sqlite"

	allowedPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("allowed key generation failed: %v", err)
	}
	blockedPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("blocked key generation failed: %v", err)
	}
	allowedID := loginIDForPubKey(allowedPub)
	blockedID := loginIDForPubKey(blockedPub)
	cfg.clientAllow = []string{allowedID}

	_, s, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	s.processSignedAction(Packet{Type: "channel_create", From: blockedID, Group: "blocked-group", Channel: "main"})
	s.processSignedAction(Packet{Type: "channel_create", From: allowedID, Group: "allowed-group", Channel: "main"})

	var blockedCount int
	if err := s.store.db.QueryRow(`SELECT COUNT(1) FROM groups_meta WHERE group_name = ?`, "blocked-group").Scan(&blockedCount); err != nil {
		t.Fatalf("count blocked group failed: %v", err)
	}
	if blockedCount != 0 {
		t.Fatalf("expected blocked identity to skip persisted topology, got count=%d", blockedCount)
	}

	var allowedCount int
	if err := s.store.db.QueryRow(`SELECT COUNT(1) FROM groups_meta WHERE group_name = ?`, "allowed-group").Scan(&allowedCount); err != nil {
		t.Fatalf("count allowed group failed: %v", err)
	}
	if allowedCount != 1 {
		t.Fatalf("expected whitelisted identity to persist topology, got count=%d", allowedCount)
	}
}

func TestPersistModePublicTopologyStoresForAnyIdentity(t *testing.T) {
	cfg := defaultTestServerConfig()
	cfg.persistenceMode = persistenceModePersist
	cfg.persistAutoHost = true
	cfg.persistPublicTopology = true
	tempDir := t.TempDir()
	cfg.persistenceDB = tempDir + "/state.sqlite"

	allowedPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("allowed key generation failed: %v", err)
	}
	blockedPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("blocked key generation failed: %v", err)
	}
	allowedID := loginIDForPubKey(allowedPub)
	blockedID := loginIDForPubKey(blockedPub)
	cfg.clientAllow = []string{allowedID}

	_, s, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	s.processSignedAction(Packet{Type: "channel_create", From: blockedID, Group: "blocked-group", Channel: "main"})
	s.processSignedAction(Packet{Type: "channel_create", From: allowedID, Group: "allowed-group", Channel: "main"})

	var blockedCount int
	if err := s.store.db.QueryRow(`SELECT COUNT(1) FROM groups_meta WHERE group_name = ?`, "blocked-group").Scan(&blockedCount); err != nil {
		t.Fatalf("count blocked group failed: %v", err)
	}
	if blockedCount != 1 {
		t.Fatalf("expected non-whitelisted identity to persist topology with public mode, got count=%d", blockedCount)
	}

	var allowedCount int
	if err := s.store.db.QueryRow(`SELECT COUNT(1) FROM groups_meta WHERE group_name = ?`, "allowed-group").Scan(&allowedCount); err != nil {
		t.Fatalf("count allowed group failed: %v", err)
	}
	if allowedCount != 1 {
		t.Fatalf("expected whitelisted identity to persist topology, got count=%d", allowedCount)
	}
}

func TestPersistModeQueuesOnlyForWhitelistedIdentities(t *testing.T) {
	cfg := defaultTestServerConfig()
	cfg.persistenceMode = persistenceModePersist
	cfg.persistAutoHost = false
	cfg.persistChatMessages = true
	tempDir := t.TempDir()
	cfg.persistenceDB = tempDir + "/state.sqlite"

	allowedPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("allowed key generation failed: %v", err)
	}
	blockedPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("blocked key generation failed: %v", err)
	}
	allowedID := loginIDForPubKey(allowedPub)
	blockedID := loginIDForPubKey(blockedPub)
	cfg.clientAllow = []string{allowedID}
	cfg.preHostedUsers = []string{allowedID, blockedID}

	_, s, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	s.maybeQueueForHostedUser(Packet{ID: "allow-1", From: "sender", To: allowedID, Body: "ok"})
	s.maybeQueueForHostedUser(Packet{ID: "block-1", From: "sender", To: blockedID, Body: "no"})

	var allowedCount int
	if err := s.store.db.QueryRow(`SELECT COUNT(1) FROM pending_messages WHERE to_id = ?`, allowedID).Scan(&allowedCount); err != nil {
		t.Fatalf("count allowed pending failed: %v", err)
	}
	if allowedCount != 1 {
		t.Fatalf("expected whitelisted identity to have queued message, got count=%d", allowedCount)
	}

	var blockedCount int
	if err := s.store.db.QueryRow(`SELECT COUNT(1) FROM pending_messages WHERE to_id = ?`, blockedID).Scan(&blockedCount); err != nil {
		t.Fatalf("count blocked pending failed: %v", err)
	}
	if blockedCount != 0 {
		t.Fatalf("expected non-whitelisted identity to skip queued message, got count=%d", blockedCount)
	}
}

func TestPersistModeSkipsQueueWhenChatMessageStorageDisabled(t *testing.T) {
	cfg := defaultTestServerConfig()
	cfg.persistenceMode = persistenceModePersist
	cfg.persistAutoHost = false
	cfg.persistChatMessages = false
	tempDir := t.TempDir()
	cfg.persistenceDB = tempDir + "/state.sqlite"

	allowedPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("allowed key generation failed: %v", err)
	}
	allowedID := loginIDForPubKey(allowedPub)
	cfg.clientAllow = []string{allowedID}
	cfg.preHostedUsers = []string{allowedID}

	_, s, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	s.maybeQueueForHostedUser(Packet{ID: "allow-1", From: "sender", To: allowedID, Body: "ok"})

	var allowedCount int
	if err := s.store.db.QueryRow(`SELECT COUNT(1) FROM pending_messages WHERE to_id = ?`, allowedID).Scan(&allowedCount); err != nil {
		t.Fatalf("count allowed pending failed: %v", err)
	}
	if allowedCount != 0 {
		t.Fatalf("expected disabled chat message storage to skip queueing, got count=%d", allowedCount)
	}
}

func TestFriendAddAndAcceptCreatesMutualFriendship(t *testing.T) {
	cfg := defaultTestServerConfig()
	addr, s, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	alice := newTestClient(t, addr)
	defer alice.close()
	bob := newTestClient(t, addr)
	defer bob.close()

	alice.sendAction(t, Packet{Type: "friend_add", To: bob.loginID})
	time.Sleep(120 * time.Millisecond)
	bob.sendAction(t, Packet{Type: "friend_accept", To: alice.loginID})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.isFriend(alice.loginID, bob.loginID) && s.isFriend(bob.loginID, alice.loginID) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("friendship was not established")
}

func TestPublicChannelAllowsAnyUserToInviteAndJoin(t *testing.T) {
	cfg := defaultTestServerConfig()
	addr, s, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	alice := newTestClient(t, addr)
	defer alice.close()
	bob := newTestClient(t, addr)
	defer bob.close()
	charlie := newTestClient(t, addr)
	defer charlie.close()

	alice.sendAction(t, Packet{Type: "channel_create", Group: "dev", Channel: "general", Public: true})
	deadlineCreate := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadlineCreate) {
		s.mu.RLock()
		_, ok := s.channels[channelKey("dev", "general")]
		s.mu.RUnlock()
		if ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	bob.sendAction(t, Packet{Type: "group_invite", To: charlie.loginID, Group: "dev", Channel: "general"})
	time.Sleep(120 * time.Millisecond)
	charlie.sendAction(t, Packet{Type: "channel_join", Group: "dev", Channel: "general"})
	time.Sleep(120 * time.Millisecond)
	alice.sendAction(t, Packet{Type: "channel_send", Group: "dev", Channel: "general", Body: "hi channel"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		msg, err := charlie.recvMaybe(150 * time.Millisecond)
		if err != nil {
			continue
		}
		if msg.Type == "channel_deliver" && msg.Body == "hi channel" {
			return
		}
	}
	t.Fatalf("channel message not delivered to joined member")
}

func TestJoinGroupWithoutChannelJoinsPublicChannelsOnly(t *testing.T) {
	cfg := defaultTestServerConfig()
	addr, _, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	alice := newTestClient(t, addr)
	defer alice.close()
	charlie := newTestClient(t, addr)
	defer charlie.close()

	alice.sendAction(t, Packet{Type: "channel_create", Group: "hub", Channel: "general", Public: true})
	alice.sendAction(t, Packet{Type: "channel_create", Group: "hub", Channel: "announcements", Public: true})
	alice.sendAction(t, Packet{Type: "channel_create", Group: "hub", Channel: "ops", Public: false})
	time.Sleep(160 * time.Millisecond)

	charlie.sendAction(t, Packet{Type: "channel_join", Group: "hub", Channel: ""})

	joined := make(map[string]bool)
	deadlineJoin := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadlineJoin) && len(joined) < 2 {
		p, err := charlie.recvMaybe(180 * time.Millisecond)
		if err != nil {
			continue
		}
		if p.Type == "channel_joined" && strings.TrimSpace(p.Group) == "hub" {
			joined[strings.TrimSpace(p.Channel)] = true
		}
	}
	if !joined["general"] || !joined["announcements"] {
		t.Fatalf("expected joins for public channels, got: %+v", joined)
	}
	if joined["ops"] {
		t.Fatalf("did not expect private channel join: %+v", joined)
	}

	alice.sendAction(t, Packet{Type: "channel_send", Group: "hub", Channel: "general", Body: "public-1"})
	alice.sendAction(t, Packet{Type: "channel_send", Group: "hub", Channel: "announcements", Body: "public-2"})
	alice.sendAction(t, Packet{Type: "channel_send", Group: "hub", Channel: "ops", Body: "private-1"})

	seenBodies := make(map[string]bool)
	deadlineDeliver := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadlineDeliver) {
		p, err := charlie.recvMaybe(180 * time.Millisecond)
		if err != nil {
			continue
		}
		if p.Type == "channel_deliver" {
			seenBodies[p.Body] = true
		}
		if seenBodies["public-1"] && seenBodies["public-2"] {
			break
		}
	}
	if !seenBodies["public-1"] || !seenBodies["public-2"] {
		t.Fatalf("expected public deliveries, got: %+v", seenBodies)
	}
	if seenBodies["private-1"] {
		t.Fatalf("did not expect private delivery, got: %+v", seenBodies)
	}
}

func TestChannelCreateRejectsTooLongChannelName(t *testing.T) {
	cfg := defaultTestServerConfig()
	cfg.maxChannelNameLen = 8
	addr, _, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	alice := newTestClient(t, addr)
	defer alice.close()

	alice.sendAction(t, Packet{Type: "channel_create", Group: "dev", Channel: "channel-name-too-long", Public: true})

	resp := alice.recv(t, 2*time.Second)
	if resp.Type != "error" {
		t.Fatalf("expected error, got %+v", resp)
	}
	if !strings.Contains(resp.Body, "channel_create failed: channel too long") {
		t.Fatalf("unexpected error: %+v", resp)
	}
}

func TestChannelCreateRejectsOverMaxChannelsPerGroup(t *testing.T) {
	cfg := defaultTestServerConfig()
	cfg.maxChannelsPerGroup = 2
	addr, _, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	alice := newTestClient(t, addr)
	defer alice.close()

	alice.sendAction(t, Packet{Type: "channel_create", Group: "dev", Channel: "one", Public: true})
	alice.sendAction(t, Packet{Type: "channel_create", Group: "dev", Channel: "two", Public: true})
	alice.sendAction(t, Packet{Type: "channel_create", Group: "dev", Channel: "three", Public: true})

	sawError := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p, err := alice.recvMaybe(200 * time.Millisecond)
		if err != nil {
			continue
		}
		if p.Type == "error" {
			if strings.Contains(p.Body, "max channels per group reached") {
				sawError = true
				break
			}
		}
	}
	if !sawError {
		t.Fatalf("expected max channels per group error")
	}
}

func compressBodyForTest(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatalf("zlib write failed: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close failed: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestCompressedDirectMessageDelivery(t *testing.T) {
	cfg := defaultTestServerConfig()
	addr, _, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	alice := newTestClient(t, addr)
	defer alice.close()
	bob := newTestClient(t, addr)
	defer bob.close()

	body := strings.Repeat("compressible-text-", 20)
	alice.sendAction(t, Packet{Type: "send", To: bob.loginID, Body: compressBodyForTest(t, body), Compression: compressionZlib, USize: len(body)})

	p := bob.recv(t, 2*time.Second)
	if p.Type != "deliver" {
		t.Fatalf("expected deliver, got: %+v", p)
	}
	if p.Body != body {
		t.Fatalf("unexpected decoded body: got=%q want=%q", p.Body, body)
	}
}

func TestCompressedBodyRejectsOversizedDecoded(t *testing.T) {
	cfg := defaultTestServerConfig()
	addr, _, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	alice := newTestClient(t, addr)
	defer alice.close()
	bob := newTestClient(t, addr)
	defer bob.close()

	body := strings.Repeat("A", defaultMaxUncompressedBytes+128)
	alice.sendAction(t, Packet{Type: "send", To: bob.loginID, Body: compressBodyForTest(t, body), Compression: compressionZlib, USize: len(body)})

	if p, err := bob.recvMaybe(400 * time.Millisecond); err == nil {
		t.Fatalf("expected no delivery for oversized decoded body, got: %+v", p)
	}
}

func TestMultipleSessionsSameLoginReceiveDelivery(t *testing.T) {
	cfg := defaultTestServerConfig()
	addr, _, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	alice := newTestClient(t, addr)
	defer alice.close()

	_, bobPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("bob key generation failed: %v", err)
	}
	bobA := newTestClientWithKey(t, addr, bobPriv)
	defer bobA.close()
	bobB := newTestClientWithKey(t, addr, bobPriv)
	defer bobB.close()

	alice.send(t, bobA.loginID, "hello-both")

	msgA := bobA.recv(t, 2*time.Second)
	msgB := bobB.recv(t, 2*time.Second)
	if msgA.Type != "deliver" || msgB.Type != "deliver" {
		t.Fatalf("expected deliver on both sessions, got A=%+v B=%+v", msgA, msgB)
	}
	if msgA.Body != "hello-both" || msgB.Body != "hello-both" {
		t.Fatalf("unexpected message body A=%+v B=%+v", msgA, msgB)
	}
}

func TestPlaintextTCPConnectionRejected(t *testing.T) {
	cfg := defaultTestServerConfig()
	addr, _, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("plain dial failed: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(`{"type":"hello","role":"user"}` + "\n")); err != nil {
		t.Fatalf("plain write failed: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var p Packet
	err = json.NewDecoder(conn).Decode(&p)
	if err == nil {
		t.Fatalf("expected plaintext connection to fail, got packet: %+v", p)
	}
}

func TestAuthRejectsClaimedPubKeyMismatch(t *testing.T) {
	cfg := defaultTestServerConfig()
	addr, _, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	conn, err := tls.Dial("tcp", addr, netsec.ClientTLSConfigInsecure())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	pubA, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key A generation failed: %v", err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key B generation failed: %v", err)
	}

	if err := enc.Encode(Packet{Type: "hello", Role: "user", PubKey: base64.StdEncoding.EncodeToString(pubA)}); err != nil {
		t.Fatalf("hello send failed: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var challenge Packet
	if err := dec.Decode(&challenge); err != nil {
		t.Fatalf("challenge read failed: %v", err)
	}
	if challenge.Type != "challenge" || challenge.Nonce == "" {
		t.Fatalf("unexpected challenge: %+v", challenge)
	}

	loginSig := ed25519.Sign(privB, []byte("login:"+challenge.Nonce))
	if err := enc.Encode(Packet{
		Type:   "auth",
		PubKey: base64.StdEncoding.EncodeToString(pubB),
		Sig:    base64.StdEncoding.EncodeToString(loginSig),
	}); err != nil {
		t.Fatalf("auth send failed: %v", err)
	}

	var resp Packet
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("auth response read failed: %v", err)
	}
	if resp.Type != "error" {
		t.Fatalf("expected error response, got %+v", resp)
	}
	if !strings.Contains(resp.Body, "pubkey mismatch") {
		t.Fatalf("unexpected auth error: %+v", resp)
	}
}

func TestPeerHelloRejectsInvalidIdentityProof(t *testing.T) {
	cfg := defaultTestServerConfig()
	addr, _, stop := startTestServer(t, "s1", "", nil, cfg)
	defer stop()

	conn, err := tls.Dial("tcp", addr, netsec.ClientTLSConfigInsecure())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	ownerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key generation failed: %v", err)
	}
	peerID, err := composeServerID(loginIDForPubKey(ownerPub), "peer1")
	if err != nil {
		t.Fatalf("compose peer id failed: %v", err)
	}

	if err := enc.Encode(Packet{
		Type:   "hello",
		Role:   "server",
		ID:     peerID,
		PubKey: base64.StdEncoding.EncodeToString(ownerPub),
		Sig:    base64.StdEncoding.EncodeToString([]byte("bad-proof")),
	}); err != nil {
		t.Fatalf("peer hello send failed: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var resp Packet
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("peer response read failed: %v", err)
	}
	if resp.Type != "error" {
		t.Fatalf("expected error, got %+v", resp)
	}
	if !strings.Contains(resp.Body, "invalid server identity proof") {
		t.Fatalf("unexpected peer error: %+v", resp)
	}
}

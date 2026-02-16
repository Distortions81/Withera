package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"goaccord/internal/netsec"
)

func main() {
	configPath := flag.String("config", "", "path to TOML configuration file")
	listenAddr := flag.String("listen", ":9000", "tcp address to listen on")
	advertiseAddr := flag.String("advertise", "", "public host:port to share with peers")
	ownerClaim := flag.String("owner", "", "owner login id (sha256(pubkey))")
	localSID := flag.String("sid", "default", "owner-scoped local server id")
	ownerKeyPath := flag.String("key", "", "owner private key file")
	peersCSV := flag.String("peers", "", "comma-separated seed peer addresses (host:port)")
	maxPeers := flag.Int("max-peers", 32, "maximum concurrent peer sessions")
	maxMsgBytes := flag.Int("max-msg-bytes", defaultMaxMessageBytes, "maximum accepted packet size in bytes")
	maxUncompressedBytes := flag.Int("max-uncompressed-bytes", defaultMaxUncompressedBytes, "maximum accepted uncompressed text body size in bytes")
	maxExpandRatio := flag.Int("max-expand-ratio", defaultMaxExpandRatio, "maximum decoded/compressed size ratio for compressed bodies")
	maxMsgsPerSec := flag.Int("max-msgs-per-sec", defaultMaxMsgsPerSec, "maximum accepted packets per second per connection")
	burstMessages := flag.Int("burst", defaultBurstMessages, "burst packet allowance per connection")
	maxSeen := flag.Int("max-seen", defaultMaxSeenEntries, "maximum dedupe IDs kept in memory")
	maxKnownAddrs := flag.Int("max-known-addrs", defaultMaxKnownAddrs, "maximum known peer addresses kept in memory")
	knownAddrTTLStr := flag.String("known-addr-ttl", defaultKnownAddrTTL.String(), "known peer address TTL")
	relayEnabled := flag.Bool("relay", true, "relay messages across peer network")
	clientMode := flag.String("client-mode", clientModePublic, "client access mode: public|private|disabled")
	clientAllowCSV := flag.String("client-allow", "", "comma-separated login_id allowlist for client-mode=private")
	persistenceMode := flag.String("persistence-mode", persistenceModeLive, "storage mode: live|persist")
	persistenceDB := flag.String("persistence-db", "", "sqlite database path (used when persistence-mode=persist)")
	persistAutoHost := flag.Bool("persist-auto-host", true, "auto-register authenticated users as hosted users in persist mode")
	persistPublicTopology := flag.Bool("persist-public-topology", false, "persist group/channel metadata for all authenticated users in persist mode (not limited by client-allow)")
	persistChatMessages := flag.Bool("persist-chat-messages", false, "persist offline direct/group chat messages in persist mode")
	maxPendingMsgs := flag.Int("max-pending-msgs", 500, "maximum queued offline messages per hosted user in persist mode")
	maxChannelsPerGroup := flag.Int("max-channels-per-group", defaultMaxChannelsPerGroup, "maximum channels allowed per group")
	maxGroupNameLen := flag.Int("max-group-name-len", defaultMaxGroupNameRunes, "maximum group name length in characters")
	maxChannelNameLen := flag.Int("max-channel-name-len", defaultMaxChannelNameRunes, "maximum channel name length in characters")
	statsHTTP := flag.Bool("stats-http", true, "enable local HTTP stats page")
	statsAddr := flag.String("stats-addr", "", "stats HTTP listen address (default derived from -listen)")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file path (auto-generated if missing)")
	tlsKey := flag.String("tls-key", "", "TLS private key file path (auto-generated if missing)")
	flag.Parse()

	visited := make(map[string]bool)
	flag.CommandLine.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})

	if strings.TrimSpace(*configPath) != "" {
		cfg, err := loadNodeConfig(*configPath)
		if err != nil {
			log.Fatalf("config load failed: %v", err)
		}
		targets := map[string]any{
			"listen":                  listenAddr,
			"advertise":               advertiseAddr,
			"owner":                   ownerClaim,
			"sid":                     localSID,
			"key":                     ownerKeyPath,
			"peers":                   peersCSV,
			"max-peers":               maxPeers,
			"max-msg-bytes":           maxMsgBytes,
			"max-uncompressed-bytes":  maxUncompressedBytes,
			"max-expand-ratio":        maxExpandRatio,
			"max-msgs-per-sec":        maxMsgsPerSec,
			"burst":                   burstMessages,
			"max-seen":                maxSeen,
			"max-known-addrs":         maxKnownAddrs,
			"known-addr-ttl":          knownAddrTTLStr,
			"relay":                   relayEnabled,
			"client-mode":             clientMode,
			"client-allow":            clientAllowCSV,
			"persistence-mode":        persistenceMode,
			"persistence-db":          persistenceDB,
			"persist-auto-host":       persistAutoHost,
			"persist-public-topology": persistPublicTopology,
			"persist-chat-messages":   persistChatMessages,
			"max-pending-msgs":        maxPendingMsgs,
			"max-channels-per-group":  maxChannelsPerGroup,
			"max-group-name-len":      maxGroupNameLen,
			"max-channel-name-len":    maxChannelNameLen,
			"stats-http":              statsHTTP,
			"stats-addr":              statsAddr,
			"tls-cert":                tlsCert,
			"tls-key":                 tlsKey,
		}
		if err := applyConfigToFlags(cfg, flag.CommandLine, visited, targets); err != nil {
			log.Fatalf("config apply failed: %v", err)
		}
	}

	knownAddrTTL, err := time.ParseDuration(strings.TrimSpace(*knownAddrTTLStr))
	if err != nil {
		log.Fatalf("invalid -known-addr-ttl: %v", err)
	}

	if strings.TrimSpace(*ownerKeyPath) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("unable to resolve home directory: %v", err)
		}
		*ownerKeyPath = filepath.Join(home, ".goaccord", "server_owner_key.json")
	}
	if strings.TrimSpace(*tlsCert) == "" {
		*tlsCert = strings.TrimSpace(*ownerKeyPath) + ".tls.crt"
	}
	if strings.TrimSpace(*tlsKey) == "" {
		*tlsKey = strings.TrimSpace(*ownerKeyPath) + ".tls.key"
	}

	ownerPriv, err := loadOrCreateKey(*ownerKeyPath)
	if err != nil {
		log.Fatalf("owner key load/create failed: %v", err)
	}
	ownerPub := ownerPriv.Public().(ed25519.PublicKey)
	ownerLoginID := loginIDForPubKey(ownerPub)
	if strings.TrimSpace(*ownerClaim) != "" && strings.TrimSpace(*ownerClaim) != ownerLoginID {
		log.Fatalf("-owner mismatch: provided=%s derived=%s", strings.TrimSpace(*ownerClaim), ownerLoginID)
	}

	serverID, err := composeServerID(ownerLoginID, *localSID)
	if err != nil {
		log.Fatalf("invalid server identity: %v", err)
	}

	s := NewServer(
		serverID,
		base64.StdEncoding.EncodeToString(ownerPub),
		ownerPriv,
		*advertiseAddr,
		*maxPeers,
		*maxMsgBytes,
		*maxMsgsPerSec,
		*burstMessages,
		*maxSeen,
		*maxKnownAddrs,
		knownAddrTTL,
	)

	s.maxUncompressedBytes = *maxUncompressedBytes
	s.maxExpandRatio = *maxExpandRatio
	s.relayEnabled = *relayEnabled
	mode := strings.ToLower(strings.TrimSpace(*clientMode))
	switch mode {
	case clientModePublic, clientModePrivate, clientModeDisabled:
		s.clientMode = mode
	default:
		log.Fatalf("invalid -client-mode: %s", *clientMode)
	}
	for _, id := range strings.Split(*clientAllowCSV, ",") {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		s.clientAllow[id] = struct{}{}
	}
	if s.clientMode == clientModePrivate {
		if len(s.clientAllow) == 0 {
			log.Fatalf("client-mode=private requires -client-allow")
		}
	}

	s.persistAutoHost = *persistAutoHost
	s.persistPublicTopology = *persistPublicTopology
	s.persistChatMessages = *persistChatMessages
	s.maxPendingMsgs = *maxPendingMsgs
	if *maxChannelsPerGroup <= 0 {
		log.Fatalf("invalid -max-channels-per-group: must be > 0")
	}
	if *maxGroupNameLen <= 0 {
		log.Fatalf("invalid -max-group-name-len: must be > 0")
	}
	if *maxChannelNameLen <= 0 {
		log.Fatalf("invalid -max-channel-name-len: must be > 0")
	}
	s.maxChannelsPerGroup = *maxChannelsPerGroup
	s.maxGroupNameRunes = *maxGroupNameLen
	s.maxChannelNameRunes = *maxChannelNameLen
	pmode := strings.ToLower(strings.TrimSpace(*persistenceMode))
	switch pmode {
	case persistenceModeLive, persistenceModePersist:
		s.persistenceMode = pmode
	default:
		log.Fatalf("invalid -persistence-mode: %s", *persistenceMode)
	}
	if s.persistenceMode == persistenceModePersist {
		dbPath := strings.TrimSpace(*persistenceDB)
		if dbPath == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("unable to resolve home directory: %v", err)
			}
			dbPath = filepath.Join(home, ".goaccord", "state", strings.ReplaceAll(s.id, ":", "_")+".sqlite")
		}
		store, err := openSQLiteStore(
			dbPath,
			s.id,
			ownerLoginID,
			s.maxPendingMsgs,
			defaultMaxPersistedFriends,
			defaultMaxPersistedChannelsPerUser,
		)
		if err != nil {
			log.Fatalf("sqlite init failed: %v", err)
		}
		s.store = store
		s.loadPersistedFriendEdges()
		s.loadPersistedChannelsAndMemberships()
		s.loadPersistedProfiles()
		s.loadPersistedGroupProfiles()
		defer func() {
			if err := store.Close(); err != nil {
				log.Printf("sqlite close error: %v", err)
			}
		}()
		log.Printf("persistence: mode=%s db=%s max-pending-msgs=%d auto-host=%t public-topology=%t chat-messages=%t", s.persistenceMode, dbPath, s.maxPendingMsgs, s.persistAutoHost, s.persistPublicTopology, s.persistChatMessages)
	} else {
		log.Printf("persistence: mode=%s", s.persistenceMode)
	}
	go s.cleanupSeen(10 * time.Minute)
	go s.peerManager()
	if *statsHTTP {
		addr := strings.TrimSpace(*statsAddr)
		if addr == "" {
			if host, port, err := net.SplitHostPort(*listenAddr); err == nil {
				if n, err := strconv.Atoi(port); err == nil {
					statsPort := n + 1000
					if host == "" || host == "0.0.0.0" || host == "::" {
						host = "127.0.0.1"
					}
					addr = net.JoinHostPort(host, strconv.Itoa(statsPort))
				}
			}
		}
		if addr == "" {
			addr = "127.0.0.1:10000"
		}
		s.startStatsHTTP(addr)
	}

	if strings.TrimSpace(*peersCSV) != "" {
		for _, peer := range strings.Split(*peersCSV, ",") {
			peer = strings.TrimSpace(peer)
			if peer == "" {
				continue
			}
			s.addKnownAddr(peer)
		}
	}

	var ln net.Listener
	host := "localhost"
	if parsedHost, _, err := net.SplitHostPort(*listenAddr); err == nil && strings.TrimSpace(parsedHost) != "" {
		host = parsedHost
	}
	hosts := []string{host, "localhost", "127.0.0.1", "::1"}
	if advHost, _, err := net.SplitHostPort(strings.TrimSpace(*advertiseAddr)); err == nil && strings.TrimSpace(advHost) != "" {
		hosts = append(hosts, advHost)
	}
	if err := netsec.EnsureSelfSignedCert(*tlsCert, *tlsKey, hosts); err != nil {
		log.Fatalf("tls cert setup failed: %v", err)
	}
	tcfg, err := netsec.ServerTLSConfig(*tlsCert, *tlsKey)
	if err != nil {
		log.Fatalf("tls config failed: %v", err)
	}
	ln, err = tls.Listen("tcp", *listenAddr, tcfg)
	if err != nil {
		log.Fatalf("tls listen error: %v", err)
	}
	log.Printf("tls required cert=%s key=%s", *tlsCert, *tlsKey)
	log.Printf("server %q listening on %s", s.id, *listenAddr)
	log.Printf("owner login_id %q (key: %s)", ownerLoginID, *ownerKeyPath)
	log.Printf("limits: max-msg-bytes=%d max-uncompressed-bytes=%d max-expand-ratio=%d max-msgs-per-sec=%d burst=%d max-seen=%d max-known-addrs=%d known-addr-ttl=%s max-channels-per-group=%d max-group-name-len=%d max-channel-name-len=%d", s.maxMessageBytes, s.maxUncompressedBytes, s.maxExpandRatio, s.maxMsgsPerSec, s.burstMessages, s.maxSeenEntries, s.maxKnownAddrs, knownAddrTTL, s.maxChannelsPerGroup, s.maxGroupNameRunes, s.maxChannelNameRunes)
	if s.advertiseAddr != "" {
		log.Printf("advertising as %s", s.advertiseAddr)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go s.serveConn(conn)
	}
}

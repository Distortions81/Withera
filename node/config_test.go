package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadNodeConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.toml")
	content := `
listen = ":9101"
advertise = "127.0.0.1:9101"
sid = "peer1"
key = "/tmp/key.json"
client_mode = "public"
peers = ["127.0.0.1:9102", "127.0.0.1:9103"]
max_channels_per_group = 77
persist_public_topology = true
persist_chat_messages = true
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config failed: %v", err)
	}

	cfg, err := loadNodeConfig(path)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	if cfg.Listen != ":9101" {
		t.Fatalf("listen mismatch: %s", cfg.Listen)
	}
	if len(cfg.Peers) != 2 {
		t.Fatalf("peers mismatch: %#v", cfg.Peers)
	}
	if cfg.MaxChannelsPerGroup == nil || *cfg.MaxChannelsPerGroup != 77 {
		t.Fatalf("max_channels_per_group mismatch")
	}
	if cfg.PersistPublicTopo == nil || !*cfg.PersistPublicTopo {
		t.Fatalf("persist_public_topology mismatch")
	}
	if cfg.PersistChatMsgs == nil || !*cfg.PersistChatMsgs {
		t.Fatalf("persist_chat_messages mismatch")
	}
}

func TestApplyConfigToFlagsHonorsCLIOverrides(t *testing.T) {
	listen := ":9000"
	clientMode := "public"
	peers := ""
	maxPeers := 32

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.StringVar(&listen, "listen", listen, "")
	fs.StringVar(&clientMode, "client-mode", clientMode, "")
	fs.StringVar(&peers, "peers", peers, "")
	fs.IntVar(&maxPeers, "max-peers", maxPeers, "")

	visited := map[string]bool{
		"listen": true, // simulate user override
	}
	targets := map[string]any{
		"listen":      &listen,
		"client-mode": &clientMode,
		"peers":       &peers,
		"max-peers":   &maxPeers,
	}

	wantPeers := []string{"127.0.0.1:9102", "127.0.0.1:9103"}
	wantMaxPeers := 64
	cfg := nodeConfig{
		Listen:     ":9101",
		ClientMode: "private",
		Peers:      wantPeers,
		MaxPeers:   &wantMaxPeers,
	}
	if err := applyConfigToFlags(cfg, fs, visited, targets); err != nil {
		t.Fatalf("apply config failed: %v", err)
	}

	if listen != ":9000" {
		t.Fatalf("listen should keep CLI override, got %s", listen)
	}
	if clientMode != "private" {
		t.Fatalf("client-mode mismatch: got %s", clientMode)
	}
	if peers != "127.0.0.1:9102,127.0.0.1:9103" {
		t.Fatalf("peers mismatch: got %s", peers)
	}
	if maxPeers != 64 {
		t.Fatalf("max-peers mismatch: got %d", maxPeers)
	}
}

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

type nodeConfig struct {
	Listen               string   `toml:"listen"`
	Advertise            string   `toml:"advertise"`
	Owner                string   `toml:"owner"`
	SID                  string   `toml:"sid"`
	Key                  string   `toml:"key"`
	Peers                []string `toml:"peers"`
	MaxPeers             *int     `toml:"max_peers"`
	MaxMsgBytes          *int     `toml:"max_msg_bytes"`
	MaxUncompressedBytes *int     `toml:"max_uncompressed_bytes"`
	MaxExpandRatio       *int     `toml:"max_expand_ratio"`
	MaxMsgsPerSec        *int     `toml:"max_msgs_per_sec"`
	Burst                *int     `toml:"burst"`
	MaxSeen              *int     `toml:"max_seen"`
	MaxKnownAddrs        *int     `toml:"max_known_addrs"`
	KnownAddrTTL         string   `toml:"known_addr_ttl"`
	Relay                *bool    `toml:"relay"`
	ClientMode           string   `toml:"client_mode"`
	ClientAllow          []string `toml:"client_allow"`

	PersistenceMode   string `toml:"persistence_mode"`
	PersistenceDB     string `toml:"persistence_db"`
	PersistAutoHost   *bool  `toml:"persist_auto_host"`
	PersistPublicTopo *bool  `toml:"persist_public_topology"`
	MaxPendingMsgs    *int   `toml:"max_pending_msgs"`

	MaxChannelsPerGroup *int `toml:"max_channels_per_group"`
	MaxGroupNameLen     *int `toml:"max_group_name_len"`
	MaxChannelNameLen   *int `toml:"max_channel_name_len"`

	StatsHTTP *bool  `toml:"stats_http"`
	StatsAddr string `toml:"stats_addr"`
	TLSCert   string `toml:"tls_cert"`
	TLSKey    string `toml:"tls_key"`
}

func loadNodeConfig(path string) (nodeConfig, error) {
	var cfg nodeConfig
	path = strings.TrimSpace(path)
	if path == "" {
		return cfg, fmt.Errorf("config path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if _, err := toml.Decode(string(raw), &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func applyConfigToFlags(cfg nodeConfig, fs *flag.FlagSet, isSet map[string]bool, targets map[string]any) error {
	setString := func(name string, value string) error {
		if isSet[name] || strings.TrimSpace(value) == "" {
			return nil
		}
		ptr, ok := targets[name].(*string)
		if !ok {
			return fmt.Errorf("internal config mapping error for %s", name)
		}
		*ptr = value
		return nil
	}
	setInt := func(name string, value *int) error {
		if isSet[name] || value == nil {
			return nil
		}
		ptr, ok := targets[name].(*int)
		if !ok {
			return fmt.Errorf("internal config mapping error for %s", name)
		}
		*ptr = *value
		return nil
	}
	setBool := func(name string, value *bool) error {
		if isSet[name] || value == nil {
			return nil
		}
		ptr, ok := targets[name].(*bool)
		if !ok {
			return fmt.Errorf("internal config mapping error for %s", name)
		}
		*ptr = *value
		return nil
	}

	if err := setString("listen", cfg.Listen); err != nil {
		return err
	}
	if err := setString("advertise", cfg.Advertise); err != nil {
		return err
	}
	if err := setString("owner", cfg.Owner); err != nil {
		return err
	}
	if err := setString("sid", cfg.SID); err != nil {
		return err
	}
	if err := setString("key", cfg.Key); err != nil {
		return err
	}
	if !isSet["peers"] && len(cfg.Peers) > 0 {
		if ptr, ok := targets["peers"].(*string); ok {
			*ptr = strings.Join(cfg.Peers, ",")
		}
	}
	if err := setInt("max-peers", cfg.MaxPeers); err != nil {
		return err
	}
	if err := setInt("max-msg-bytes", cfg.MaxMsgBytes); err != nil {
		return err
	}
	if err := setInt("max-uncompressed-bytes", cfg.MaxUncompressedBytes); err != nil {
		return err
	}
	if err := setInt("max-expand-ratio", cfg.MaxExpandRatio); err != nil {
		return err
	}
	if err := setInt("max-msgs-per-sec", cfg.MaxMsgsPerSec); err != nil {
		return err
	}
	if err := setInt("burst", cfg.Burst); err != nil {
		return err
	}
	if err := setInt("max-seen", cfg.MaxSeen); err != nil {
		return err
	}
	if err := setInt("max-known-addrs", cfg.MaxKnownAddrs); err != nil {
		return err
	}
	if err := setString("known-addr-ttl", cfg.KnownAddrTTL); err != nil {
		return err
	}
	if err := setBool("relay", cfg.Relay); err != nil {
		return err
	}
	if err := setString("client-mode", cfg.ClientMode); err != nil {
		return err
	}
	if !isSet["client-allow"] && len(cfg.ClientAllow) > 0 {
		if ptr, ok := targets["client-allow"].(*string); ok {
			*ptr = strings.Join(cfg.ClientAllow, ",")
		}
	}
	if err := setString("persistence-mode", cfg.PersistenceMode); err != nil {
		return err
	}
	if err := setString("persistence-db", cfg.PersistenceDB); err != nil {
		return err
	}
	if err := setBool("persist-auto-host", cfg.PersistAutoHost); err != nil {
		return err
	}
	if err := setBool("persist-public-topology", cfg.PersistPublicTopo); err != nil {
		return err
	}
	if err := setInt("max-pending-msgs", cfg.MaxPendingMsgs); err != nil {
		return err
	}
	if err := setInt("max-channels-per-group", cfg.MaxChannelsPerGroup); err != nil {
		return err
	}
	if err := setInt("max-group-name-len", cfg.MaxGroupNameLen); err != nil {
		return err
	}
	if err := setInt("max-channel-name-len", cfg.MaxChannelNameLen); err != nil {
		return err
	}
	if err := setBool("stats-http", cfg.StatsHTTP); err != nil {
		return err
	}
	if err := setString("stats-addr", cfg.StatsAddr); err != nil {
		return err
	}
	if err := setString("tls-cert", cfg.TLSCert); err != nil {
		return err
	}
	if err := setString("tls-key", cfg.TLSKey); err != nil {
		return err
	}

	// keep staticcheck from treating fs as unused if call sites change
	_ = fs
	return nil
}

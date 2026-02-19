package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type groupEntry struct {
	Name     string   `json:"name"`
	Channels []string `json:"channels,omitempty"`
}

type chatContext struct {
	Mode    string `json:"mode,omitempty"`
	Target  string `json:"target,omitempty"`
	Group   string `json:"group,omitempty"`
	Channel string `json:"channel,omitempty"`
}

type uiStateFile struct {
	Groups  []groupEntry `json:"groups,omitempty"`
	Context chatContext  `json:"context,omitempty"`
}

func uiStatePathForProfile(profilePath string) string {
	return strings.TrimSpace(profilePath) + ".ui.json"
}

func loadUIState(path string) ([]groupEntry, chatContext, error) {
	if strings.TrimSpace(path) == "" {
		return nil, chatContext{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, chatContext{}, nil
		}
		return nil, chatContext{}, err
	}
	var f uiStateFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, chatContext{}, err
	}
	return f.Groups, f.Context, nil
}

func saveUIState(path string, groups []groupEntry, ctx chatContext) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	out := uiStateFile{
		Groups:  groups,
		Context: ctx,
	}
	payload, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, payload, 0o600)
}

func normalizeGroupEntries(groups map[string]map[string]struct{}) []groupEntry {
	names := make([]string, 0, len(groups))
	for g := range groups {
		names = append(names, g)
	}
	sort.Strings(names)
	out := make([]groupEntry, 0, len(names))
	for _, g := range names {
		channels := make([]string, 0, len(groups[g]))
		for ch := range groups[g] {
			ch = strings.TrimSpace(ch)
			if ch != "" {
				channels = append(channels, ch)
			}
		}
		sort.Strings(channels)
		out = append(out, groupEntry{Name: g, Channels: channels})
	}
	return out
}

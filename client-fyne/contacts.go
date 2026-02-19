package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type contactsFile struct {
	Contacts []savedContact `json:"contacts"`
}

type savedContact struct {
	Alias   string `json:"alias"`
	LoginID string `json:"login_id"`
}

func loadContacts(path string) (map[string]string, error) {
	out := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	var f contactsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	for _, c := range f.Contacts {
		alias := strings.TrimSpace(c.Alias)
		id := strings.TrimSpace(c.LoginID)
		if alias == "" || !looksLikeLoginID(id) {
			continue
		}
		out[alias] = id
	}
	return out, nil
}

func saveContacts(path string, contacts map[string]string) error {
	merged := make(map[string]string)
	existing, err := loadContacts(path)
	if err != nil {
		return err
	}
	for a, id := range existing {
		merged[a] = id
	}
	for a, id := range contacts {
		merged[a] = id
	}
	return writeContactsAtomic(path, merged)
}

func writeContactsAtomic(path string, contacts map[string]string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	aliases := make([]string, 0, len(contacts))
	for a := range contacts {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	f := contactsFile{Contacts: make([]savedContact, 0, len(aliases))}
	for _, a := range aliases {
		f.Contacts = append(f.Contacts, savedContact{Alias: a, LoginID: contacts[a]})
	}
	payload, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, payload, 0o600)
}

func displayPeer(loginID string, selfID string, selfName string, nicknames map[string]string, contacts map[string]string) string {
	loginID = strings.TrimSpace(loginID)
	if loginID == "" {
		return "-"
	}
	if loginID == selfID && strings.TrimSpace(selfName) != "" {
		return strings.TrimSpace(selfName)
	}
	if nick := strings.TrimSpace(nicknames[loginID]); nick != "" {
		return nick
	}
	for alias, id := range contacts {
		if id == loginID {
			return alias
		}
	}
	return shortID(loginID)
}

func ensureContact(loginID string, selfID string, contacts map[string]string) (string, bool) {
	loginID = strings.TrimSpace(loginID)
	if !looksLikeLoginID(loginID) || loginID == selfID {
		return "", false
	}
	for _, id := range contacts {
		if id == loginID {
			return "", false
		}
	}
	base := shortID(loginID)
	alias := base
	for i := 2; ; i++ {
		if cur, ok := contacts[alias]; !ok {
			contacts[alias] = loginID
			return alias, true
		} else if cur == loginID {
			return "", false
		}
		alias = fmt.Sprintf("%s-%d", base, i)
	}
}

package apphome

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	CurrentDirName = ".withera"
	LegacyDirName  = ".goaccord"
)

func BaseDir() string {
	home, _ := os.UserHomeDir()
	return BaseDirWithHome(home)
}

func BaseDirWithHome(home string) string {
	home = strings.TrimSpace(home)
	if home == "" {
		return CurrentDirName
	}

	current := filepath.Join(home, CurrentDirName)
	legacy := filepath.Join(home, LegacyDirName)

	if dirExists(current) {
		return current
	}
	if dirExists(legacy) {
		return legacy
	}
	return current
}

func CurrentDirWithHome(home string) string {
	home = strings.TrimSpace(home)
	if home == "" {
		return CurrentDirName
	}
	return filepath.Join(home, CurrentDirName)
}

func LegacyDirWithHome(home string) string {
	home = strings.TrimSpace(home)
	if home == "" {
		return LegacyDirName
	}
	return filepath.Join(home, LegacyDirName)
}

func BaseDirForKeyPath(home string, keyPath string) string {
	home = strings.TrimSpace(home)
	keyPath = strings.TrimSpace(keyPath)
	if home == "" {
		return CurrentDirName
	}

	current := CurrentDirWithHome(home)
	legacy := LegacyDirWithHome(home)
	clean := filepath.Clean(keyPath)

	if isPathWithin(clean, legacy) {
		return legacy
	}
	if isPathWithin(clean, current) {
		return current
	}
	return BaseDirWithHome(home)
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func isPathWithin(p string, dir string) bool {
	if strings.TrimSpace(p) == "" || strings.TrimSpace(dir) == "" {
		return false
	}
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

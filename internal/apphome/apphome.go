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

func dirExists(p string) bool {
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	return info.IsDir()
}

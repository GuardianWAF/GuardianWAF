package events

import (
	"fmt"
	"path/filepath"
	"strings"
)

func cleanEventFilePath(path string, allowEmpty bool) (string, error) {
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("event file path contains NUL byte")
	}
	if path == "" {
		if allowEmpty {
			return "", nil
		}
		return "", fmt.Errorf("event file path must not be empty")
	}
	return filepath.Clean(path), nil
}

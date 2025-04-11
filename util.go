package main

import (
	"fmt"
	"io/fs"
	"strings"
)

func checkNamespace(dataDirFS fs.FS, namespace string) (string, error) {
	if namespace == "" {
		return "", fmt.Errorf("invalid namespace: %s", namespace)
	}
	if strings.HasPrefix(namespace, ".") {
		return "", fmt.Errorf("invalid namespace: %s", namespace)
	}
	if strings.Contains(namespace, "/") {
		return "", fmt.Errorf("invalid namespace: %s", namespace)
	}
	f, err := fs.Stat(dataDirFS, namespace)
	if err != nil {
		return "", fmt.Errorf("invalid namespace: %s", namespace)
	}
	if !f.IsDir() {
		return "", fmt.Errorf("invalid namespace: %s", namespace)
	}
	return f.Name(), nil
}

package main

import (
	"fmt"
	"io/fs"
)

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch c {
		case '0', '1', '2', '3', '4',
			'5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f':
		default:
			return false
		}
	}
	return true
}

func checkNamespace(dataDirFS fs.FS, namespace string) (string, error) {
	if !isSHA256(namespace) {
		return "", fmt.Errorf("invalid namespace")
	}
	f, err := fs.Stat(dataDirFS, namespace)
	if err != nil {
		return "", fmt.Errorf("invalid namespace")
	}
	if !f.IsDir() {
		return "", fmt.Errorf("invalid namespace")
	}
	return f.Name(), nil
}

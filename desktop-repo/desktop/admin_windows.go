//go:build windows

package main

import "os"

// На Windows открыть физический диск может только администратор: самый простой способ проверки без лишних библиотек.
func isAdmin() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

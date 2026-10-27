package main

import (
	"encoding/hex"
	"testing"
)

// Вектор посчитан на стороне сервера (backend/app/transports.py): master = HMAC(secret, "ctmaster"), ключ = HMAC(master, "ct:"+имя).
func TestKeyCompatWithBackend(t *testing.T) {
	master, _ := hex.DecodeString("c1242e11ee13684a1e624cfb2334908ee1d5e260c2467c945d2bd3229552a67b")
	if got := hex.EncodeToString(userKey(master, "tg123")); got != "e0995095498210896406f197180023a2c85c39e7c6a070a3a4b8f622b46e1c15" {
		t.Fatalf("ключ не совпадает с бэкендом: %s", got)
	}
}

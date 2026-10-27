package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Ключи нужны только для формы трафика (скрытие длин, проверка своих). Секретность данных обеспечивает
// внутренний Shadowsocks-2022, поэтому здесь только стандартные примитивы: HMAC-SHA256, HKDF, ChaCha20-Poly1305.

func mac(key []byte, parts ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// userKey — долгоживущий ключ пользователя; считается из общего секрета и имени, базу хранить не нужно.
func userKey(master []byte, user string) []byte { return mac(master, []byte("ct:"+user)) }

func epochDay(t time.Time) uint64 { return uint64(t.Unix() / 86400) }

// epochKey меняется каждые сутки: метка пользователя и порт «плывут» во времени.
func epochKey(ku []byte, day uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], day)
	return mac(ku, []byte("epoch"), b[:])
}

func uidTag(ke []byte) (t [8]byte) {
	copy(t[:], mac(ke, []byte("id")))
	return
}

func deriveKey(ke, salt []byte, info string) []byte {
	k := make([]byte, 32)
	io.ReadFull(hkdf.New(sha256.New, ke, salt, []byte(info)), k)
	return k
}

// portFor выбирает порт из диапазона по пользователю и дню (на узле диапазон перенаправляется на порт сервера).
func portFor(ke []byte, lo, hi int) int {
	if hi <= lo {
		return lo
	}
	v := binary.BigEndian.Uint32(mac(ke, []byte("port"))[:4])
	return lo + int(v%uint32(hi-lo+1))
}

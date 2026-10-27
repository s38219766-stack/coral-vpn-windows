package main

import (
	"bytes"
	"testing"
	"time"
)

func BenchmarkChromeHello(b *testing.B) {
	ke := epochKey(userKey(master, "tg1"), epochDay(time.Now()))
	for i := 0; i < b.N; i++ {
		buildClientHello(ke, bytes.Repeat([]byte{1}, 16), time.Now(), "ya.ru")
	}
}

func BenchmarkStaticHello(b *testing.B) {
	ke := epochKey(userKey(master, "tg1"), epochDay(time.Now()))
	auth := makeAuth(ke, bytes.Repeat([]byte{1}, 16), time.Now())
	for i := 0; i < b.N; i++ {
		staticHello(auth, "ya.ru")
	}
}

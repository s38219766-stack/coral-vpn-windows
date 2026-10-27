package main

import (
	"bytes"
	"testing"
	"time"
)

func TestChromeHelloCarriesAuthAndParses(t *testing.T) {
	ke := epochKey(userKey(master, "tg1"), epochDay(time.Now()))
	auth := makeAuth(ke, bytes.Repeat([]byte{8}, 16), time.Now())
	rec, err := chromeHello(auth, "www.yandex.ru")
	if err != nil {
		t.Fatal(err)
	}
	got, sni, err := parseClientHello(rec)
	if err != nil || sni != "www.yandex.ru" || !bytes.Equal(got, auth) {
		t.Fatalf("разбор ClientHello Chrome: err=%v sni=%q auth совпал=%v", err, sni, bytes.Equal(got, auth))
	}
	if _, ok := checkAuth(ke, got, time.Now(), time.Minute); !ok {
		t.Fatal("проверка не прошла")
	}
	static := staticHello(auth, "www.yandex.ru")
	t.Logf("размер ClientHello: Chrome %d байт, запасной %d байт", len(rec), len(static))
	if len(rec) <= len(static) {
		t.Fatal("Chrome-слепок должен быть богаче запасного шаблона")
	}
}

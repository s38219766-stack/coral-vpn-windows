package main

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const sampleVlessReality = "vless://11111111-2222-3333-4444-555555555555@203.0.113.5:8443?security=reality&type=tcp&flow=xtls-rprx-vision&sni=dl.google.com&fp=chrome&pbk=oISxSJtXPf6uQs9UetFaUx4qj3az86NUQZaiGK-b9Ec&sid=ca41daf280d91594#Coral%20FI%20(u)"
const sampleVlessWS = "vless://11111111-2222-3333-4444-555555555555@coral.example.org:443?security=tls&type=ws&path=%2Fabc&host=coral.example.org&sni=coral.example.org&fp=chrome&alpn=http%2F1.1#WS%20TLS%20443"
const sampleVlessXHTTP = "vless://11111111-2222-3333-4444-555555555555@coral.example.org:443?security=tls&type=xhttp&path=%2Fxh&host=coral.example.org&mode=packet-up&sni=coral.example.org&fp=chrome&alpn=h2#XHTTP"

const sampleExtra = `{"servers":[
 {"kind":"hysteria2","name":"Быстрый UDP (Hysteria2)","host":"203.0.113.5","port":443,"password":"p1","sni":"example.org","ports":"20000:30000"},
 {"kind":"ss2022","name":"Простой TCP (Shadowsocks)","host":"203.0.113.5","port":8388,"password":"AAAAAAAAAAAAAAAAAAAAAA==:AAAAAAAAAAAAAAAAAAAAAA==","ss_method":"2022-blake3-aes-128-gcm"},
 {"kind":"tuic","name":"Запасной UDP (TUIC)","host":"203.0.113.5","port":4443,"uuid":"11111111-2222-3333-4444-555555555555","password":"p3","sni":"example.org"},
 {"kind":"ct","name":"Наш протокол (Coral)","host":"203.0.113.5,203.0.113.6","ports":"21000:21999","ct_key":"abcd","ss_method":"2022-blake3-aes-128-gcm","password":"AAAAAAAAAAAAAAAAAAAAAA==:AAAAAAAAAAAAAAAAAAAAAA=="},
 {"kind":"shadowtls","name":"Маска TLS (Shadow-TLS)","host":"203.0.113.5","port":8853,"password":"p5","sni":"www.yandex.ru","ss_method":"2022-blake3-aes-128-gcm","ss_password":"AAAAAAAAAAAAAAAAAAAAAA==:AAAAAAAAAAAAAAAAAAAAAA=="}]}`

func fakeResolve(h string) []string {
	if strings.HasPrefix(h, "coral.") {
		return []string{"203.0.113.9"}
	}
	return []string{h}
}

func sample() []Server {
	body := base64.StdEncoding.EncodeToString([]byte(strings.Join([]string{sampleVlessReality, sampleVlessWS, sampleVlessXHTTP}, "\n")))
	return append(ParseSubscription(body), ParseExtra(sampleExtra)...)
}

func TestParse(t *testing.T) {
	s := sample()
	if len(s) != 8 {
		t.Fatalf("ожидалось 8 серверов, получено %d", len(s))
	}
	if s[0].PBK == "" || s[0].Flow != "xtls-rprx-vision" || s[1].Network != "ws" || s[1].Path != "/abc" {
		t.Fatalf("разбор VLESS: %+v", s[:2])
	}
	if s[6].Kind != "ct" || s[6].Host != "203.0.113.5,203.0.113.6" || s[6].CTKey != "abcd" {
		t.Fatalf("разбор ct: %+v", s[6])
	}
}

func TestBuild(t *testing.T) {
	for _, mode := range []string{"tun", "proxy"} {
		for _, route := range []string{"ru", "all"} {
			b, err := BuildConfig(sample(), Options{Mode: mode, Route: route}, fakeResolve)
			if err != nil {
				t.Fatal(err)
			}
			if b.CT == nil || b.CT.Ports != "21000:21999" {
				t.Fatalf("ct не найден: %+v", b.CT)
			}
			if len(b.Skipped) != 1 || !strings.Contains(b.Skipped[0], "XHTTP") {
				t.Fatalf("XHTTP должен быть пропущен: %v", b.Skipped)
			}
			js := string(b.JSON)
			if mode == "tun" && !strings.Contains(js, "203.0.113.6/32") {
				t.Fatal("адреса серверов должны быть исключены из туннеля, иначе ct зациклится")
			}
			// проверка настоящим sing-box, если он есть
			bin := os.Getenv("SINGBOX")
			if bin == "" {
				if p, err := exec.LookPath("sing-box"); err == nil {
					bin = p
				}
			}
			if bin == "" {
				continue
			}
			f := filepath.Join(t.TempDir(), "c.json")
			os.WriteFile(f, b.JSON, 0o600)
			if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err != nil {
				t.Fatalf("sing-box отверг конфиг (%s/%s): %v\n%s", mode, route, err, out)
			}
		}
	}
}

package main

import (
	"crypto/hmac"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Маскировка под TLS 1.3. Клиент шлёт правдоподобный ClientHello, в поля random и session_id которого вложена
// наша проверка (они и у настоящих клиентов случайные). Сервер отвечает ServerHello и ChangeCipherSpec, дальше
// всё идёт как записи TLS application data. Чужой (проба) получает настоящий сайт с именем из ClientHello.
//
// ClientHello строится библиотекой uTLS по слепку Chrome, поэтому отпечаток (JA3/JA4, порядок расширений, GREASE)
// совпадает с настоящим браузером. Запасной статичный шаблон нужен только на случай сбоя библиотеки.

const (
	recHandshake = 0x16
	recCCS       = 0x14
	recAppData   = 0x17
	authLen      = 64 // random(32) + session_id(32)
)

// DefaultSNI — имена, под которые маскируемся; сервер сам ходит на эти сайты при пробах, остальное отбрасывает.
var DefaultSNI = []string{"www.yandex.ru", "dl.google.com", "www.cloudflare.com", "ya.ru"}

func sniFor(ke []byte, list []string) string {
	v := binary.BigEndian.Uint32(mac(ke, []byte("sni"))[:4])
	return list[int(v)%len(list)]
}

func u16(b []byte, v int) { binary.BigEndian.PutUint16(b, uint16(v)) }

func ext(typ int, data []byte) []byte {
	out := make([]byte, 4+len(data))
	u16(out, typ)
	u16(out[2:], len(data))
	copy(out[4:], data)
	return out
}

func buildClientHello(ke, cn []byte, now time.Time, sni string) []byte {
	auth := makeAuth(ke, cn, now)
	if rec, err := chromeHello(auth, sni); err == nil {
		return rec
	}
	return staticHello(auth, sni) // запасной вариант, если библиотека отпечатков не собрала ClientHello
}

// chromeHello строит ClientHello настоящего Chrome (библиотека uTLS: порядок расширений, шифры, GREASE, ключи
// обмена — как у браузера) и подменяет в нём random и session_id на нашу проверку.
func chromeHello(auth []byte, sni string) ([]byte, error) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	u := utls.UClient(c1, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}
	raw := append([]byte(nil), u.HandshakeState.Hello.Raw...)
	if len(raw) < 71 || raw[0] != 1 || raw[38] != 32 {
		return nil, errBad
	}
	copy(raw[6:38], auth[:32])
	copy(raw[39:71], auth[32:])
	return append([]byte{recHandshake, 3, 1, byte(len(raw) >> 8), byte(len(raw))}, raw...), nil
}

func makeAuth(ke, cn []byte, now time.Time) []byte {
	auth := make([]byte, authLen)
	tag := uidTag(ke)
	copy(auth[0:8], tag[:])
	copy(auth[8:24], cn)
	mk := mac(ke, []byte("mask"), cn)
	binary.BigEndian.PutUint32(auth[24:28], uint32(now.Unix())^binary.BigEndian.Uint32(mk[0:4]))
	m := mac(ke, []byte("hello"), auth[0:28])
	copy(auth[28:44], m[:16])
	crand.Read(auth[44:])
	return auth
}

func staticHello(auth []byte, sni string) []byte {
	suites := []int{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	cs := make([]byte, 2*len(suites))
	for i, s := range suites {
		u16(cs[2*i:], s)
	}
	name := []byte(sni)
	sn := make([]byte, 5+len(name))
	u16(sn, 3+len(name))
	sn[2] = 0
	u16(sn[3:], len(name))
	copy(sn[5:], name)
	ks := make([]byte, 2+2+32)
	u16(ks, 36)
	u16(ks[2:], 0x001d)
	u16(ks[4:], 32)
	crand.Read(ks[6:])
	var exts []byte
	for _, e := range [][]byte{
		ext(0x0000, sn),
		ext(0x0017, nil),
		ext(0xff01, []byte{0}),
		ext(0x000a, []byte{0, 6, 0, 0x1d, 0, 0x17, 0, 0x18}),
		ext(0x000b, []byte{1, 0}),
		ext(0x0023, nil),
		ext(0x0010, []byte{0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}),
		ext(0x0005, []byte{1, 0, 0, 0, 0}),
		ext(0x000d, []byte{0, 16, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1}),
		ext(0x0012, nil),
		ext(0x0033, ks),
		ext(0x002d, []byte{1, 1}),
		ext(0x002b, []byte{4, 3, 4, 3, 3}),
		ext(0x001b, []byte{2, 0, 2}),
	} {
		exts = append(exts, e...)
	}
	body := []byte{3, 3}
	body = append(body, auth[0:32]...)
	body = append(body, 32)
	body = append(body, auth[32:]...)
	body = append(body, byte(len(cs)>>8), byte(len(cs)))
	body = append(body, cs...)
	body = append(body, 1, 0)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{recHandshake, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	return rec
}

var errBad = errors.New("не ClientHello")

// parseClientHello достаёт auth (random+session_id) и SNI; формат проверяется строго, чтобы чужие данные не разбирать.
func parseClientHello(rec []byte) (auth []byte, sni string, err error) {
	if len(rec) < 5+4 || rec[0] != recHandshake || rec[5] != 1 {
		return nil, "", errBad
	}
	b := rec[5:]
	hl := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if hl+4 > len(b) {
		return nil, "", errBad
	}
	b = b[4 : 4+hl]
	if len(b) < 2+32+1 {
		return nil, "", errBad
	}
	random := b[2:34]
	sl := int(b[34])
	if sl != 32 || len(b) < 35+sl+2 {
		return nil, "", errBad
	}
	sid := b[35 : 35+sl]
	p := 35 + sl
	csl := int(binary.BigEndian.Uint16(b[p:]))
	p += 2 + csl
	if p+1 > len(b) {
		return nil, "", errBad
	}
	p += 1 + int(b[p])
	if p+2 > len(b) {
		return nil, "", errBad
	}
	el := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if p+el > len(b) {
		return nil, "", errBad
	}
	e := b[p : p+el]
	for len(e) >= 4 {
		t := int(binary.BigEndian.Uint16(e))
		l := int(binary.BigEndian.Uint16(e[2:]))
		if 4+l > len(e) {
			break
		}
		if t == 0 && l >= 5 {
			nl := int(binary.BigEndian.Uint16(e[7:]))
			if 9+nl <= 4+l {
				sni = string(e[9 : 9+nl])
			}
		}
		e = e[4+l:]
	}
	auth = append(append([]byte(nil), random...), sid...)
	return auth, sni, nil
}

// checkAuth проверяет вложение для известного ключа дня.
func checkAuth(ke, auth []byte, now time.Time, window time.Duration) (cn []byte, ok bool) {
	m := mac(ke, []byte("hello"), auth[0:28])
	if !hmac.Equal(m[:16], auth[28:44]) {
		return nil, false
	}
	cn = auth[8:24]
	mk := mac(ke, []byte("mask"), cn)
	ts := int64(binary.BigEndian.Uint32(auth[24:28]) ^ binary.BigEndian.Uint32(mk[0:4]))
	d := now.Unix() - ts
	if d < 0 {
		d = -d
	}
	if time.Duration(d)*time.Second > window {
		return nil, false
	}
	return append([]byte(nil), cn...), true
}

// buildServerFlight — ServerHello (с тем же session_id) и ChangeCipherSpec, как отвечает TLS 1.3 сервер.
func buildServerFlight(sid []byte) []byte {
	var exts []byte
	exts = append(exts, ext(0x002b, []byte{3, 4})...)
	ks := make([]byte, 4+32)
	u16(ks, 0x001d)
	u16(ks[2:], 32)
	crand.Read(ks[4:])
	exts = append(exts, ext(0x0033, ks)...)
	body := []byte{3, 3}
	rnd := make([]byte, 32)
	crand.Read(rnd)
	body = append(body, rnd...)
	body = append(body, 32)
	body = append(body, sid...)
	body = append(body, 0x13, 0x01, 0)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	hs := append([]byte{2, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	out := append([]byte{recHandshake, 3, 3, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	return append(out, recCCS, 3, 3, 0, 1, 1)
}

// skipServerFlight читает и выбрасывает ServerHello и ChangeCipherSpec.
func skipServerFlight(c net.Conn) error {
	for _, want := range []byte{recHandshake, recCCS} {
		var h [5]byte
		if _, err := io.ReadFull(c, h[:]); err != nil {
			return err
		}
		if h[0] != want || h[1] != 3 {
			return errBad
		}
		if _, err := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint16(h[3:]))); err != nil {
			return err
		}
	}
	return nil
}

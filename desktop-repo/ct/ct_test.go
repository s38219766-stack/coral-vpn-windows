package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var master = bytes.Repeat([]byte{7}, 32)
var lastSNI atomic.Value

func listen(t *testing.T) net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func echo(t *testing.T) string {
	l := listen(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.(*net.TCPConn).CloseWrite() }()
		}
	}()
	return l.Addr().String()
}

func web(t *testing.T) string {
	l := listen(t)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				b := make([]byte, 512)
				c.Read(b)
				c.Write([]byte("HTTP/1.0 200 OK\r\n\r\nreal site"))
				c.Close()
			}()
		}
	}()
	return l.Addr().String()
}

func setup(t *testing.T) (*Server, *Client, string) {
	site := web(t)
	srv := NewServer(master, echo(t), site)
	srv.Dest = func(sni string) string { lastSNI.Store(sni); return site }
	srv.SetUsers([]string{"tg1", "tg2"})
	l := listen(t)
	go srv.ServeTCP(l)
	host, port, _ := net.SplitHostPort(l.Addr().String())
	p := 0
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	return srv, &Client{Remote: host, PortLo: p, PortHi: p, Key: userKey(master, "tg1")}, l.Addr().String()
}

func TestRoundTripBulk(t *testing.T) {
	_, cl, _ := setup(t)
	sc, err := cl.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	data := make([]byte, 4<<20)
	rand.Read(data)
	go func() { sc.Write(data); sc.CloseWrite() }()
	got, err := io.ReadAll(sc)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("данные не совпали: %v, %d из %d", err, len(got), len(data))
	}
	over := float64(sc.WireOut.Load())/float64(sc.DataOut.Load()) - 1
	t.Logf("скачивание/загрузка: накладные расходы %.2f%%", over*100)
	if over > 0.02 {
		t.Fatalf("слишком большие накладные расходы на крупных данных: %.2f%%", over*100)
	}
}

func TestSmallInteractiveBudget(t *testing.T) {
	_, cl, _ := setup(t)
	sc, err := cl.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	msg := make([]byte, 90)
	buf := make([]byte, 90)
	for i := 0; i < 2000; i++ {
		rand.Read(msg)
		sc.Write(msg)
		if _, err := io.ReadFull(sc, buf); err != nil || !bytes.Equal(buf, msg) {
			t.Fatalf("раунд %d: %v", i, err)
		}
	}
	over := float64(sc.WireOut.Load())/float64(sc.DataOut.Load()) - 1
	t.Logf("мелкие сообщения: накладные расходы %.0f%% (кадр и теги включены), профиль %s", over*100, sc.sh.p.name)
}

func TestProbeSeesRealSite(t *testing.T) {
	_, _, addr := setup(t)
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c)
	if !strings.Contains(string(b), "real site") {
		t.Fatalf("проба не получила сайт: %q", b)
	}
}

func TestReplayGoesToSite(t *testing.T) {
	_, cl, addr := setup(t)
	now := time.Now()
	ke := epochKey(cl.Key, epochDay(now))
	hello := buildClientHello(ke, bytes.Repeat([]byte{9}, 16), now, "www.yandex.ru")
	c1, _ := net.Dial("tcp", addr)
	c1.Write(hello)
	buf := make([]byte, 16)
	c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	c1.Read(buf) // свой получает ServerHello
	if buf[0] != recHandshake {
		t.Fatalf("первый ответ не TLS-запись: %x", buf[:5])
	}
	c1.Close()
	c2, _ := net.Dial("tcp", addr)
	defer c2.Close()
	c2.Write(hello)
	c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c2)
	if !strings.Contains(string(b), "real site") {
		t.Fatalf("повтор должен уйти на сайт: %q", b)
	}
}

func TestUnknownUserGoesToSiteWithItsSNI(t *testing.T) {
	_, cl, addr := setup(t)
	cl.Key = userKey(master, "stranger")
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	now := time.Now()
	c.Write(buildClientHello(epochKey(cl.Key, epochDay(now)), bytes.Repeat([]byte{3}, 16), now, "dl.google.com"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c)
	if !strings.Contains(string(b), "real site") {
		t.Fatalf("чужой должен уйти на сайт: %q", b)
	}
	if lastSNI.Load() != "dl.google.com" {
		t.Fatalf("пробу надо отправлять на сайт с тем именем, что в ClientHello, а не на %v", lastSNI.Load())
	}
}

func TestStaleTimestampRejected(t *testing.T) {
	ke := epochKey(userKey(master, "tg1"), epochDay(time.Now()))
	rec := buildClientHello(ke, bytes.Repeat([]byte{1}, 16), time.Now().Add(-time.Hour), "ya.ru")
	auth, _, err := parseClientHello(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := checkAuth(ke, auth, time.Now(), 5*time.Minute); ok {
		t.Fatal("старое время должно отклоняться")
	}
}

func TestClientHelloLooksLikeTLSAndParses(t *testing.T) {
	ke := epochKey(userKey(master, "tg1"), epochDay(time.Now()))
	rec := buildClientHello(ke, bytes.Repeat([]byte{5}, 16), time.Now(), "ya.ru")
	if rec[0] != 0x16 || rec[1] != 3 || rec[5] != 1 {
		t.Fatalf("не похоже на ClientHello: %x", rec[:8])
	}
	if int(rec[3])<<8|int(rec[4]) != len(rec)-5 {
		t.Fatal("длина записи не совпадает")
	}
	auth, sni, err := parseClientHello(rec)
	if err != nil || sni != "ya.ru" || len(auth) != 64 {
		t.Fatalf("разбор: %v %q %d", err, sni, len(auth))
	}
	if _, ok := checkAuth(ke, auth, time.Now(), time.Minute); !ok {
		t.Fatal("своя проверка не прошла")
	}
	// два ClientHello одного пользователя не совпадают ни в одном длинном куске (всё случайно, нет сигнатуры)
	rec2 := buildClientHello(ke, bytes.Repeat([]byte{6}, 16), time.Now(), "ya.ru")
	if bytes.Equal(rec[11:43], rec2[11:43]) {
		t.Fatal("random совпал")
	}
}

func TestAllWireRecordsAreTLSAppData(t *testing.T) {
	_, cl, addr := setup(t)
	// между клиентом и сервером ставим прослойку, которая записывает байты ответа сервера
	px, _ := net.Listen("tcp", "127.0.0.1:0")
	defer px.Close()
	var seen bytes.Buffer
	done := make(chan struct{})
	go func() {
		c, _ := px.Accept()
		u, _ := net.Dial("tcp", addr)
		go io.Copy(u, c)
		io.Copy(io.MultiWriter(c, &seen), u)
		close(done)
	}()
	host, port, _ := net.SplitHostPort(px.Addr().String())
	p := 0
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	cl.Remote, cl.PortLo, cl.PortHi = host, p, p
	sc, err := cl.Dial()
	if err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, 5000)
	rand.Read(msg)
	sc.Write(msg)
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(sc, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatal(err)
	}
	sc.CloseWrite()
	io.Copy(io.Discard, sc)
	sc.Close()
	<-done
	b := seen.Bytes()
	if b[0] != recHandshake || b[1] != 3 {
		t.Fatalf("ответ сервера должен начинаться с ServerHello: %x", b[:5])
	}
	p0 := 5 + (int(b[3])<<8 | int(b[4]))
	if b[p0] != recCCS {
		t.Fatalf("после ServerHello должен идти ChangeCipherSpec: %x", b[p0])
	}
	p0 += 6
	n := 0
	for p0 < len(b) {
		if b[p0] != recAppData || b[p0+1] != 3 || b[p0+2] != 3 {
			t.Fatalf("запись %d не application data: %x", n, b[p0:p0+5])
		}
		p0 += 5 + (int(b[p0+3])<<8 | int(b[p0+4]))
		n++
	}
	t.Logf("записей application data после рукопожатия: %d", n)
}

func TestProfilesDifferPerUser(t *testing.T) {
	cn := bytes.Repeat([]byte{4}, 16)
	a := profileFor(epochKey(userKey(master, "tg1"), 100), cn)
	b := profileFor(epochKey(userKey(master, "tg2"), 100), cn)
	c := profileFor(epochKey(userKey(master, "tg1"), 101), cn)
	same := func(x, y profile) bool { return fmt.Sprint(x.sizes, x.weights) == fmt.Sprint(y.sizes, y.weights) }
	if same(a, b) || same(a, c) {
		t.Fatal("профили не должны совпадать у разных пользователей и дней")
	}
}

func TestHandshakeAddsLittleDelay(t *testing.T) {
	_, cl, _ := setup(t)
	t0 := time.Now()
	for i := 0; i < 20; i++ {
		sc, err := cl.Dial()
		if err != nil {
			t.Fatal(err)
		}
		sc.Write([]byte("ping"))
		b := make([]byte, 4)
		io.ReadFull(sc, b)
		sc.Close()
	}
	per := time.Since(t0) / 20
	t.Logf("полный цикл соединения: %v", per)
	if per > 150*time.Millisecond {
		t.Fatalf("слишком медленно: %v", per)
	}
}

func TestUDPRoundTrip(t *testing.T) {
	up, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer up.Close()
	go func() {
		b := make([]byte, 2000)
		for {
			n, a, err := up.ReadFromUDP(b)
			if err != nil {
				return
			}
			up.WriteToUDP(b[:n], a)
		}
	}()
	srv := NewServer(master, up.LocalAddr().String(), "")
	srv.SetUsers([]string{"tg1"})
	sp, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer sp.Close()
	go srv.ServeUDP(sp)
	port := sp.LocalAddr().(*net.UDPAddr).Port
	cl := &Client{Remote: "127.0.0.1", PortLo: port, PortHi: port, Key: userKey(master, "tg1")}
	lp, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer lp.Close()
	go cl.ServeUDP(lp)
	app, _ := net.DialUDP("udp", nil, lp.LocalAddr().(*net.UDPAddr))
	defer app.Close()
	for i := 0; i < 20; i++ {
		msg := make([]byte, 40+i)
		rand.Read(msg)
		app.Write(msg)
		app.SetReadDeadline(time.Now().Add(3 * time.Second))
		b := make([]byte, 2000)
		n, err := app.Read(b)
		if err != nil || !bytes.Equal(b[:n], msg) {
			t.Fatalf("udp %d: %v", i, err)
		}
	}
}

func TestPortsDifferByUserAndDay(t *testing.T) {
	a := portFor(epochKey(userKey(master, "tg1"), 100), 20000, 30000)
	b := portFor(epochKey(userKey(master, "tg2"), 100), 20000, 30000)
	c := portFor(epochKey(userKey(master, "tg1"), 101), 20000, 30000)
	if a == b && a == c {
		t.Fatal("порты не должны совпадать у всех")
	}
	if a < 20000 || a > 30000 {
		t.Fatal("порт вне диапазона")
	}
}

func TestFailoverToSecondHost(t *testing.T) {
	_, cl, _ := setup(t)
	cl.Remote = "127.0.0.2," + cl.Remote // первый адрес не слушает порт
	sc, err := cl.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	sc.Write([]byte("ping"))
	b := make([]byte, 4)
	if _, err := io.ReadFull(sc, b); err != nil || string(b) != "ping" {
		t.Fatalf("после переключения связь не работает: %v", err)
	}
	if cl.cur.Load() != 1 {
		t.Fatalf("рабочий сервер должен запомниться, индекс %d", cl.cur.Load())
	}
}

func TestKeepaliveSentWhenIdle(t *testing.T) {
	_, cl, _ := setup(t)
	sc, err := cl.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	sc.kaMin, sc.kaMax = 40*time.Millisecond, 80*time.Millisecond
	go sc.keepalive()
	sc.Write([]byte("x"))
	go io.Copy(io.Discard, sc)
	time.Sleep(300 * time.Millisecond)
	before := sc.WireOut.Load()
	time.Sleep(500 * time.Millisecond)
	if sc.WireOut.Load() <= before {
		t.Fatal("холостые кадры не отправляются")
	}
}

func TestPortsAreRandomPerConnection(t *testing.T) {
	cl := &Client{Remote: "127.0.0.1", PortLo: 21000, PortHi: 21999, Key: userKey(master, "tg1")}
	seen := map[int]bool{}
	for i := 0; i < 40; i++ {
		_, p, _ := net.SplitHostPort(cl.addrFor("127.0.0.1", time.Now()))
		n := 0
		for _, ch := range p {
			n = n*10 + int(ch-'0')
		}
		if n < 21000 || n > 21999 {
			t.Fatalf("порт вне диапазона: %d", n)
		}
		seen[n] = true
	}
	if len(seen) < 20 {
		t.Fatalf("порты почти не меняются: %d разных из 40", len(seen))
	}
	a1 := cl.addr(time.Now())
	if a2 := cl.addr(time.Now().Add(5 * time.Second)); a1 != a2 {
		t.Fatal("UDP-порт не должен меняться чаще раза в минуту")
	}
}

func TestRaceDialSkipsBlackholedHostQuickly(t *testing.T) {
	_, cl, _ := setup(t)
	real := cl.Remote
	cl.Remote = "blackhole.test," + real
	var d net.Dialer
	cl.dialFn = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "blackhole.test") {
			<-ctx.Done() // «глухой» адрес: ни ответа, ни отказа
			return nil, ctx.Err()
		}
		return d.DialContext(ctx, network, addr)
	}
	t0 := time.Now()
	sc, err := cl.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	took := time.Since(t0)
	sc.Write([]byte("ping"))
	b := make([]byte, 4)
	if _, err := io.ReadFull(sc, b); err != nil || string(b) != "ping" {
		t.Fatalf("связь не работает: %v", err)
	}
	t.Logf("подключение при «глухом» первом адресе: %v", took)
	if took > 700*time.Millisecond {
		t.Fatalf("гонка должна обойти молчащий адрес за ~300 мс, а не за таймаут: %v", took)
	}
	if cl.cur.Load() != 1 {
		t.Fatalf("рабочий сервер должен запомниться, индекс %d", cl.cur.Load())
	}
}

package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

type entry struct {
	user string
	ke   []byte
}

type Server struct {
	Master   []byte
	Upstream string // куда отдавать расшифрованный поток (локальный Shadowsocks)
	Fallback string // куда отправлять «чужих» (настоящий сайт)
	Window   time.Duration
	SNI      []string                // разрешённые имена маскировки; к ним сервер ходит при пробах
	Dest     func(sni string) string // куда отправить пробу с этим именем (по умолчанию sni:443, иначе Fallback)
	FlightLo int                     // «хвост» ответа сервера (имитация цепочки сертификатов): от... до байт
	FlightHi int

	mu      sync.Mutex
	tags    map[[8]byte]entry
	users   []string
	day     uint64
	replay  map[string]time.Time
	udpSess map[string]*udpSession
	stats   map[string]int
	lastLog map[string]time.Time
}

func NewServer(master []byte, upstream, fallback string) *Server {
	return &Server{Master: master, Upstream: upstream, Fallback: fallback, Window: 5 * time.Minute, FlightLo: 500, FlightHi: 1800,
		replay: map[string]time.Time{}, udpSess: map[string]*udpSession{}, stats: map[string]int{}, lastLog: map[string]time.Time{}}
}

// SetUsers обновляет список пользователей; метки на вчера, сегодня и завтра считаются заранее (граница суток, часы телефонов).
func (s *Server) SetUsers(users []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = users
	s.rebuild(epochDay(time.Now()))
}

func (s *Server) rebuild(day uint64) {
	t := make(map[[8]byte]entry, len(s.users)*3)
	for _, u := range s.users {
		ku := userKey(s.Master, u)
		for _, d := range []uint64{day - 1, day, day + 1} {
			ke := epochKey(ku, d)
			t[uidTag(ke)] = entry{u, ke}
		}
	}
	s.tags, s.day = t, day
}

func (s *Server) lookup(tag [8]byte) (entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := epochDay(time.Now()); d != s.day {
		s.rebuild(d)
	}
	e, ok := s.tags[tag]
	return e, ok
}

// LoadUsers читает JSON-список имён и перечитывает его при изменении файла.
func (s *Server) LoadUsers(path string) {
	var last time.Time
	for {
		if st, err := os.Stat(path); err == nil && st.ModTime() != last {
			if b, err := os.ReadFile(path); err == nil {
				var u []string
				if json.Unmarshal(b, &u) == nil {
					s.SetUsers(u)
					last = st.ModTime()
					log.Printf("пользователей: %d", len(u))
				}
			}
		}
		time.Sleep(10 * time.Second)
	}
}

func (s *Server) seen(cn []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if len(s.replay) > 20000 {
		for k, t := range s.replay {
			if now.After(t) {
				delete(s.replay, k)
			}
		}
	}
	if t, ok := s.replay[string(cn)]; ok && now.Before(t) {
		return true
	}
	s.replay[string(cn)] = now.Add(2 * s.Window)
	return false
}

func (s *Server) ServeTCP(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go s.handleTCP(c)
	}
}

// readFirst читает первую запись TLS. Если пришло что-то другое или меньше, отдаёт что есть (проба ждёт ответа).
func readFirst(c net.Conn) (rec []byte, tls bool) {
	buf := make([]byte, 5)
	n := 0
	c.SetReadDeadline(time.Now().Add(8 * time.Second))
	for n < 5 {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			return buf[:n], false
		}
		if n < 5 {
			c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		}
	}
	if buf[0] != recHandshake || buf[1] != 3 {
		return buf, false
	}
	l := int(binary.BigEndian.Uint16(buf[3:]))
	if l < 40 || l > 4096 {
		return buf, false
	}
	rest := make([]byte, l)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	m, err := io.ReadFull(c, rest)
	if err != nil {
		return append(buf, rest[:m]...), false
	}
	return append(buf, rest...), true
}

func (s *Server) dest(sni string) string {
	if s.Dest != nil {
		return s.Dest(sni)
	}
	list := s.SNI
	if len(list) == 0 {
		list = DefaultSNI
	}
	for _, n := range list {
		if n == sni {
			return net.JoinHostPort(sni, "443")
		}
	}
	return s.Fallback
}

// note пишет в журнал причину и адрес клиента; чтобы журнал не разрастался, подробно только первые события и потом раз в минуту.
func (s *Server) note(c net.Conn, what string) {
	s.mu.Lock()
	s.stats[what]++
	n := s.stats[what]
	show := n <= 20 || time.Since(s.lastLog[what]) > time.Minute
	if show {
		s.lastLog[what] = time.Now()
	}
	s.mu.Unlock()
	if show {
		log.Printf("%s (всего %d) от %s", what, n, c.RemoteAddr())
	}
}

func (s *Server) handleTCP(c net.Conn) {
	defer c.Close()
	rec, isTLS := readFirst(c)
	c.SetReadDeadline(time.Time{})
	if !isTLS {
		s.note(c, "не TLS (проба или сканер)")
		s.fallback(c, rec, s.Fallback)
		return
	}
	auth, sni, err := parseClientHello(rec)
	if err != nil {
		s.note(c, "TLS не разобран")
		s.fallback(c, rec, s.Fallback)
		return
	}
	var tag [8]byte
	copy(tag[:], auth[:8])
	e, ok := s.lookup(tag)
	if !ok {
		s.note(c, "неизвестная метка пользователя")
		s.fallback(c, rec, s.dest(sni))
		return
	}
	cn, ok := checkAuth(e.ke, auth, time.Now(), s.Window)
	if !ok {
		s.note(c, "проверка не прошла у "+e.user+" (MAC или время: часы телефона уходят больше чем на 5 минут?)")
		s.fallback(c, rec, s.dest(sni))
		return
	}
	if s.seen(cn) {
		s.note(c, "повтор рукопожатия")
		s.fallback(c, rec, s.dest(sni))
		return
	}
	s.note(c, "свой клиент принят: "+e.user)
	up, err := net.DialTimeout("tcp", s.Upstream, 5*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	sh := newShaper(profileFor(e.ke, cn))
	sc := newSecure(c, deriveKey(e.ke, cn, "s2c"), deriveKey(e.ke, cn, "c2s"), sh)
	if _, err := c.Write(buildServerFlight(auth[32:])); err != nil {
		return
	}
	if s.FlightHi > 0 { // «хвост» первого ответа: настоящий сервер шлёт цепочку сертификатов, пустой ответ выглядел бы странно
		n := s.FlightLo
		if s.FlightHi > s.FlightLo {
			n += sh.r.IntN(s.FlightHi - s.FlightLo + 1)
		}
		sc.wmu.Lock()
		sc.writeFrame(nil, n)
		sc.wmu.Unlock()
	}
	defer sc.Close()
	go sc.keepalive()
	pipe(sc, tcpHalf{up.(*net.TCPConn)})
}

// fallback прозрачно отдаёт соединение настоящему сайту: проба видит обычный веб-сервер.
func (s *Server) fallback(c net.Conn, got []byte, to string) {
	if to == "" {
		return
	}
	up, err := net.DialTimeout("tcp", to, 4*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	up.Write(got)
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

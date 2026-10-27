package main

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type hostNote struct {
	ok bool
	at time.Time
}

type Client struct {
	Remote string // сервер или несколько через запятую (мосты): при сбое берём следующий
	PortLo int
	PortHi int
	Key    []byte   // ключ пользователя
	SNI    []string // имена для маскировки (по умолчанию DefaultSNI); должны совпадать с серверными

	cur atomic.Int32 // индекс последнего рабочего сервера

	dialFn  func(ctx context.Context, network, addr string) (net.Conn, error) // для тестов
	seen    map[string]hostNote
	mu      sync.Mutex
	udpPort int
	udpAt   time.Time
}

func (cl *Client) hosts() []string {
	var out []string
	for _, h := range strings.Split(cl.Remote, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// pickPort — случайный порт из диапазона: каждое новое соединение идёт на другой порт, поэтому блокировка отдельных портов
// почти ничего не отнимает (сервер принимает весь диапазон одинаково).
func (cl *Client) pickPort() int {
	if cl.PortHi <= cl.PortLo {
		return cl.PortLo
	}
	return cl.PortLo + rand.IntN(cl.PortHi-cl.PortLo+1)
}

func (cl *Client) addrFor(host string, _ time.Time) string {
	return net.JoinHostPort(host, fmt.Sprint(cl.pickPort()))
}

// addr — адрес для UDP: порт «прыгает» раз в минуту (в пределах минуты соответствие в NAT оператора не меняется).
func (cl *Client) addr(now time.Time) string {
	h := cl.hosts()
	cl.mu.Lock()
	if cl.udpPort == 0 || now.Sub(cl.udpAt) > time.Minute {
		cl.udpPort, cl.udpAt = cl.pickPort(), now
	}
	port := cl.udpPort
	cl.mu.Unlock()
	return net.JoinHostPort(h[int(cl.cur.Load())%len(h)], fmt.Sprint(port))
}

// noteHost печатает в журнал строку «host ok|fail <адрес>»: приложение по ним шлёт серверу анонимную статистику,
// какие адреса у какого оператора отвечают. Повторяем строку только при смене состояния или раз в 5 минут.
func (cl *Client) noteHost(host string, ok bool) {
	cl.mu.Lock()
	if cl.seen == nil {
		cl.seen = map[string]hostNote{}
	}
	prev, had := cl.seen[host]
	now := time.Now()
	print := !had || prev.ok != ok || now.Sub(prev.at) > 5*time.Minute
	if print {
		cl.seen[host] = hostNote{ok, now}
	}
	cl.mu.Unlock()
	if print {
		if ok {
			log.Printf("host ok %s", host)
		} else {
			log.Printf("host fail %s", host)
		}
	}
}

// connect подключается «гонкой»: сначала пробуем последний рабочий сервер, и если он не ответил за 300 мс, параллельно
// запускаем следующий (потом следующий), побеждает первый ответивший. Так блокировка адреса стоит доли секунды, а не таймаут.
// Каждая попытка идёт на случайный порт из диапазона; на каждый сервер даётся две попытки с разными портами.
func (cl *Client) connect(now time.Time) (net.Conn, error) {
	h := cl.hosts()
	if len(h) == 0 {
		return nil, errors.New("не задан сервер")
	}
	start := int(cl.cur.Load())
	var order []int
	for pass := 0; pass < 2; pass++ {
		for i := 0; i < len(h); i++ {
			order = append(order, (start+i)%len(h))
		}
	}
	type result struct {
		c   net.Conn
		idx int
		err error
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan result, len(order))
	launched, pending := 0, 0
	launch := func() {
		idx := order[launched]
		launched++
		pending++
		go func() {
			dial := cl.dialFn
			if dial == nil {
				d := net.Dialer{Timeout: 5 * time.Second}
				dial = d.DialContext
			}
			c, err := dial(ctx, "tcp", cl.addrFor(h[idx], now))
			if err != nil && ctx.Err() == nil { // отмена из-за победителя — не отказ адреса
				cl.noteHost(h[idx], false)
			}
			ch <- result{c, idx, err}
		}()
	}
	launch()
	timer := time.NewTimer(300 * time.Millisecond)
	defer timer.Stop()
	var last error
	for pending > 0 {
		select {
		case r := <-ch:
			pending--
			if r.err == nil {
				cancel()
				rest := pending
				go func() { // опоздавшие соединения закрываем
					for i := 0; i < rest; i++ {
						if x := <-ch; x.c != nil {
							x.c.Close()
						}
					}
				}()
				cl.cur.Store(int32(r.idx))
				cl.noteHost(h[r.idx], true)
				return r.c, nil
			}
			last = r.err
			if launched < len(order) { // не ждём 300 мс, если сервер отказал сразу
				launch()
			}
		case <-timer.C:
			if launched < len(order) {
				launch()
				timer.Reset(300 * time.Millisecond)
			}
		}
	}
	return nil, last
}

// Dial открывает соединение с сервером: отправляет ClientHello с нашей проверкой внутри. Ответ сервера
// (ServerHello и ChangeCipherSpec) читается лениво, поэтому данные можно слать сразу, без лишней задержки.
func (cl *Client) Dial() (*secureConn, error) {
	now := time.Now()
	ke := epochKey(cl.Key, epochDay(now))
	list := cl.SNI
	if len(list) == 0 {
		list = DefaultSNI
	}
	c, err := cl.connect(now)
	if err != nil {
		return nil, err
	}
	cn := make([]byte, 16)
	crand.Read(cn)
	if _, err := c.Write(buildClientHello(ke, cn, now, sniFor(ke, list))); err != nil {
		c.Close()
		return nil, err
	}
	sc := newSecure(c, deriveKey(ke, cn, "c2s"), deriveKey(ke, cn, "s2c"), newShaper(profileFor(ke, cn)))
	sc.skip = true
	return sc, nil
}

func (cl *Client) ServeTCP(l net.Listener) {
	for {
		lc, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer lc.Close()
			sc, err := cl.Dial()
			if err != nil {
				log.Printf("соединение: %v", err)
				return
			}
			defer sc.Close()
			go sc.keepalive()
			pipe(sc, tcpHalf{lc.(*net.TCPConn)})
		}()
	}
}

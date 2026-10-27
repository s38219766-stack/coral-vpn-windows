package main

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	maxData      = 16000
	jitterFrames = 3 // сколько первых записей сдвигаем по времени
	jitterMax    = 3 // миллисекунд
)

// secureConn — поток кадров: [заголовок 4 байта (длина данных, длина дополнения) в AEAD] [данные+дополнение в AEAD].
// Нулевой заголовок (0,0) — конец потока. Кадр только с дополнением (данных 0) — холостой.
type secureConn struct {
	c            net.Conn
	rd, wr       cipher.AEAD
	rn, wn       uint64
	sh           *shaper
	rbuf         []byte
	wmu          sync.Mutex
	last         atomic.Int64 // время последней записи (для холостых кадров)
	quit         chan struct{}
	once         sync.Once
	kaMin, kaMax time.Duration // период холостых кадров
	skip         bool          // клиент: перед чтением выбросить ServerHello и ChangeCipherSpec

	WireOut, WireIn, DataOut atomic.Int64
}

func newSecure(c net.Conn, wKey, rKey []byte, sh *shaper) *secureConn {
	w, _ := chacha20poly1305.New(wKey)
	r, _ := chacha20poly1305.New(rKey)
	return &secureConn{c: c, rd: r, wr: w, sh: sh, quit: make(chan struct{}), kaMin: 20 * time.Second, kaMax: 45 * time.Second}
}

func nonce(n uint64) []byte {
	var b [12]byte
	binary.BigEndian.PutUint64(b[4:], n)
	return b[:]
}

func (s *secureConn) writeFrame(data []byte, pad int) error {
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[0:], uint16(len(data)))
	binary.BigEndian.PutUint16(hdr[2:], uint16(pad))
	buf := make([]byte, 5, 5+20+len(data)+pad+16)
	buf = s.wr.Seal(buf, nonce(s.wn), hdr[:], nil)
	s.wn++
	if len(data)+pad > 0 {
		body := make([]byte, len(data)+pad)
		copy(body, data)
		buf = s.wr.Seal(buf, nonce(s.wn), body, nil)
		s.wn++
	}
	// Каждый кадр — запись TLS application data
	buf[0], buf[1], buf[2] = recAppData, 3, 3
	binary.BigEndian.PutUint16(buf[3:], uint16(len(buf)-5))
	n, err := s.c.Write(buf)
	s.last.Store(time.Now().UnixNano())
	s.WireOut.Add(int64(n))
	s.DataOut.Add(int64(len(data)))
	return err
}

func (s *secureConn) Write(p []byte) (int, error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	sent := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxData {
			n = maxData
		}
		if s.sh.frames < jitterFrames { // небольшие случайные паузы в начале: ровный темп выдаёт программу
			time.Sleep(time.Duration(s.sh.r.IntN(jitterMax+1)) * time.Millisecond)
		}
		if err := s.writeFrame(p[:n], s.sh.padFor(n)); err != nil {
			return sent, err
		}
		sent += n
		p = p[n:]
	}
	return sent, nil
}

// CloseWrite отправляет признак конца потока и закрывает направление записи.
func (s *secureConn) CloseWrite() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	err := s.writeFrame(nil, 0)
	if tc, ok := s.c.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	return err
}

func (s *secureConn) Read(p []byte) (int, error) {
	if s.skip {
		s.skip = false
		if err := skipServerFlight(s.c); err != nil {
			return 0, err
		}
	}
	for len(s.rbuf) == 0 {
		var rh [5]byte
		if _, err := io.ReadFull(s.c, rh[:]); err != nil {
			return 0, err
		}
		if rh[0] != recAppData || rh[1] != 3 {
			return 0, io.ErrUnexpectedEOF
		}
		rec := make([]byte, binary.BigEndian.Uint16(rh[3:]))
		if _, err := io.ReadFull(s.c, rec); err != nil {
			return 0, err
		}
		s.WireIn.Add(int64(5 + len(rec)))
		if len(rec) < 20 {
			return 0, io.ErrUnexpectedEOF
		}
		hdr, err := s.rd.Open(nil, nonce(s.rn), rec[:20], nil)
		if err != nil {
			return 0, err
		}
		s.rn++
		dl := int(binary.BigEndian.Uint16(hdr[0:]))
		pl := int(binary.BigEndian.Uint16(hdr[2:]))
		if dl+pl == 0 {
			return 0, io.EOF
		}
		if len(rec) != 20+dl+pl+16 {
			return 0, io.ErrUnexpectedEOF
		}
		plain, err := s.rd.Open(nil, nonce(s.rn), rec[20:], nil)
		if err != nil {
			return 0, err
		}
		s.rn++
		s.rbuf = plain[:dl]
	}
	n := copy(p, s.rbuf)
	s.rbuf = s.rbuf[n:]
	return n, nil
}

func (s *secureConn) Close() error {
	s.once.Do(func() { close(s.quit) })
	return s.c.Close()
}

// keepalive шлёт редкие холостые кадры, пока соединение простаивает: мобильные NAT не закрывают «тихие» соединения,
// а длинное молчание не отличает наш поток от обычного.
func (s *secureConn) keepalive() {
	for {
		wait := s.kaMin + time.Duration(s.sh.r.Int64N(int64(s.kaMax-s.kaMin)+1))
		select {
		case <-s.quit:
			return
		case <-time.After(wait):
		}
		if time.Since(time.Unix(0, s.last.Load())) < wait {
			continue
		}
		s.wmu.Lock()
		err := s.writeFrame(nil, 20+s.sh.r.IntN(100))
		s.wmu.Unlock()
		if err != nil {
			return
		}
	}
}

// pipe гоняет данные в обе стороны, пока обе половины не закончатся.
func pipe(a, b interface {
	io.ReadWriter
	CloseWrite() error
}) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src interface {
		io.ReadWriter
		CloseWrite() error
	}) {
		defer wg.Done()
		io.Copy(dst, src)
		dst.CloseWrite()
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

type tcpHalf struct{ *net.TCPConn }

func (t tcpHalf) CloseWrite() error { return t.TCPConn.CloseWrite() }

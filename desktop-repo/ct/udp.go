package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// UDP-режим: каждая датаграмма самодостаточна: метка(8) | случайный nonce(12) | AEAD([длина 2][данные][дополнение]).
// Направление (c/s) входит в проверяемые данные, чтобы ответы сервера нельзя было выдать за запросы клиента.

func udpSeal(ke []byte, dir byte, data []byte, pad int) []byte {
	aead, _ := chacha20poly1305.New(deriveKey(ke, nil, "udp"))
	tag := uidTag(ke)
	plain := make([]byte, 2+len(data)+pad)
	binary.BigEndian.PutUint16(plain, uint16(len(data)))
	copy(plain[2:], data)
	out := make([]byte, 8+12, 8+12+len(plain)+16)
	copy(out, tag[:])
	crand.Read(out[8:20])
	return aead.Seal(out, out[8:20], plain, []byte{dir})
}

func udpOpen(ke []byte, dir byte, pkt []byte) []byte {
	if len(pkt) < 8+12+2+16 {
		return nil
	}
	aead, _ := chacha20poly1305.New(deriveKey(ke, nil, "udp"))
	plain, err := aead.Open(nil, pkt[8:20], pkt[20:], []byte{dir})
	if err != nil || len(plain) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(plain))
	if 2+n > len(plain) {
		return nil
	}
	return plain[2 : 2+n]
}

type udpSession struct {
	up   *net.UDPConn
	last time.Time
}

func (s *Server) ServeUDP(pc *net.UDPConn) {
	buf := make([]byte, 65535)
	sh := map[string]*shaper{}
	var shm sync.Mutex
	go func() { // чистка простаивающих сессий
		for range time.Tick(30 * time.Second) {
			s.mu.Lock()
			for k, v := range s.udpSess {
				if time.Since(v.last) > 90*time.Second {
					v.up.Close()
					delete(s.udpSess, k)
				}
			}
			s.mu.Unlock()
		}
	}()
	for {
		n, from, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 8+12+2+16 {
			continue
		}
		var tag [8]byte
		copy(tag[:], buf[:8])
		e, ok := s.lookup(tag)
		if !ok {
			continue // чужим не отвечаем
		}
		data := udpOpen(e.ke, 'c', buf[:n])
		if data == nil {
			continue
		}
		key := from.String()
		s.mu.Lock()
		sess := s.udpSess[key]
		if sess == nil {
			ua, _ := net.ResolveUDPAddr("udp", s.Upstream)
			up, err := net.DialUDP("udp", nil, ua)
			if err != nil {
				s.mu.Unlock()
				continue
			}
			sess = &udpSession{up: up}
			s.udpSess[key] = sess
			shm.Lock()
			sh[key] = newShaper(profileFor(e.ke, []byte("udp")))
			shm.Unlock()
			go func(from *net.UDPAddr, sess *udpSession, ke []byte, key string) {
				rb := make([]byte, 65535)
				for {
					m, err := sess.up.Read(rb)
					if err != nil {
						return
					}
					shm.Lock()
					pad := sh[key].padFor(m)
					shm.Unlock()
					pc.WriteToUDP(udpSeal(ke, 's', rb[:m], pad), from)
				}
			}(from, sess, e.ke, key)
		}
		sess.last = time.Now()
		s.mu.Unlock()
		sess.up.Write(data)
	}
}

// ServeUDP на клиенте: локальный порт для sing-box, пакеты уходят на сервер в форме CT.
// Сокет не «привязан» к серверу: адрес берётся на каждый пакет, поэтому смена рабочего моста подхватывается сразу.
func (cl *Client) ServeUDP(local *net.UDPConn) error {
	rc, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return err
	}
	var mu sync.Mutex
	var lastLocal *net.UDPAddr
	sh := newShaper(profileFor(epochKey(cl.Key, epochDay(time.Now())), []byte("udp")))
	go func() {
		b := make([]byte, 65535)
		for {
			n, _, err := rc.ReadFromUDP(b)
			if err != nil {
				return
			}
			ke := epochKey(cl.Key, epochDay(time.Now()))
			if data := udpOpen(ke, 's', b[:n]); data != nil {
				mu.Lock()
				la := lastLocal
				mu.Unlock()
				if la != nil {
					local.WriteToUDP(data, la)
				}
			}
		}
	}()
	b := make([]byte, 65535)
	for {
		n, from, err := local.ReadFromUDP(b)
		if err != nil {
			return err
		}
		mu.Lock()
		lastLocal = from
		pad := sh.padFor(n)
		mu.Unlock()
		remote, err := net.ResolveUDPAddr("udp", cl.addr(time.Now()))
		if err != nil {
			continue
		}
		rc.WriteToUDP(udpSeal(epochKey(cl.Key, epochDay(time.Now())), 'c', b[:n], pad), remote)
	}
}

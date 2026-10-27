package main

import (
	crand "crypto/rand"
	"encoding/binary"
	mrand "math/rand/v2"
)

// Профиль — распределение размеров кадров на проводе. Выбирается из ключа дня и одноразового числа соединения,
// поэтому у разных пользователей и разных соединений «почерк» разный.
type profile struct {
	name    string
	sizes   []int
	weights []int
	hello   [2]int // диапазон дополнения после рукопожатия
}

var baseProfiles = []profile{
	{"web", []int{140, 260, 520, 700, 1200, 1400}, []int{22, 16, 12, 8, 14, 28}, [2]int{0, 260}},
	{"video", []int{120, 600, 1380, 1440}, []int{10, 6, 54, 30}, [2]int{0, 120}},
	{"call", []int{110, 160, 220, 340}, []int{34, 30, 24, 12}, [2]int{0, 400}},
}

// profileFor строит профиль для пользователя и дня: берёт один из базовых и сдвигает размеры (±18%) и веса (±35%)
// по ключу, поэтому распределения у разных людей и в разные дни не совпадают. На одно соединение приходится ещё
// и своя выборка из него (cn выбирает базовый профиль).
func profileFor(ke, cn []byte) profile {
	v := binary.BigEndian.Uint32(mac(ke, []byte("profile"), cn)[:4])
	base := baseProfiles[int(v)%len(baseProfiles)]
	d := mac(ke, []byte("shape"), []byte(base.name)) // 32 байта: хватает на размеры и веса
	p := profile{name: base.name, hello: base.hello}
	for i, sz := range base.sizes {
		j := (float64(d[i%16])/255 - 0.5) * 0.36
		n := int(float64(sz) * (1 + j))
		if n < frameOverhead+8 {
			n = frameOverhead + 8
		}
		p.sizes = append(p.sizes, n)
	}
	for i, w := range base.weights {
		j := (float64(d[16+i%16])/255 - 0.5) * 0.70
		n := int(float64(w) * (1 + j))
		if n < 1 {
			n = 1
		}
		p.weights = append(p.weights, n)
	}
	return p
}

func newRand() *mrand.Rand {
	var seed [32]byte
	crand.Read(seed[:])
	return mrand.New(mrand.NewChaCha8(seed))
}

func (p profile) sample(r *mrand.Rand) int {
	total := 0
	for _, w := range p.weights {
		total += w
	}
	x := r.IntN(total)
	for i, w := range p.weights {
		if x < w {
			return p.sizes[i]
		}
		x -= w
	}
	return p.sizes[len(p.sizes)-1]
}

const (
	frameOverhead = 36   // заголовок 20 + тег тела 16
	bulkThreshold = 1200 // крупные куски (скачивание) не дополняем: скорость не страдает
	warmupFrames  = 12   // первые кадры соединения всегда выглядят по профилю: по ним чаще всего и опознают
	padBudget     = 0.05 // дальше дополнение не больше 5% от данных...
	padAllowance  = 4096 // ...плюс небольшой запас для коротких соединений
)

// shaper решает, сколько добавить к каждому кадру.
type shaper struct {
	p      profile
	r      *mrand.Rand
	frames int
	data   int64
	pad    int64
}

func newShaper(p profile) *shaper { return &shaper{p: p, r: newRand()} }

func (s *shaper) padFor(n int) int {
	s.frames++
	s.data += int64(n)
	if n >= bulkThreshold {
		return 0
	}
	want := s.p.sample(s.r) - frameOverhead - n
	if want <= 0 {
		return 0
	}
	if s.frames > warmupFrames {
		room := int64(padBudget*float64(s.data)) + padAllowance - s.pad
		if room <= 0 {
			return 0
		}
		if int64(want) > room {
			want = int(room)
		}
	}
	s.pad += int64(want)
	return want
}

func (s *shaper) helloPad() int {
	lo, hi := s.p.hello[0], s.p.hello[1]
	if hi <= lo {
		return lo
	}
	return lo + s.r.IntN(hi-lo+1)
}

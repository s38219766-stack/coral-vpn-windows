// coral — консольный клиент Coral VPN для Linux и Windows. Движок: sing-box; свой протокол Coral Transport — через ct.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const usage = `Coral VPN (консольная версия)

  coral login <ссылка-подписки>    сохранить подписку (ссылку даёт бот или Mini App)
  coral servers                    показать доступные способы подключения
  coral up [-mode tun|proxy] [-route ru|all] [-port 7890] [-server строка]
                                   подключиться (tun — вся система, нужны права администратора;
                                   proxy — локальный прокси 127.0.0.1:7890 без прав;
                                   -server — использовать только подходящие способы)
  coral down                       отключиться
  coral status                     состояние

Нужны рядом с программой (или в PATH): sing-box, а для «Нашего протокола» ещё ct.`

func main() {
	if len(os.Args) < 2 {
		fmt.Println(usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "login":
		if len(os.Args) < 3 {
			fatal("укажите ссылку подписки: coral login <ссылка>")
		}
		servers, err := Fetch(os.Args[2])
		if err != nil {
			fatal("не удалось получить подписку: %v", err)
		}
		if err := saveStore(Store{Sub: os.Args[2], Servers: servers}); err != nil {
			fatal("не удалось сохранить: %v", err)
		}
		fmt.Printf("Готово. Найдено способов подключения: %d. Запуск: coral up\n", len(servers))
	case "servers":
		st := loadStore()
		if st.Sub == "" {
			fatal("сначала: coral login <ссылка>")
		}
		servers, err := Fetch(st.Sub)
		if err != nil {
			fmt.Println("(используем сохранённый список:", err, ")")
			servers = st.Servers
		}
		for i, s := range servers {
			note := ""
			if s.Kind == "vless" && s.Network == "xhttp" {
				note = "  [пока не поддерживается на компьютере]"
			}
			fmt.Printf("%2d. %-34s %s%s\n", i+1, s.Name, s.Kind, note)
		}
	case "up":
		fs := flag.NewFlagSet("up", flag.ExitOnError)
		mode := fs.String("mode", "tun", "tun | proxy")
		route := fs.String("route", "ru", "ru — российское напрямую, all — всё через VPN")
		port := fs.Int("port", 7890, "порт локального прокси")
		only := fs.String("server", "", "использовать только способы, в названии или типе которых есть эта строка (например Coral FI, ct, hysteria2)")
		fs.Parse(os.Args[2:])
		up(*mode, *route, *port, *only)
	case "down":
		down()
	case "status":
		status()
	default:
		fmt.Println(usage)
		os.Exit(2)
	}
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "ошибка: "+f+"\n", a...)
	os.Exit(1)
}

// findBin ищет вспомогательную программу: рядом с coral, в каталоге настроек, затем в PATH.
func findBin(name string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if exe, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(exe), name); fileExists(p) {
			return p
		}
	}
	if p := filepath.Join(confDir(), "bin", name); fileExists(p) {
		return p
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

func fileExists(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() }

func up(mode, route string, port int, only string) {
	if mode != "tun" && mode != "proxy" {
		fatal("режим должен быть tun или proxy")
	}
	st := loadStore()
	if st.Sub == "" {
		fatal("сначала: coral login <ссылка>")
	}
	if mode == "tun" && !isAdmin() {
		fatal("для режима tun нужны права администратора (Linux: sudo coral up; Windows: запустите от имени администратора). Без прав: coral up -mode proxy")
	}
	sb := findBin("sing-box")
	if sb == "" {
		fatal("не найден sing-box: положите его рядом с coral или в %s", filepath.Join(confDir(), "bin"))
	}
	servers, err := Fetch(st.Sub)
	if err != nil {
		fmt.Println("подписка недоступна, берём сохранённый список:", err)
		servers = st.Servers
	} else {
		st.Servers = servers
		saveStore(st)
	}
	if only != "" {
		var keep []Server
		for _, s := range servers {
			if strings.Contains(strings.ToLower(s.Name), strings.ToLower(only)) || s.Kind == only {
				keep = append(keep, s)
			}
		}
		if len(keep) == 0 {
			fatal("нет способов, подходящих под «%s» (список: coral servers)", only)
		}
		servers = keep
	}
	if err := os.MkdirAll(confDir(), 0o700); err != nil {
		fatal("%v", err)
	}
	built, err := BuildConfig(servers, Options{Mode: mode, Route: route, ProxyPort: port, CacheFile: filepath.Join(confDir(), "cache.db")}, nil)
	if err != nil {
		fatal("%v", err)
	}
	cfgPath := filepath.Join(confDir(), "sing-box.json")
	if err := os.WriteFile(cfgPath, built.JSON, 0o600); err != nil {
		fatal("%v", err)
	}
	for _, s := range built.Skipped {
		fmt.Println("пропущено:", s)
	}
	fmt.Printf("способов в работе: %d (автовыбор по скорости)\n", len(built.Tags))

	var procs []*exec.Cmd
	cleanup := func() {
		for _, p := range procs {
			if p.Process != nil {
				p.Process.Kill()
			}
		}
		os.Remove(pidFile())
	}
	if built.CT != nil {
		ct := findBin("ct")
		if ct == "" {
			fmt.Println("ct не найден — «Наш протокол» отключён (положите ct рядом с coral)")
		} else {
			c := exec.Command(ct, "client", "-listen", "127.0.0.1:19500", "-remote", built.CT.Hosts, "-ports", orDefault(built.CT.Ports, "9500:9500"))
			c.Env = append(os.Environ(), "CT_KEY="+built.CT.Key)
			c.Stdout, c.Stderr = os.Stdout, os.Stderr
			if err := c.Start(); err != nil {
				fatal("не удалось запустить ct: %v", err)
			}
			procs = append(procs, c)
		}
	}
	cmd := exec.Command(sb, "run", "-c", cfgPath, "-D", confDir())
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		cleanup()
		fatal("не удалось запустить sing-box: %v", err)
	}
	procs = append(procs, cmd)
	os.WriteFile(pidFile(), []byte(strconv.Itoa(os.Getpid())), 0o600)

	started := time.Now()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	if waitPort(port, 15*time.Second) {
		if ok, ms := probe(port); ok {
			fmt.Printf("✅ Подключено (проверка прошла за %d мс). Режим: %s. Остановить: Ctrl+C или coral down\n", ms, mode)
		} else {
			fmt.Println("⚠ Локальный прокси работает, но проверка связи не прошла: возможно, идёт выбор способа, подождите несколько секунд")
		}
	} else {
		fmt.Println("⚠ sing-box не открыл порт вовремя — смотрите сообщения выше")
	}
	select {
	case <-sig:
		fmt.Println("\nОтключаемся…")
	case err := <-done:
		fmt.Println("sing-box остановился:", err)
		if time.Since(started) < 10*time.Second && mode == "tun" {
			fmt.Println("Подсказка: туннель не запустился. Чаще всего мешает другой включённый VPN (MantaRay, WireGuard, OpenVPN и т.п.): выключите его и повторите. Без прав и без конфликтов можно запустить: coral up -mode proxy")
		}
	}
	cleanup()
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func pidFile() string { return filepath.Join(confDir(), "coral.pid") }

func down() {
	b, err := os.ReadFile(pidFile())
	if err != nil {
		fmt.Println("не запущено")
		return
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	p, err := os.FindProcess(pid)
	if err == nil {
		if runtime.GOOS == "windows" {
			err = p.Kill()
		} else {
			err = p.Signal(syscall.SIGTERM)
		}
	}
	if err != nil {
		fmt.Println("процесс уже завершён")
		os.Remove(pidFile())
		return
	}
	fmt.Println("команда отключения отправлена")
}

func status() {
	st := loadStore()
	if st.Sub == "" {
		fmt.Println("не настроено: coral login <ссылка>")
		return
	}
	b, err := os.ReadFile(pidFile())
	if err != nil {
		fmt.Println("состояние: выключено")
		return
	}
	fmt.Printf("состояние: запущено (pid %s)\n", strings.TrimSpace(string(b)))
	if ok, ms := probe(7890); ok {
		fmt.Printf("проверка связи через локальный прокси: ок, %d мс\n", ms)
	} else {
		fmt.Println("проверка связи через локальный прокси: не прошла")
	}
}

func waitPort(port int, d time.Duration) bool {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond); err == nil {
			c.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// probe — запрос через локальный прокси; 204 значит, что трафик проходит через выбранный сервер.
func probe(port int) (bool, int) {
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	c := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	for i := 0; i < 8; i++ {
		t0 := time.Now()
		if r, err := c.Get("https://cp.cloudflare.com/generate_204"); err == nil {
			r.Body.Close()
			if r.StatusCode == 204 {
				return true, int(time.Since(t0).Milliseconds())
			}
		}
		time.Sleep(time.Second)
	}
	return false, 0
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Server — один способ подключения: VLESS из подписки или дополнительный сервер из /api/app/extra.
type Server struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"` // vless | hysteria2 | tuic | ss2022 | ct | shadowtls
	UUID       string   `json:"uuid,omitempty"`
	Host       string   `json:"host"`
	Port       int      `json:"port,omitempty"`
	Network    string   `json:"network,omitempty"`  // tcp | ws | xhttp
	Security   string   `json:"security,omitempty"` // reality | tls | none
	SNI        string   `json:"sni,omitempty"`
	FP         string   `json:"fp,omitempty"`
	PBK        string   `json:"pbk,omitempty"`
	SID        string   `json:"sid,omitempty"`
	Flow       string   `json:"flow,omitempty"`
	Path       string   `json:"path,omitempty"`
	HostHeader string   `json:"host_header,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
	Secret     string   `json:"secret,omitempty"`
	SSMethod   string   `json:"ss_method,omitempty"`
	SSPassword string   `json:"ss_password,omitempty"`
	Ports      string   `json:"ports,omitempty"`
	CTKey      string   `json:"ct_key,omitempty"`
}

var httpc = &http.Client{Timeout: 20 * time.Second}

func get(u string) (string, error) {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "CoralDesktop/0.1")
	r, err := httpc.Do(req)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	b, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		return "", err
	}
	if r.StatusCode != 200 {
		return "", fmt.Errorf("%s: HTTP %d", u, r.StatusCode)
	}
	return string(b), nil
}

// ParseSubscription разбирает подписку Marzban: base64 со списком ссылок vless:// по строкам (или сами ссылки).
func ParseSubscription(body string) []Server {
	text := strings.TrimSpace(body)
	if !strings.Contains(text, "://") {
		if dec, err := base64.StdEncoding.DecodeString(pad(text)); err == nil {
			text = string(dec)
		} else if dec, err := base64.URLEncoding.DecodeString(pad(text)); err == nil {
			text = string(dec)
		}
	}
	var out []Server
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "vless://") {
			continue
		}
		if s, err := parseVless(line); err == nil {
			out = append(out, s)
		}
	}
	return out
}

func pad(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r", ""), "\n", "")
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return s
}

func parseVless(link string) (Server, error) {
	u, err := url.Parse(link)
	if err != nil || u.User == nil || u.Hostname() == "" {
		return Server{}, fmt.Errorf("плохая ссылка")
	}
	q := u.Query()
	port := 443
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	name, _ := url.QueryUnescape(u.Fragment)
	if name == "" {
		name = u.Hostname()
	}
	def := func(v, d string) string {
		if v == "" {
			return d
		}
		return v
	}
	var alpn []string
	for _, a := range strings.Split(q.Get("alpn"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			alpn = append(alpn, a)
		}
	}
	return Server{
		Name: name, Kind: "vless", UUID: u.User.Username(), Host: u.Hostname(), Port: port,
		Network: def(q.Get("type"), "tcp"), Security: def(q.Get("security"), "none"), SNI: q.Get("sni"), FP: def(q.Get("fp"), "chrome"),
		PBK: q.Get("pbk"), SID: q.Get("sid"), Flow: q.Get("flow"), Path: q.Get("path"), HostHeader: q.Get("host"), ALPN: alpn,
	}, nil
}

// ParseExtra разбирает ответ /api/app/extra (Hysteria2, TUIC, Shadowsocks, Coral Transport, Shadow-TLS).
func ParseExtra(body string) []Server {
	var d struct {
		Servers []map[string]any `json:"servers"`
	}
	if json.Unmarshal([]byte(body), &d) != nil {
		return nil
	}
	str := func(m map[string]any, k string) string { v, _ := m[k].(string); return v }
	var out []Server
	for _, m := range d.Servers {
		kind := str(m, "kind")
		switch kind {
		case "hysteria2", "tuic", "ss2022", "ct", "shadowtls":
		default:
			continue
		}
		port := 0
		if f, ok := m["port"].(float64); ok {
			port = int(f)
		}
		out = append(out, Server{
			Name: str(m, "name"), Kind: kind, UUID: str(m, "uuid"), Host: str(m, "host"), Port: port, SNI: str(m, "sni"),
			Secret: str(m, "password"), SSMethod: str(m, "ss_method"), SSPassword: str(m, "ss_password"), Ports: str(m, "ports"), CTKey: str(m, "ct_key"),
		})
	}
	return out
}

// Fetch загружает подписку и дополнительные серверы. Адрес API берётся из самой ссылки подписки.
func Fetch(sub string) ([]Server, error) {
	body, err := get(sub)
	if err != nil {
		return nil, err
	}
	servers := ParseSubscription(body)
	if u, err := url.Parse(sub); err == nil {
		q := url.Values{"sub": {sub}, "carrier": {"desktop"}, "net": {"wifi"}}
		if extra, err := get(fmt.Sprintf("%s://%s/api/app/extra?%s", u.Scheme, u.Host, q.Encode())); err == nil {
			servers = append(servers, ParseExtra(extra)...)
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("в подписке нет серверов: проверьте срок действия")
	}
	return servers, nil
}

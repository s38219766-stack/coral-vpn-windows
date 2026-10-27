package main

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

type Options struct {
	Mode      string // tun | proxy
	Route     string // ru | all
	ProxyPort int
	CTPort    int
	CacheFile string
}

// CTSpec — параметры локального ct-клиента (Coral Transport) для сервера kind=ct.
type CTSpec struct {
	Hosts string
	Ports string
	Key   string
}

type Built struct {
	JSON    []byte
	Tags    []string // понятные названия серверов (для вывода)
	CT      *CTSpec
	Skipped []string // что не поддерживается на компьютере
}

type M = map[string]any

func tlsObj(sni string) M {
	return M{"enabled": true, "server_name": sni}
}

func lookup4(host string) []string {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	var out []string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return out
}

var bankSuffix = []string{"sberbank.com", "tinkoff.com", "vtb.com", "alfabank.com", "2gis.com", "ozon.ru", "ozonusercontent.com", "wbstatic.net", "avito.st",
	"userapi.com", "vk-cdn.net", "vkuser.net", "mycdn.me", "yandex.net", "yandex.com", "yastatic.net", "rustore.ru", "mts.ru"}

// BuildConfig собирает конфигурацию sing-box (формат 1.14) для набора серверов.
func BuildConfig(servers []Server, o Options, resolve func(string) []string) (*Built, error) {
	if resolve == nil {
		resolve = lookup4
	}
	if o.ProxyPort == 0 {
		o.ProxyPort = 7890
	}
	if o.CTPort == 0 {
		o.CTPort = 19500
	}
	b := &Built{}
	var outs []M
	var tags []string
	exclude := map[string]bool{}
	addExclude := func(hosts string) {
		for _, h := range strings.Split(hosts, ",") {
			for _, ip := range resolve(strings.TrimSpace(h)) {
				exclude[ip] = true
			}
		}
	}
	for i, s := range servers {
		tag := fmt.Sprintf("%02d %s", i+1, s.Name)
		switch s.Kind {
		case "vless":
			if s.Network == "xhttp" {
				b.Skipped = append(b.Skipped, s.Name+" (XHTTP пока не поддерживается на компьютере)")
				continue
			}
			ips := resolve(s.Host)
			if len(ips) == 0 {
				b.Skipped = append(b.Skipped, s.Name+" (не удалось определить адрес "+s.Host+")")
				continue
			}
			addExclude(s.Host)
			o1 := M{"type": "vless", "tag": tag, "server": ips[0], "server_port": s.Port, "uuid": s.UUID}
			if s.Flow != "" {
				o1["flow"] = s.Flow
			}
			sni := s.SNI
			if sni == "" {
				sni = s.Host
			}
			t := tlsObj(sni)
			t["utls"] = M{"enabled": true, "fingerprint": s.FP}
			switch s.Security {
			case "reality":
				t["reality"] = M{"enabled": true, "public_key": s.PBK, "short_id": s.SID}
				o1["tls"] = t
			case "tls":
				if len(s.ALPN) > 0 {
					t["alpn"] = s.ALPN
				}
				o1["tls"] = t
			}
			if s.Network == "ws" {
				host := s.HostHeader
				if host == "" {
					host = sni
				}
				path := s.Path
				if path == "" {
					path = "/"
				}
				o1["transport"] = M{"type": "ws", "path": path, "headers": M{"Host": host}}
			}
			outs = append(outs, o1)
		case "hysteria2":
			addExclude(s.Host)
			o1 := M{"type": "hysteria2", "tag": tag, "server": s.Host, "server_port": s.Port, "password": s.Secret,
				"tls": M{"enabled": true, "server_name": s.SNI, "alpn": []string{"h3"}}}
			if s.Ports != "" {
				o1["server_ports"] = []string{s.Ports}
				o1["hop_interval"] = "30s"
			}
			outs = append(outs, o1)
		case "tuic":
			addExclude(s.Host)
			outs = append(outs, M{"type": "tuic", "tag": tag, "server": s.Host, "server_port": s.Port, "uuid": s.UUID, "password": s.Secret,
				"congestion_control": "bbr", "tls": M{"enabled": true, "server_name": s.SNI, "alpn": []string{"h3"}}})
		case "ss2022":
			addExclude(s.Host)
			outs = append(outs, M{"type": "shadowsocks", "tag": tag, "server": s.Host, "server_port": s.Port, "method": s.SSMethod, "password": s.Secret})
		case "shadowtls":
			addExclude(s.Host)
			outs = append(outs,
				M{"type": "shadowtls", "tag": tag + " (маска)", "server": s.Host, "server_port": s.Port, "version": 3, "password": s.Secret, "tls": tlsObj(s.SNI)},
				M{"type": "shadowsocks", "tag": tag, "detour": tag + " (маска)", "method": s.SSMethod, "password": s.SSPassword})
		case "ct":
			if b.CT != nil {
				continue
			}
			addExclude(s.Host)
			b.CT = &CTSpec{Hosts: s.Host, Ports: s.Ports, Key: s.CTKey}
			outs = append(outs, M{"type": "shadowsocks", "tag": tag, "server": "127.0.0.1", "server_port": o.CTPort, "method": s.SSMethod, "password": s.Secret,
				"multiplex": M{"enabled": true, "protocol": "smux", "max_connections": 4, "min_streams": 4}})
		default:
			continue
		}
		tags = append(tags, tag)
	}
	if len(tags) == 0 {
		return nil, fmt.Errorf("нет серверов, которые можно использовать на компьютере")
	}
	b.Tags = tags

	inbounds := []M{{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": o.ProxyPort}}
	if o.Mode == "tun" {
		var ex []string
		for ip := range exclude {
			ex = append(ex, ip+"/32")
		}
		inbounds = append(inbounds, M{"type": "tun", "tag": "tun-in", "interface_name": "coral0", "address": []string{"172.31.254.1/30"}, "auto_route": true,
			"strict_route": true, "stack": "mixed", "route_exclude_address": ex})
	}
	outbounds := []M{{"type": "direct", "tag": "direct"}}
	outbounds = append(outbounds, M{"type": "selector", "tag": "proxy", "outbounds": append([]string{"auto"}, tags...), "default": "auto"})
	outbounds = append(outbounds, M{"type": "urltest", "tag": "auto", "outbounds": tags, "url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 100})
	outbounds = append(outbounds, outs...)

	rules := []M{
		{"action": "sniff"},
		{"protocol": "dns", "action": "hijack-dns"},
		{"ip_is_private": true, "outbound": "direct"},
	}
	var ruleSets []M
	dnsRules := []M{}
	if o.Route != "all" {
		rules = append(rules,
			M{"domain_suffix": append([]string{"ru", "su", "xn--p1ai"}, bankSuffix...), "outbound": "direct"},
			M{"rule_set": []string{"geoip-ru", "geosite-yandex", "geosite-vk", "geosite-mailru", "geosite-category-gov-ru"}, "outbound": "direct"})
		for _, n := range []string{"geoip-ru", "geosite-yandex", "geosite-vk", "geosite-mailru", "geosite-category-gov-ru"} {
			repo := "sing-geosite"
			if strings.HasPrefix(n, "geoip") {
				repo = "sing-geoip"
			}
			ruleSets = append(ruleSets, M{"type": "remote", "tag": n, "format": "binary", "download_detour": "proxy", "update_interval": "7d",
				"url": "https://raw.githubusercontent.com/SagerNet/" + repo + "/rule-set/" + n + ".srs"})
		}
		dnsRules = append(dnsRules, M{"domain_suffix": []string{"ru", "su", "xn--p1ai"}, "server": "local"},
			M{"rule_set": []string{"geosite-yandex", "geosite-vk", "geosite-mailru", "geosite-category-gov-ru"}, "server": "local"})
	}
	route := M{"rules": rules, "final": "proxy", "auto_detect_interface": true, "default_domain_resolver": "local"}
	if len(ruleSets) > 0 {
		route["rule_set"] = ruleSets
	}
	cfg := M{
		"log": M{"level": "warn"},
		"dns": M{
			"servers": []M{{"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"}, {"type": "local", "tag": "local"}},
			"rules":   dnsRules, "final": "remote", "strategy": "ipv4_only",
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     route,
	}
	if o.CacheFile != "" {
		cfg["experimental"] = M{"cache_file": M{"enabled": true, "path": o.CacheFile}}
	}
	js, err := json.MarshalIndent(cfg, "", " ")
	b.JSON = js
	return b, err
}

package main

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
)

// Store — сохранённые настройки: ссылка подписки и последний список серверов (на случай, если домен недоступен).
type Store struct {
	Sub     string   `json:"sub"`
	Servers []Server `json:"servers,omitempty"`
}

// confDir — каталог настроек. При запуске через sudo берём каталог обычного пользователя, а не root.
func confDir() string {
	if v := os.Getenv("CORAL_HOME"); v != "" {
		return v
	}
	if os.Geteuid() == 0 {
		if name := os.Getenv("SUDO_USER"); name != "" {
			if u, err := user.Lookup(name); err == nil {
				return filepath.Join(u.HomeDir, ".config", "coral")
			}
		}
	}
	d, err := os.UserConfigDir()
	if err != nil {
		d = "."
	}
	return filepath.Join(d, "coral")
}

func loadStore() Store {
	var s Store
	if b, err := os.ReadFile(filepath.Join(confDir(), "config.json")); err == nil {
		json.Unmarshal(b, &s)
	}
	return s
}

func saveStore(s Store) error {
	if err := os.MkdirAll(confDir(), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", " ")
	return os.WriteFile(filepath.Join(confDir(), "config.json"), b, 0o600)
}

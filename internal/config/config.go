package config

import (
	"gopkg.in/yaml.v2"
	"os"
)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
	Mail     MailConfig     `yaml:"mail"`
	Cert     CertConfig     `yaml:"cert"`
	Storage  StorageConfig  `yaml:"storage"`
}

type StorageConfig struct {
	DataDir string `yaml:"data_dir"`
}

type ServerConfig struct {
	Port string `yaml:"port"`
	Mode string `yaml:"mode"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type MailConfig struct {
	DataPath   string   `yaml:"data_path"`
	LogPath    string   `yaml:"log_path"`
	Domains    []string `yaml:"domains"`
	AdminEmail string   `yaml:"admin_email"`
}

type CertConfig struct {
	AcmePath  string `yaml:"acme_path"`
	CertPath  string `yaml:"cert_path"`
	DNSConfig string `yaml:"dns_config"`
	AutoRenew bool   `yaml:"auto_renew"`
}

func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port: "8686",
			Mode: "release",
		},
		Database: DatabaseConfig{
			Path: "./db",
		},
		Mail: MailConfig{
			DataPath: "./mail",
			LogPath:  "./logs",
			Domains:  []string{},
		},
		Cert: CertConfig{
			AcmePath:  "./acme",
			CertPath:  "./certs",
			AutoRenew: true,
		},
		Storage: StorageConfig{
			DataDir: "./data",
		},
	}

	if configFile := os.Getenv("ESEMAIL_CONFIG"); configFile != "" {
		data, err := os.ReadFile(configFile)
		if err == nil {
			yaml.Unmarshal(data, cfg)
		}
	}

	if port := os.Getenv("ESEMAIL_PORT"); port != "" {
		cfg.Server.Port = port
	}

	return cfg, nil
}

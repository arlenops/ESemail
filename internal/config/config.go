package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Server   ServerConfig   `yaml:"server" json:"server"`
	Database DatabaseConfig `yaml:"database" json:"database"`
	Mail     MailConfig     `yaml:"mail" json:"mail"`
	Cert     CertConfig     `yaml:"cert" json:"cert"`
	Storage  StorageConfig  `yaml:"storage" json:"storage"`
	Security SecurityConfig `yaml:"security" json:"security"`
	Logging  LoggingConfig  `yaml:"logging" json:"logging"`
}

type StorageConfig struct {
	DataDir     string `yaml:"data_dir" json:"data_dir" env:"STORAGE_DATA_DIR" default:"./data"`
	BackupDir   string `yaml:"backup_dir" json:"backup_dir" env:"STORAGE_BACKUP_DIR" default:"./backups"`
	MaxFileSize int64  `yaml:"max_file_size" json:"max_file_size" default:"104857600"`
	CleanupDays int    `yaml:"cleanup_days" json:"cleanup_days" default:"30"`
}

type ServerConfig struct {
	Port            string        `yaml:"port" json:"port" env:"SERVER_PORT" default:"8686"`
	Host            string        `yaml:"host" json:"host" env:"SERVER_HOST" default:"0.0.0.0"`
	Mode            string        `yaml:"mode" json:"mode" default:"release"`
	ReadTimeout     time.Duration `yaml:"read_timeout" json:"read_timeout" default:"30s"`
	WriteTimeout    time.Duration `yaml:"write_timeout" json:"write_timeout" default:"30s"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" json:"shutdown_timeout" default:"10s"`
	MaxHeaderBytes  int           `yaml:"max_header_bytes" json:"max_header_bytes" default:"1048576"`
}

type DatabaseConfig struct {
	Type         string `yaml:"type" json:"type" env:"DB_TYPE" default:"json"`
	Path         string `yaml:"path" json:"path" env:"DB_PATH" default:"./db"`
	Host         string `yaml:"host" json:"host" env:"DB_HOST" default:"localhost"`
	Port         int    `yaml:"port" json:"port" env:"DB_PORT" default:"5432"`
	Username     string `yaml:"username" json:"username" env:"DB_USERNAME"`
	Password     string `yaml:"password" json:"password" env:"DB_PASSWORD"`
	Database     string `yaml:"database" json:"database" env:"DB_NAME" default:"esemail"`
	SSLMode      string `yaml:"ssl_mode" json:"ssl_mode" env:"DB_SSL_MODE" default:"disable"`
	MaxOpenConns int    `yaml:"max_open_conns" json:"max_open_conns" default:"10"`
	MaxIdleConns int    `yaml:"max_idle_conns" json:"max_idle_conns" default:"5"`
}

type MailConfig struct {
	Domain          string        `yaml:"domain" json:"domain" env:"MAIL_DOMAIN" default:"localhost"`
	DataPath        string        `yaml:"data_path" json:"data_path" default:"./mail"`
	LogPath         string        `yaml:"log_path" json:"log_path" default:"./logs"`
	Domains         []string      `yaml:"domains" json:"domains"`
	AdminEmail      string        `yaml:"admin_email" json:"admin_email"`
	SMTPPort        string        `yaml:"smtp_port" json:"smtp_port" env:"SMTP_PORT" default:"2525"`
	SMTPSPort       string        `yaml:"smtps_port" json:"smtps_port" env:"SMTPS_PORT" default:"4465"`
	IMAPPort        string        `yaml:"imap_port" json:"imap_port" env:"IMAP_PORT" default:"1143"`
	IMAPSPort       string        `yaml:"imaps_port" json:"imaps_port" env:"IMAPS_PORT" default:"9993"`
	EnableTLS       bool          `yaml:"enable_tls" json:"enable_tls" env:"MAIL_ENABLE_TLS" default:"false"`
	TLSCertFile     string        `yaml:"tls_cert_file" json:"tls_cert_file" env:"TLS_CERT_FILE"`
	TLSKeyFile      string        `yaml:"tls_key_file" json:"tls_key_file" env:"TLS_KEY_FILE"`
	MaxMessageSize  int64         `yaml:"max_message_size" json:"max_message_size" default:"26214400"`
	MaxRecipients   int           `yaml:"max_recipients" json:"max_recipients" default:"100"`
	QueueRetries    int           `yaml:"queue_retries" json:"queue_retries" default:"3"`
	QueueInterval   time.Duration `yaml:"queue_interval" json:"queue_interval" default:"30s"`
	RetryInterval   time.Duration `yaml:"retry_interval" json:"retry_interval" default:"5m"`
	MaxConcurrent   int           `yaml:"max_concurrent" json:"max_concurrent" default:"10"`
}

type CertConfig struct {
	CertPath         string `yaml:"cert_path" json:"cert_path" env:"CERT_PATH" default:"/etc/ssl/mail"`
	Server           string `yaml:"server" json:"server" env:"ACME_SERVER" default:"letsencrypt"`
	Email            string `yaml:"email" json:"email" env:"ACME_EMAIL"`
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	JWTSecret        string        `yaml:"jwt_secret" json:"-" env:"JWT_SECRET"`
	JWTExpiration    time.Duration `yaml:"jwt_expiration" json:"jwt_expiration" default:"24h"`
	CSRFSecret       string        `yaml:"csrf_secret" json:"-" env:"CSRF_SECRET"`
	RateLimitEnabled bool          `yaml:"rate_limit_enabled" json:"rate_limit_enabled" default:"true"`
	RateLimitRPS     int           `yaml:"rate_limit_rps" json:"rate_limit_rps" default:"100"`
	RateLimitBurst   int           `yaml:"rate_limit_burst" json:"rate_limit_burst" default:"200"`
	AllowedOrigins   []string      `yaml:"allowed_origins" json:"allowed_origins"`
	TrustedProxies   []string      `yaml:"trusted_proxies" json:"trusted_proxies"`
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Level       string `yaml:"level" json:"level" env:"LOG_LEVEL" default:"info"`
	Format      string `yaml:"format" json:"format" env:"LOG_FORMAT" default:"json"`
	Output      string `yaml:"output" json:"output" env:"LOG_OUTPUT" default:"stdout"`
	File        string `yaml:"file" json:"file" env:"LOG_FILE"`
	MaxSize     int    `yaml:"max_size" json:"max_size" default:"100"`
	MaxBackups  int    `yaml:"max_backups" json:"max_backups" default:"3"`
	MaxAge      int    `yaml:"max_age" json:"max_age" default:"7"`
	Compress    bool   `yaml:"compress" json:"compress" default:"true"`
	EnableCaller bool  `yaml:"enable_caller" json:"enable_caller" default:"true"`
}

func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port:            "8686",
			Host:            "0.0.0.0",
			Mode:            "release",
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    30 * time.Second,
			ShutdownTimeout: 10 * time.Second,
			MaxHeaderBytes:  1 << 20, // 1MB
		},
		Database: DatabaseConfig{
			Type:         "json",
			Path:         "./db",
			Host:         "localhost",
			Port:         5432,
			Database:     "esemail",
			SSLMode:      "disable",
			MaxOpenConns: 10,
			MaxIdleConns: 5,
		},
		Mail: MailConfig{
			Domain:         "localhost",
			DataPath:       "./mail",
			LogPath:        "./logs",
			Domains:        []string{},
			SMTPPort:       "2525",
			SMTPSPort:      "4465",
			IMAPPort:       "1143",
			IMAPSPort:      "9993",
			EnableTLS:      false,
			MaxMessageSize: 25 * 1024 * 1024, // 25MB
			MaxRecipients:  100,
			QueueRetries:   3,
			QueueInterval:  30 * time.Second,
			RetryInterval:  5 * time.Minute,
			MaxConcurrent:  10,
		},
		Cert: CertConfig{
			CertPath:  "./certs",
			Server:    "letsencrypt",
			Email:     "admin@example.com",
		},
		Storage: StorageConfig{
			DataDir:     "./data",
			BackupDir:   "./backups",
			MaxFileSize: 100 * 1024 * 1024, // 100MB
			CleanupDays: 30,
		},
		Security: SecurityConfig{
			JWTExpiration:    24 * time.Hour,
			RateLimitEnabled: true,
			RateLimitRPS:     100,
			RateLimitBurst:   200,
			AllowedOrigins:   []string{},
			TrustedProxies:   []string{},
		},
		Logging: LoggingConfig{
			Level:        "info",
			Format:       "json",
			Output:       "stdout",
			MaxSize:      100,
			MaxBackups:   3,
			MaxAge:       7,
			Compress:     true,
			EnableCaller: true,
		},
	}

	// Load from config file
	if configFile := os.Getenv("ESEMAIL_CONFIG"); configFile != "" {
		if err := loadConfigFromFile(cfg, configFile); err != nil {
			return nil, fmt.Errorf("加载配置文件失败: %w", err)
		}
	}

	// Load from environment variables
	loadFromEnv(cfg)

	return cfg, nil
}

// loadConfigFromFile 从配置文件加载
func loadConfigFromFile(cfg *Config, configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	ext := strings.ToLower(filepath.Ext(configPath))
	switch ext {
	case ".yaml", ".yml":
		return yaml.Unmarshal(data, cfg)
	case ".json":
		return json.Unmarshal(data, cfg)
	default:
		// 默认尝试YAML
		return yaml.Unmarshal(data, cfg)
	}
}

// loadFromEnv 从环境变量加载配置
func loadFromEnv(cfg *Config) {
	// Server
	if port := os.Getenv("ESEMAIL_PORT"); port != "" {
		cfg.Server.Port = port
	}
	if port := os.Getenv("SERVER_PORT"); port != "" {
		cfg.Server.Port = port
	}
	if host := os.Getenv("SERVER_HOST"); host != "" {
		cfg.Server.Host = host
	}

	// Mail
	if domain := os.Getenv("MAIL_DOMAIN"); domain != "" {
		cfg.Mail.Domain = domain
	}
	if smtpPort := os.Getenv("SMTP_PORT"); smtpPort != "" {
		cfg.Mail.SMTPPort = smtpPort
	}
	if imapPort := os.Getenv("IMAP_PORT"); imapPort != "" {
		cfg.Mail.IMAPPort = imapPort
	}
	if enableTLS := os.Getenv("MAIL_ENABLE_TLS"); enableTLS != "" {
		if tls, err := strconv.ParseBool(enableTLS); err == nil {
			cfg.Mail.EnableTLS = tls
		}
	}

	// Database
	if dbType := os.Getenv("DB_TYPE"); dbType != "" {
		cfg.Database.Type = dbType
	}
	if dbHost := os.Getenv("DB_HOST"); dbHost != "" {
		cfg.Database.Host = dbHost
	}
	if dbPort := os.Getenv("DB_PORT"); dbPort != "" {
		if port, err := strconv.Atoi(dbPort); err == nil {
			cfg.Database.Port = port
		}
	}
	if dbUser := os.Getenv("DB_USERNAME"); dbUser != "" {
		cfg.Database.Username = dbUser
	}
	if dbPass := os.Getenv("DB_PASSWORD"); dbPass != "" {
		cfg.Database.Password = dbPass
	}
	if dbName := os.Getenv("DB_NAME"); dbName != "" {
		cfg.Database.Database = dbName
	}

	// Security
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		cfg.Security.JWTSecret = jwtSecret
	}
	if csrfSecret := os.Getenv("CSRF_SECRET"); csrfSecret != "" {
		cfg.Security.CSRFSecret = csrfSecret
	}

	// Logging
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		cfg.Logging.Level = logLevel
	}
	if logFormat := os.Getenv("LOG_FORMAT"); logFormat != "" {
		cfg.Logging.Format = logFormat
	}
	if logFile := os.Getenv("LOG_FILE"); logFile != "" {
		cfg.Logging.File = logFile
	}
}

// GetDSN 获取数据库连接字符串
func (c *Config) GetDSN() string {
	switch c.Database.Type {
	case "postgres", "postgresql":
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			c.Database.Host, c.Database.Port, c.Database.Username, c.Database.Password,
			c.Database.Database, c.Database.SSLMode)
	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			c.Database.Username, c.Database.Password, c.Database.Host, c.Database.Port, c.Database.Database)
	default:
		return ""
	}
}

// IsProduction 检查是否为生产环境
func (c *Config) IsProduction() bool {
	env := os.Getenv("APP_ENV")
	return env == "production" || env == "prod"
}

// IsDevelopment 检查是否为开发环境
func (c *Config) IsDevelopment() bool {
	env := os.Getenv("APP_ENV")
	return env == "development" || env == "dev" || env == ""
}

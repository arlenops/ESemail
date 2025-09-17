package config

import (
	"fmt"
	"os"
	"time"
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
	DataDir     string `yaml:"data_dir" json:"data_dir" env:"STORAGE_DATA_DIR" default:"/opt/esemail/data"`
	BackupDir   string `yaml:"backup_dir" json:"backup_dir" env:"STORAGE_BACKUP_DIR" default:"/opt/esemail/backups"`
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
	Path         string `yaml:"path" json:"path" env:"DB_PATH" default:"/opt/esemail/data/db"`
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
	DataPath        string        `yaml:"data_path" json:"data_path" default:"/opt/esemail/mail"`
	LogPath         string        `yaml:"log_path" json:"log_path" default:"/opt/esemail/logs"`
	Domains         []string      `yaml:"domains" json:"domains"`
	AdminEmail      string        `yaml:"admin_email" json:"admin_email"`
	SMTPPort        string        `yaml:"smtp_port" json:"smtp_port" env:"SMTP_PORT" default:"25"`
	SMTPSubmissionPort string     `yaml:"smtp_submission_port" json:"smtp_submission_port" env:"SMTP_SUBMISSION_PORT" default:"587"`
	SMTPSPort       string        `yaml:"smtps_port" json:"smtps_port" env:"SMTPS_PORT" default:"465"`
	IMAPPort        string        `yaml:"imap_port" json:"imap_port" env:"IMAP_PORT" default:"143"`
	IMAPSPort       string        `yaml:"imaps_port" json:"imaps_port" env:"IMAPS_PORT" default:"993"`
	EnableTLS       bool          `yaml:"enable_tls" json:"enable_tls" env:"MAIL_ENABLE_TLS" default:"true"`
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
	// 初始化必要目录
	initializeDirectories()

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
			Path:         "/opt/esemail/data/db",
			Host:         "localhost",
			Port:         5432,
			Database:     "esemail",
			SSLMode:      "disable",
			MaxOpenConns: 10,
			MaxIdleConns: 5,
		},
		Mail: MailConfig{
			Domain:             "caiji.wiki",
			DataPath:           "/opt/esemail/mail",
			LogPath:            "/opt/esemail/logs",
			Domains:            []string{"caiji.wiki"},
			AdminEmail:         "admin@caiji.wiki",
			SMTPPort:           "25",
			SMTPSubmissionPort: "587",
			SMTPSPort:          "465",
			IMAPPort:           "143",
			IMAPSPort:          "993",
			EnableTLS:          true,
			TLSCertFile:        "/etc/ssl/mail/mail.caiji.wiki/fullchain.pem",
			TLSKeyFile:         "/etc/ssl/mail/mail.caiji.wiki/private.key",
			MaxMessageSize:     25 * 1024 * 1024, // 25MB
			MaxRecipients:      100,
			QueueRetries:       3,
			QueueInterval:      30 * time.Second,
			RetryInterval:      5 * time.Minute,
			MaxConcurrent:      10,
		},
		Cert: CertConfig{
			CertPath: "/etc/ssl/mail",
			Server:   "letsencrypt",
			Email:    "admin@caiji.wiki",
		},
		Storage: StorageConfig{
			DataDir:     "/opt/esemail/data",
			BackupDir:   "/opt/esemail/backups",
			MaxFileSize: 100 * 1024 * 1024, // 100MB
			CleanupDays: 30,
		},
		Security: SecurityConfig{
			JWTSecret:        "caiji-wiki-mail-server-jwt-secret-2024-fixed",
			JWTExpiration:    24 * time.Hour,
			CSRFSecret:       "caiji-wiki-mail-server-csrf-secret-2024-fixed",
			RateLimitEnabled: true,
			RateLimitRPS:     100,
			RateLimitBurst:   200,
			AllowedOrigins:   []string{"https://mail.caiji.wiki", "http://localhost:8686"},
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

	return cfg, nil
}

// initializeDirectories 初始化所有必要的目录和权限
func initializeDirectories() {
	dirs := []string{
		"/opt/esemail",
		"/opt/esemail/data",
		"/opt/esemail/data/db",
		"/opt/esemail/mail",
		"/opt/esemail/logs",
		"/opt/esemail/backups",
		"/var/mail",
		"/var/mail/vhosts",
		"/var/mail/vhosts/caiji.wiki",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			// 忽略权限错误，继续创建其他目录
			continue
		}
	}

	// 尝试设置邮件目录权限（如果有权限）
	os.Chown("/var/mail", 5000, 5000)  // vmail用户
	os.Chown("/var/mail/vhosts", 5000, 5000)
	os.Chown("/var/mail/vhosts/caiji.wiki", 5000, 5000)
	os.Chmod("/var/mail/vhosts", 0770)
	os.Chmod("/var/mail/vhosts/caiji.wiki", 0770)
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
	return true // 固定为生产环境
}

// IsDevelopment 检查是否为开发环境
func (c *Config) IsDevelopment() bool {
	return false // 固定为生产环境
}

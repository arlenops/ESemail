package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// EnhancedConfig 增强的应用配置结构
type EnhancedConfig struct {
	Server   ServerConfig   `yaml:"server" json:"server"`
	Database DatabaseConfig `yaml:"database" json:"database"`
	Mail     MailConfig     `yaml:"mail" json:"mail"`
	Storage  StorageConfig  `yaml:"storage" json:"storage"`
	Security SecurityConfig `yaml:"security" json:"security"`
	Logging  LoggingConfig  `yaml:"logging" json:"logging"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Port            string        `yaml:"port" json:"port" env:"SERVER_PORT" default:"8686"`
	Host            string        `yaml:"host" json:"host" env:"SERVER_HOST" default:"0.0.0.0"`
	ReadTimeout     time.Duration `yaml:"read_timeout" json:"read_timeout" default:"30s"`
	WriteTimeout    time.Duration `yaml:"write_timeout" json:"write_timeout" default:"30s"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" json:"shutdown_timeout" default:"10s"`
	MaxHeaderBytes  int           `yaml:"max_header_bytes" json:"max_header_bytes" default:"1048576"`
}

// DatabaseConfig 数据库配置  
type DatabaseConfig struct {
	Type         string `yaml:"type" json:"type" env:"DB_TYPE" default:"json"`
	Host         string `yaml:"host" json:"host" env:"DB_HOST" default:"localhost"`
	Port         int    `yaml:"port" json:"port" env:"DB_PORT" default:"5432"`
	Username     string `yaml:"username" json:"username" env:"DB_USERNAME"`
	Password     string `yaml:"password" json:"password" env:"DB_PASSWORD"`
	Database     string `yaml:"database" json:"database" env:"DB_NAME" default:"esemail"`
	SSLMode      string `yaml:"ssl_mode" json:"ssl_mode" env:"DB_SSL_MODE" default:"disable"`
	MaxOpenConns int    `yaml:"max_open_conns" json:"max_open_conns" default:"10"`
	MaxIdleConns int    `yaml:"max_idle_conns" json:"max_idle_conns" default:"5"`
}

// MailConfig 邮件配置
type MailConfig struct {
	Domain          string        `yaml:"domain" json:"domain" env:"MAIL_DOMAIN" default:"localhost"`
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

// StorageConfig 存储配置
type StorageConfig struct {
	DataDir     string `yaml:"data_dir" json:"data_dir" env:"STORAGE_DATA_DIR" default:"./data"`
	BackupDir   string `yaml:"backup_dir" json:"backup_dir" env:"STORAGE_BACKUP_DIR" default:"./backups"`
	MaxFileSize int64  `yaml:"max_file_size" json:"max_file_size" default:"104857600"`
	CleanupDays int    `yaml:"cleanup_days" json:"cleanup_days" default:"30"`
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

// LoadEnhancedConfig 从多个来源加载增强配置
func LoadEnhancedConfig(configPaths ...string) (*EnhancedConfig, error) {
	config := &EnhancedConfig{}
	
	// 设置默认值
	if err := setEnhancedDefaults(config); err != nil {
		return nil, fmt.Errorf("设置默认值失败: %w", err)
	}
	
	// 从文件加载配置
	for _, path := range configPaths {
		if err := loadEnhancedConfigFromFile(config, path); err != nil {
			// 如果文件不存在，继续尝试下一个
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("从文件 %s 加载配置失败: %w", path, err)
		}
		break
	}
	
	// 从环境变量覆盖配置
	if err := loadEnhancedConfigFromEnv(config); err != nil {
		return nil, fmt.Errorf("从环境变量加载配置失败: %w", err)
	}
	
	// 验证配置
	if err := validateEnhancedConfig(config); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}
	
	return config, nil
}

// loadEnhancedConfigFromFile 从文件加载配置
func loadEnhancedConfigFromFile(config *EnhancedConfig, configPath string) error {
	if configPath == "" {
		return nil
	}
	
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return err
	}
	
	file, err := os.Open(configPath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	
	ext := strings.ToLower(filepath.Ext(configPath))
	switch ext {
	case ".yaml", ".yml":
		return yaml.Unmarshal(data, config)
	case ".json":
		return json.Unmarshal(data, config)
	default:
		// 尝试YAML格式
		if err := yaml.Unmarshal(data, config); err != nil {
			// 如果YAML失败，尝试JSON
			return json.Unmarshal(data, config)
		}
		return nil
	}
}

// setEnhancedDefaults 设置增强配置的默认值
func setEnhancedDefaults(config *EnhancedConfig) error {
	// Server defaults
	if config.Server.Port == "" {
		config.Server.Port = "8686"
	}
	if config.Server.Host == "" {
		config.Server.Host = "0.0.0.0"
	}
	if config.Server.ReadTimeout == 0 {
		config.Server.ReadTimeout = 30 * time.Second
	}
	if config.Server.WriteTimeout == 0 {
		config.Server.WriteTimeout = 30 * time.Second
	}
	if config.Server.ShutdownTimeout == 0 {
		config.Server.ShutdownTimeout = 10 * time.Second
	}
	if config.Server.MaxHeaderBytes == 0 {
		config.Server.MaxHeaderBytes = 1 << 20 // 1MB
	}
	
	// Mail defaults
	if config.Mail.Domain == "" {
		config.Mail.Domain = "localhost"
	}
	if config.Mail.SMTPPort == "" {
		config.Mail.SMTPPort = "2525"
	}
	if config.Mail.SMTPSPort == "" {
		config.Mail.SMTPSPort = "4465"
	}
	if config.Mail.IMAPPort == "" {
		config.Mail.IMAPPort = "1143"
	}
	if config.Mail.IMAPSPort == "" {
		config.Mail.IMAPSPort = "9993"
	}
	if config.Mail.MaxMessageSize == 0 {
		config.Mail.MaxMessageSize = 25 * 1024 * 1024 // 25MB
	}
	if config.Mail.MaxRecipients == 0 {
		config.Mail.MaxRecipients = 100
	}
	if config.Mail.QueueRetries == 0 {
		config.Mail.QueueRetries = 3
	}
	if config.Mail.QueueInterval == 0 {
		config.Mail.QueueInterval = 30 * time.Second
	}
	if config.Mail.RetryInterval == 0 {
		config.Mail.RetryInterval = 5 * time.Minute
	}
	if config.Mail.MaxConcurrent == 0 {
		config.Mail.MaxConcurrent = 10
	}
	
	// Storage defaults
	if config.Storage.DataDir == "" {
		config.Storage.DataDir = "./data"
	}
	if config.Storage.BackupDir == "" {
		config.Storage.BackupDir = "./backups"
	}
	if config.Storage.MaxFileSize == 0 {
		config.Storage.MaxFileSize = 100 * 1024 * 1024 // 100MB
	}
	if config.Storage.CleanupDays == 0 {
		config.Storage.CleanupDays = 30
	}
	
	// Database defaults
	if config.Database.Type == "" {
		config.Database.Type = "json"
	}
	if config.Database.Host == "" {
		config.Database.Host = "localhost"
	}
	if config.Database.Port == 0 {
		config.Database.Port = 5432
	}
	if config.Database.Database == "" {
		config.Database.Database = "esemail"
	}
	if config.Database.SSLMode == "" {
		config.Database.SSLMode = "disable"
	}
	if config.Database.MaxOpenConns == 0 {
		config.Database.MaxOpenConns = 10
	}
	if config.Database.MaxIdleConns == 0 {
		config.Database.MaxIdleConns = 5
	}
	
	// Security defaults
	if config.Security.JWTExpiration == 0 {
		config.Security.JWTExpiration = 24 * time.Hour
	}
	config.Security.RateLimitEnabled = true
	if config.Security.RateLimitRPS == 0 {
		config.Security.RateLimitRPS = 100
	}
	if config.Security.RateLimitBurst == 0 {
		config.Security.RateLimitBurst = 200
	}
	
	// Logging defaults
	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "json"
	}
	if config.Logging.Output == "" {
		config.Logging.Output = "stdout"
	}
	if config.Logging.MaxSize == 0 {
		config.Logging.MaxSize = 100
	}
	if config.Logging.MaxBackups == 0 {
		config.Logging.MaxBackups = 3
	}
	if config.Logging.MaxAge == 0 {
		config.Logging.MaxAge = 7
	}
	config.Logging.EnableCaller = true
	
	return nil
}

// loadEnhancedConfigFromEnv 从环境变量加载配置
func loadEnhancedConfigFromEnv(config *EnhancedConfig) error {
	// Server
	if port := os.Getenv("SERVER_PORT"); port != "" {
		config.Server.Port = port
	}
	if host := os.Getenv("SERVER_HOST"); host != "" {
		config.Server.Host = host
	}
	
	// Mail
	if domain := os.Getenv("MAIL_DOMAIN"); domain != "" {
		config.Mail.Domain = domain
	}
	if smtpPort := os.Getenv("SMTP_PORT"); smtpPort != "" {
		config.Mail.SMTPPort = smtpPort
	}
	if imapPort := os.Getenv("IMAP_PORT"); imapPort != "" {
		config.Mail.IMAPPort = imapPort
	}
	if enableTLS := os.Getenv("MAIL_ENABLE_TLS"); enableTLS != "" {
		if tls, err := strconv.ParseBool(enableTLS); err == nil {
			config.Mail.EnableTLS = tls
		}
	}
	
	// Database
	if dbType := os.Getenv("DB_TYPE"); dbType != "" {
		config.Database.Type = dbType
	}
	if dbHost := os.Getenv("DB_HOST"); dbHost != "" {
		config.Database.Host = dbHost
	}
	if dbPort := os.Getenv("DB_PORT"); dbPort != "" {
		if port, err := strconv.Atoi(dbPort); err == nil {
			config.Database.Port = port
		}
	}
	
	// Security
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		config.Security.JWTSecret = jwtSecret
	}
	if csrfSecret := os.Getenv("CSRF_SECRET"); csrfSecret != "" {
		config.Security.CSRFSecret = csrfSecret
	}
	
	// Logging
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		config.Logging.Level = logLevel
	}
	if logFormat := os.Getenv("LOG_FORMAT"); logFormat != "" {
		config.Logging.Format = logFormat
	}
	
	return nil
}

// validateEnhancedConfig 验证增强配置
func validateEnhancedConfig(config *EnhancedConfig) error {
	// 验证端口
	ports := []string{config.Server.Port, config.Mail.SMTPPort, config.Mail.SMTPSPort, config.Mail.IMAPPort, config.Mail.IMAPSPort}
	for _, port := range ports {
		if port != "" {
			if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
				return fmt.Errorf("无效端口号: %s", port)
			}
		}
	}
	
	// 验证域名
	if config.Mail.Domain == "" {
		return fmt.Errorf("邮件域名不能为空")
	}
	
	// 验证TLS配置
	if config.Mail.EnableTLS {
		if config.Mail.TLSCertFile == "" || config.Mail.TLSKeyFile == "" {
			return fmt.Errorf("启用TLS时必须提供证书文件路径")
		}
	}
	
	// 验证日志级别
	validLevels := []string{"debug", "info", "warn", "error", "fatal"}
	levelValid := false
	for _, level := range validLevels {
		if config.Logging.Level == level {
			levelValid = true
			break
		}
	}
	if !levelValid {
		return fmt.Errorf("无效的日志级别: %s", config.Logging.Level)
	}
	
	return nil
}

// GetDSN 获取数据库连接字符串
func (c *EnhancedConfig) GetDSN() string {
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
func (c *EnhancedConfig) IsProduction() bool {
	env := os.Getenv("APP_ENV")
	return env == "production" || env == "prod"
}

// IsDevelopment 检查是否为开发环境
func (c *EnhancedConfig) IsDevelopment() bool {
	env := os.Getenv("APP_ENV")
	return env == "development" || env == "dev" || env == ""
}
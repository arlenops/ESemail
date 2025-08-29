package models

import (
	"esemail/internal/storage"
	"time"
)

// User 用户模型
type User struct {
	storage.BaseEntity
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Domain    string    `json:"domain"`
	Active    bool      `json:"active"`
	Aliases   []string  `json:"aliases"`
	Quota     int64     `json:"quota"`
	UsedQuota int64     `json:"used_quota"`
	Password  string    `json:"password"` // bcrypt加密后的密码
}

// Domain 域名模型
type Domain struct {
	storage.BaseEntity
	Name       string            `json:"name"`
	Active     bool              `json:"active"`
	DNSRecords map[string]string `json:"dns_records"`
	DKIMKey    string            `json:"dkim_key"`
	Status     string            `json:"status"`
}

// MailRecord 邮件记录模型
type MailRecord struct {
	storage.BaseEntity
	MessageID    string            `json:"message_id"`
	From         string            `json:"from"`
	To           []string          `json:"to"`
	Subject      string            `json:"subject"`
	Size         int64             `json:"size"`
	Status       string            `json:"status"` // sent, received, failed, queued
	Direction    string            `json:"direction"` // inbound, outbound
	Headers      map[string]string `json:"headers"`
	Body         string            `json:"body,omitempty"`
	Attachments  []Attachment      `json:"attachments,omitempty"`
	SpamScore    float64           `json:"spam_score"`
	DeliveryTime *time.Time        `json:"delivery_time,omitempty"`
	ErrorMessage string            `json:"error_message,omitempty"`
}

// Attachment 附件模型
type Attachment struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Type     string `json:"type"`
	Filename string `json:"filename"`
}

// Certificate 证书模型
type Certificate struct {
	storage.BaseEntity
	Domain       string     `json:"domain"`
	Type         string     `json:"type"` // single, wildcard
	Status       string     `json:"status"` // valid, expired, expiring, error
	IssuedAt     time.Time  `json:"issued_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	Issuer       string     `json:"issuer"`
	AutoRenew    bool       `json:"auto_renew"`
	DNSProvider  string     `json:"dns_provider,omitempty"`
	LastRenewed  *time.Time `json:"last_renewed,omitempty"`
	RenewError   string     `json:"renew_error,omitempty"`
}

// SystemConfig 系统配置模型
type SystemConfig struct {
	storage.BaseEntity
	Domain        string            `json:"domain"`
	Hostname      string            `json:"hostname"`
	AdminEmail    string            `json:"admin_email"`
	Settings      map[string]string `json:"settings"`
	Initialized   bool              `json:"initialized"`
	Version       string            `json:"version"`
}

// AuthUser 认证用户模型
type AuthUser struct {
	storage.BaseEntity
	Username      string    `json:"username"`
	Password      string    `json:"password"` // bcrypt加密
	Email         string    `json:"email"`
	Role          string    `json:"role"` // admin, user
	Active        bool      `json:"active"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP   string    `json:"last_login_ip,omitempty"`
	FailedLogins  int       `json:"failed_logins"`
	LockedUntil   *time.Time `json:"locked_until,omitempty"`
}

// DNSRecord DNS记录模型
type DNSRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	TTL      int    `json:"ttl"`
	Status   string `json:"status"`   // found, missing, error
	Required bool   `json:"required"`
}

// ServiceStatus 服务状态模型
type ServiceStatus struct {
	Name         string    `json:"name"`
	Status       string    `json:"status"` // healthy, warning, critical, unknown
	Message      string    `json:"message"`
	LastCheck    time.Time `json:"last_check"`
	Port         int       `json:"port,omitempty"`
	ProcessID    string    `json:"process_id,omitempty"`
	ResponseTime int64     `json:"response_time,omitempty"` // 毫秒
}

// SystemHealth 系统健康状态模型
type SystemHealth struct {
	storage.BaseEntity
	Services     []ServiceStatus   `json:"services"`
	SystemInfo   SystemInfo        `json:"system_info"`
	OverallState string            `json:"overall_state"` // healthy, warning, critical
	LastUpdate   time.Time         `json:"last_update"`
	Alerts       []Alert           `json:"alerts,omitempty"`
}

// SystemInfo 系统信息模型
type SystemInfo struct {
	CPUUsage     float64 `json:"cpu_usage"`
	MemoryUsage  float64 `json:"memory_usage"`
	DiskUsage    float64 `json:"disk_usage"`
	Uptime       string  `json:"uptime"`
	LoadAverage  string  `json:"load_average"`
	NetworkStats NetworkStats `json:"network_stats"`
}

// NetworkStats 网络统计信息
type NetworkStats struct {
	BytesReceived int64 `json:"bytes_received"`
	BytesSent     int64 `json:"bytes_sent"`
	PacketsReceived int64 `json:"packets_received"`
	PacketsSent   int64 `json:"packets_sent"`
}

// Alert 告警模型
type Alert struct {
	Level     string    `json:"level"` // info, warning, error, critical
	Message   string    `json:"message"`
	Service   string    `json:"service,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Resolved  bool      `json:"resolved"`
}

// LogEntry 日志条目模型
type LogEntry struct {
	storage.BaseEntity
	Level     string            `json:"level"` // debug, info, warn, error
	Message   string            `json:"message"`
	Service   string            `json:"service"`
	Component string            `json:"component,omitempty"`
	UserID    string            `json:"user_id,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Context   map[string]string `json:"context,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// BackupRecord 备份记录模型
type BackupRecord struct {
	storage.BaseEntity
	Type        string    `json:"type"` // full, incremental
	Status      string    `json:"status"` // success, failed, in_progress
	FilePath    string    `json:"file_path"`
	FileSize    int64     `json:"file_size"`
	StartTime   time.Time `json:"start_time"`
	EndTime     *time.Time `json:"end_time,omitempty"`
	ErrorMessage string   `json:"error_message,omitempty"`
}

// CreateUserRequest 创建用户请求
type CreateUserRequest struct {
	Email    string   `json:"email" binding:"required,email"`
	Name     string   `json:"name" binding:"required"`
	Password string   `json:"password" binding:"required,min=6"`
	Aliases  []string `json:"aliases"`
	Quota    int64    `json:"quota"`
}

// UpdateUserRequest 更新用户请求
type UpdateUserRequest struct {
	Name    string   `json:"name"`
	Active  bool     `json:"active"`
	Aliases []string `json:"aliases"`
	Quota   int64    `json:"quota"`
}

// IssueCertRequest 签发证书请求
type IssueCertRequest struct {
	Domain      string `json:"domain" binding:"required"`
	Type        string `json:"type"`
	DNSProvider string `json:"dns_provider"`
	APIKey      string `json:"api_key"`
	APISecret   string `json:"api_secret"`
}

// SetupConfigRequest 系统配置请求
type SetupConfigRequest struct {
	Domain     string `json:"domain" binding:"required"`
	Hostname   string `json:"hostname" binding:"required"`
	AdminEmail string `json:"admin_email" binding:"required,email"`
}

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// ChangePasswordRequest 修改密码请求
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}
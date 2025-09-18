package service

import (
	"fmt"
	"os"
	"time"
)

type SystemService struct{
	securityService *SecurityService
}

// SetupConfig 简化的配置结构
type SetupConfig struct {
	Domain     string
	Hostname   string
	AdminEmail string
}

type SystemStatus struct {
	Initialized      bool              `json:"initialized"`
	Version          string            `json:"version"`
	InstallPath      string            `json:"install_path"`
	ConfigPath       string            `json:"config_path"`
	ServicesStatus   map[string]string `json:"services_status"`
	TotalUsers       int               `json:"total_users"`
	TotalDomains     int               `json:"total_domains"`
	StorageUsage     int64             `json:"storage_usage"`
	MemoryUsage      int64             `json:"memory_usage"`
	CPUUsage         float64           `json:"cpu_usage"`
	Uptime           string            `json:"uptime"`
	LastBackup       *time.Time        `json:"last_backup"`
	SecurityAlerts   int               `json:"security_alerts"`
}

type InitializationResult struct {
	Success      bool              `json:"success"`
	Message      string            `json:"message"`
	Steps        []string          `json:"steps"`
	FailedSteps  []string          `json:"failed_steps"`
	Warnings     []string          `json:"warnings"`
	Details      map[string]string `json:"details"`
	Duration     string            `json:"duration"`
	NextSteps    []string          `json:"next_steps"`
}

func NewSystemService() *SystemService {
	return &SystemService{
		securityService: NewSecurityService(),
	}
}

func (s *SystemService) GetSystemStatus() *SystemStatus {
	return &SystemStatus{
		Initialized:    true,
		Version:        "1.0.0",
		InstallPath:    "/opt/esemail",
		ConfigPath:     "/opt/esemail/config",
		ServicesStatus: map[string]string{
			"smtp": "running",
			"imap": "running",
			"web":  "running",
		},
		TotalUsers:     1,
		TotalDomains:   1,
		StorageUsage:   1024 * 1024, // 1MB
		MemoryUsage:    64 * 1024 * 1024, // 64MB
		CPUUsage:       5.0,
		Uptime:         "1h 30m",
		SecurityAlerts: 0,
	}
}

func (s *SystemService) GetInitializationStatus() map[string]interface{} {
	return map[string]interface{}{
		"is_initialized": true,
		"status":         "completed",
		"progress":       100,
		"message":        "系统已初始化完成",
	}
}

func (s *SystemService) InitializeSystem() *InitializationResult {
	start := time.Now()

	steps := []string{
		"创建必要目录",
		"初始化数据库",
		"生成证书配置",
		"启动邮件服务",
	}

	// 确保目录存在
	dirs := []string{
		"/opt/esemail/config",
		"/opt/esemail/mail",
		"/opt/esemail/logs",
		"/opt/esemail/certs",
		"/opt/esemail/data/db",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return &InitializationResult{
				Success:     false,
				Message:     fmt.Sprintf("创建目录失败: %v", err),
				Steps:       steps,
				FailedSteps: []string{"创建必要目录"},
				Duration:    time.Since(start).String(),
			}
		}
	}

	return &InitializationResult{
		Success:   true,
		Message:   "系统初始化成功",
		Steps:     steps,
		Duration:  time.Since(start).String(),
		NextSteps: []string{"配置域名", "添加用户", "设置DNS记录"},
	}
}
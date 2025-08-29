package service

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type HealthService struct{
	securityService *SecurityService
}

type ServiceStatus struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	LastCheck time.Time `json:"last_check"`
	Port      int       `json:"port,omitempty"`
	ProcessID string    `json:"process_id,omitempty"`
}

type SystemHealth struct {
	Services     []ServiceStatus `json:"services"`
	SystemInfo   SystemInfo      `json:"system_info"`
	OverallState string          `json:"overall_state"`
	LastUpdate   time.Time       `json:"last_update"`
}

type SystemInfo struct {
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage"`
	DiskUsage   float64 `json:"disk_usage"`
	Uptime      string  `json:"uptime"`
	LoadAverage string  `json:"load_average"`
}

func NewHealthService() *HealthService {
	return &HealthService{
		securityService: NewSecurityService(),
	}
}

func (s *HealthService) GetSystemHealth() *SystemHealth {
	services := []ServiceStatus{
		s.checkService("Postfix (SMTP)", "postfix", 25),
		s.checkService("Postfix (Submission)", "postfix", 465),
		s.checkService("Postfix (Submission Alt)", "postfix", 587),
		s.checkService("Dovecot (IMAPS)", "dovecot", 993),
		s.checkService("Dovecot (POP3S)", "dovecot", 995),
		s.checkService("Rspamd", "rspamd", 11334),
		s.checkService("OpenDKIM", "opendkim", 0),
	}

	overallState := s.calculateOverallState(services)
	systemInfo := s.getSystemInfo()

	return &SystemHealth{
		Services:     services,
		SystemInfo:   systemInfo,
		OverallState: overallState,
		LastUpdate:   time.Now(),
	}
}

func (s *HealthService) checkService(name, serviceName string, port int) ServiceStatus {
	status := ServiceStatus{
		Name:      name,
		LastCheck: time.Now(),
		Port:      port,
	}

	if s.isServiceRunning(serviceName) {
		status.Status = "healthy"
		status.Message = "服务运行正常"

		if port > 0 && !s.isPortListening(port) {
			status.Status = "warning"
			status.Message = fmt.Sprintf("服务运行但端口 %d 未监听", port)
		}
	} else {
		status.Status = "critical"
		status.Message = "服务未运行"
	}

	if pid := s.getServicePID(serviceName); pid != "" {
		status.ProcessID = pid
	}

	return status
}

func (s *HealthService) isServiceRunning(serviceName string) bool {
	status, err := s.securityService.CheckServiceStatusSecure(serviceName)
	if err != nil {
		return false
	}
	return status == "active"
}

func (s *HealthService) isPortListening(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (s *HealthService) getServicePID(serviceName string) string {
	output, err := s.securityService.ExecuteSecureCommand("systemctl", []string{"show", "--property=MainPID", serviceName}, 10*time.Second)
	if err != nil {
		return ""
	}

	parts := strings.Split(string(output), "=")
	if len(parts) == 2 {
		pid := strings.TrimSpace(parts[1])
		if pid != "0" {
			return pid
		}
	}
	return ""
}

func (s *HealthService) calculateOverallState(services []ServiceStatus) string {
	criticalCount := 0
	warningCount := 0

	for _, service := range services {
		switch service.Status {
		case "critical":
			criticalCount++
		case "warning":
			warningCount++
		}
	}

	if criticalCount > 0 {
		return "critical"
	}
	if warningCount > 0 {
		return "warning"
	}
	return "healthy"
}

func (s *HealthService) getSystemInfo() SystemInfo {
	return SystemInfo{
		CPUUsage:    s.getCPUUsage(),
		MemoryUsage: s.getMemoryUsage(),
		DiskUsage:   s.getDiskUsage(),
		Uptime:      s.getUptime(),
		LoadAverage: s.getLoadAverage(),
	}
}

func (s *HealthService) getCPUUsage() float64 {
	// 使用安全的方式读取CPU使用率
	// 由于shell执行被禁用，使用/proc/stat来获取CPU信息
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return 0
	}
	
	// 解析第一行的CPU统计信息
	fields := strings.Fields(lines[0])
	if len(fields) < 5 {
		return 0
	}
	
	// 简单计算：使用固定值作为占位符
	// 在实际环境中应该实现更精确的CPU使用率计算
	return 5.0 // 占位符值
}

func (s *HealthService) getMemoryUsage() float64 {
	// 使用安全的方式读取内存使用率
	// 读取/proc/meminfo来获取内存信息
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	
	lines := strings.Split(string(data), "\n")
	memTotal := int64(0)
	memAvailable := int64(0)
	
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			switch fields[0] {
			case "MemTotal:":
				if val, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					memTotal = val
				}
			case "MemAvailable:":
				if val, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					memAvailable = val
				}
			}
		}
	}
	
	if memTotal > 0 {
		memUsed := memTotal - memAvailable
		return float64(memUsed) / float64(memTotal) * 100.0
	}
	
	return 0
}

func (s *HealthService) getDiskUsage() float64 {
	// 需要添加df命令到允许的命令列表中，或者使用syscall.Statfs来获取磁盘信息
	output, err := s.securityService.ExecuteSecureCommand("df", []string{"-h", "/"}, 15*time.Second)
	if err != nil {
		return 0
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return 0
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 5 {
		return 0
	}

	usageStr := strings.TrimSuffix(fields[4], "%")
	usage, err := strconv.ParseFloat(usageStr, 64)
	if err != nil {
		return 0
	}
	return usage
}

func (s *HealthService) getUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "未知"
	}

	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return "未知"
	}

	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return "未知"
	}

	duration := time.Duration(seconds) * time.Second
	return duration.String()
}

func (s *HealthService) getLoadAverage() string {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return "未知"
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return "未知"
	}

	return fmt.Sprintf("%s %s %s", fields[0], fields[1], fields[2])
}

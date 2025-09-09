package service

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type SecurityService struct {
	allowedCommands map[string]bool
	domainRegex     *regexp.Regexp
	emailRegex      *regexp.Regexp
	hostnameRegex   *regexp.Regexp
}

func NewSecurityService() *SecurityService {
	allowedCommands := map[string]bool{
		"systemctl":      true,
		"opendkim-genkey": true,
		"apt":            true,
		"dpkg":           true,
		"postmap":        true,
		"postfix":        true,
		"dovecot":        true,
		"chown":          true,
		"chmod":          true,
		"openssl":        true,  // 允许openssl用于证书解析
		"df":             true,  // 允许df用于磁盘使用率查询
		"dig":            true,  // 允许dig用于DNS查询
		"curl":           false, // 禁用curl，安全风险太高
		"sh":             false, // 禁用shell执行
		"bash":           false, // 禁用bash执行
		"wget":           false, // 禁用wget，安全风险太高
		"acme.sh":        false, // 禁用acme.sh直接执行
	}

	// 严格的域名验证正则
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	
	// 邮箱验证正则
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	
	// 主机名验证正则
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

	return &SecurityService{
		allowedCommands: allowedCommands,
		domainRegex:     domainRegex,
		emailRegex:      emailRegex,
		hostnameRegex:   hostnameRegex,
	}
}

// ValidateDomain 验证域名格式
func (s *SecurityService) ValidateDomain(domain string) error {
	if len(domain) == 0 || len(domain) > 253 {
		return errors.New("域名长度不符合要求")
	}
	
	if !s.domainRegex.MatchString(domain) {
		return errors.New("域名格式不正确")
	}
	
	// 检查是否包含危险字符
	if strings.ContainsAny(domain, ";|&$`\"'\\<>(){}[]") {
		return errors.New("域名包含非法字符")
	}
	
	return nil
}

// ValidateEmail 验证邮箱格式
func (s *SecurityService) ValidateEmail(email string) error {
	if len(email) == 0 || len(email) > 254 {
		return errors.New("邮箱长度不符合要求")
	}
	
	if !s.emailRegex.MatchString(email) {
		return errors.New("邮箱格式不正确")
	}
	
	// 检查是否包含危险字符
	if strings.ContainsAny(email, ";|&$`\"'\\<>(){}[]") {
		return errors.New("邮箱包含非法字符")
	}
	
	return nil
}

// ValidateHostname 验证主机名格式
func (s *SecurityService) ValidateHostname(hostname string) error {
	if len(hostname) == 0 || len(hostname) > 253 {
		return errors.New("主机名长度不符合要求")
	}
	
	if !s.hostnameRegex.MatchString(hostname) {
		return errors.New("主机名格式不正确")
	}
	
	return nil
}

// SanitizeString 清理字符串，移除危险字符
func (s *SecurityService) SanitizeString(input string) string {
	// 移除所有shell特殊字符
	dangerous := []string{";", "|", "&", "$", "`", "\"", "'", "\\", "<", ">", "(", ")", "{", "}", "[", "]", "\n", "\r", "\t"}
	
	result := input
	for _, char := range dangerous {
		result = strings.ReplaceAll(result, char, "")
	}
	
	return strings.TrimSpace(result)
}

// ExecuteSecureCommand 安全地执行系统命令
func (s *SecurityService) ExecuteSecureCommand(command string, args []string, timeout time.Duration) ([]byte, error) {
	// 检查命令是否在白名单中
	allowed, exists := s.allowedCommands[command]
	if !exists || !allowed {
		return nil, fmt.Errorf("命令 '%s' 不被允许执行", command)
	}
	
	// 验证参数
	for i, arg := range args {
		if strings.ContainsAny(arg, ";|&$`\"'\\<>{}[]") {
			return nil, fmt.Errorf("参数 %d 包含危险字符: %s", i, arg)
		}
	}
	
	// 如果没有指定超时时间，使用默认值
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	
	// 创建命令
	cmd := exec.Command(command, args...)
	
	// 设置安全的环境变量（清空环境变量，只保留必需的）
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
		"SHELL=/bin/bash",
		"USER=root",
	}
	
	// 设置进程组ID，便于清理子进程
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	
	// 创建超时上下文
	done := make(chan error, 1)
	var output []byte
	var err error
	
	go func() {
		output, err = cmd.CombinedOutput()
		done <- err
	}()
	
	select {
	case err := <-done:
		return output, err
	case <-time.After(timeout):
		// 超时，杀死进程组
		if cmd.Process != nil {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil, fmt.Errorf("命令执行超时 (%v)", timeout)
	}
}

// ValidateFilePath 验证文件路径安全性
func (s *SecurityService) ValidateFilePath(path string) error {
	// 检查路径遍历攻击
	if strings.Contains(path, "..") {
		return errors.New("路径包含危险的上级目录引用")
	}
	
	// 检查相对路径的合法性 
	if strings.HasPrefix(path, "./") || strings.HasPrefix(path, "/") {
		allowedPrefixes := []string{
			"./data/", "./config/", "./mail/", "./logs/", "./certs/", "./acme/",
			"/var/lib/esemail/", "/etc/esemail/", "/etc/postfix/", "/etc/dovecot/", 
			"/etc/opendkim/", "/etc/ssl/mail/", "/etc/rspamd/", "/var/spool/postfix/",
		}
		
		allowed := false
		for _, prefix := range allowedPrefixes {
			if strings.HasPrefix(path, prefix) {
				allowed = true
				break
			}
		}
		
		if !allowed {
			return errors.New("路径不在允许的目录范围内")
		}
	}
	
	// 检查危险字符
	if strings.ContainsAny(path, ";|&$`\"'<>{}[]") {
		return errors.New("路径包含危险字符")
	}
	
	return nil
}

// GenerateDKIMKeySecure 安全地生成DKIM密钥
func (s *SecurityService) GenerateDKIMKeySecure(domain string) error {
	// 验证域名
	if err := s.ValidateDomain(domain); err != nil {
		return fmt.Errorf("域名验证失败: %v", err)
	}
	
	// 安全地执行opendkim-genkey命令
	args := []string{
		"-s", "default",
		"-d", domain,
		"-D", "./config/opendkim/keys/default",
	}
	
	output, err := s.ExecuteSecureCommand("opendkim-genkey", args, 60*time.Second)
	if err != nil {
		return fmt.Errorf("DKIM密钥生成失败: %v, 输出: %s", err, string(output))
	}
	
	return nil
}

// RestartServiceSecure 安全地重启服务
func (s *SecurityService) RestartServiceSecure(serviceName string) error {
	// 白名单验证服务名
	allowedServices := map[string]bool{
		"postfix":  true,
		"dovecot":  true,
		"rspamd":   true,
		"opendkim": true,
	}
	
	if !allowedServices[serviceName] {
		log.Printf("ERROR: 服务 '%s' 不被允许重启", serviceName)
		return fmt.Errorf("服务 '%s' 不被允许重启", serviceName)
	}
	
	// 使用安全的systemctl命令重启服务
	log.Printf("DEBUG: RestartServiceSecure被调用，服务名: %s", serviceName)
	if _, err := s.ExecuteSecureCommand("systemctl", []string{"restart", serviceName}, 30*time.Second); err != nil {
		log.Printf("ERROR: 重启服务 %s 失败: %v", serviceName, err)
		return fmt.Errorf("重启服务 %s 失败: %v", serviceName, err)
	}
	log.Printf("INFO: 成功重启服务 %s", serviceName)
	return nil
}

// ReloadServiceSecure 安全地重载服务配置
func (s *SecurityService) ReloadServiceSecure(serviceName string) error {
	// 白名单验证服务名
	allowedServices := map[string]bool{
		"postfix":  true,
		"dovecot":  true,
		"rspamd":   true,
		"opendkim": true,
	}
	
	if !allowedServices[serviceName] {
		return fmt.Errorf("服务 '%s' 不被允许重载", serviceName)
	}
	
	// 使用安全的systemctl命令重载服务
	if _, err := s.ExecuteSecureCommand("systemctl", []string{"reload", serviceName}, 30*time.Second); err != nil {
		log.Printf("ERROR: 重载服务 %s 失败: %v", serviceName, err)
		return fmt.Errorf("重载服务 %s 失败: %v", serviceName, err)
	}
	log.Printf("INFO: 成功重载服务 %s", serviceName)
	return nil
}

// CheckServiceStatusSecure 安全地检查服务状态
func (s *SecurityService) CheckServiceStatusSecure(serviceName string) (string, error) {
	// 白名单验证服务名
	allowedServices := map[string]bool{
		"postfix":  true,
		"dovecot":  true,
		"rspamd":   true,
		"opendkim": true,
	}
	
	if !allowedServices[serviceName] {
		return "", fmt.Errorf("服务 '%s' 不被允许查询状态", serviceName)
	}
	
	// 使用安全的systemctl命令检查服务状态
	output, err := s.ExecuteSecureCommand("systemctl", []string{"is-active", serviceName}, 10*time.Second)
	if err != nil {
		log.Printf("WARNING: 检查服务 %s 状态失败: %v", serviceName, err)
		return "inactive", nil
	}
	status := strings.TrimSpace(string(output))
	log.Printf("INFO: 服务 %s 状态: %s", serviceName, status)
	return status, nil
}
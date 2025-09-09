package service

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type EnvironmentService struct{}

type ServiceDependency struct {
	Name         string `json:"name"`
	Command      string `json:"command"`
	Package      string `json:"package"`
	Status       string `json:"status"` // installed, missing, error
	Version      string `json:"version"`
	Description  string `json:"description"`
	InstallCmd   string `json:"install_cmd"`
	ConfigPath   string `json:"config_path"`
	Required     bool   `json:"required"`
	CheckCommand string `json:"check_command"`
}

type EnvironmentStatus struct {
	Ready        bool                 `json:"ready"`
	Dependencies []ServiceDependency  `json:"dependencies"`
	SystemInfo   SystemRequirements   `json:"system_info"`
	LastCheck    time.Time           `json:"last_check"`
	Summary      EnvironmentSummary   `json:"summary"`
}

type SystemRequirements struct {
	OS            string `json:"os"`
	Architecture  string `json:"architecture"`
	Kernel        string `json:"kernel"`
	HasRoot       bool   `json:"has_root"`
	PortsOpen     []int  `json:"ports_open"`
	DiskSpace     string `json:"disk_space"`
	Memory        string `json:"memory"`
}

type EnvironmentSummary struct {
	TotalServices    int `json:"total_services"`
	InstalledServices int `json:"installed_services"`
	MissingServices  int `json:"missing_services"`
	RequiredMissing  int `json:"required_missing"`
}

func NewEnvironmentService() *EnvironmentService {
	return &EnvironmentService{}
}

func (s *EnvironmentService) CheckEnvironment() *EnvironmentStatus {
	log.Printf("开始检查邮局环境依赖")
	
	dependencies := s.getServiceDependencies()
	systemInfo := s.getSystemRequirements()
	
	// 检查每个依赖项
	for i := range dependencies {
		s.checkDependency(&dependencies[i])
	}
	
	// 生成摘要
	summary := s.generateSummary(dependencies)
	ready := summary.RequiredMissing == 0
	
	status := &EnvironmentStatus{
		Ready:        ready,
		Dependencies: dependencies,
		SystemInfo:   systemInfo,
		LastCheck:    time.Now(),
		Summary:      summary,
	}
	
	log.Printf("环境检查完成：%d/%d 服务已安装，系统%s", summary.InstalledServices, summary.TotalServices, 
		map[bool]string{true: "就绪", false: "未就绪"}[ready])
	
	return status
}

func (s *EnvironmentService) getServiceDependencies() []ServiceDependency {
	return []ServiceDependency{
		{
			Name:         "Postfix",
			Command:      "postfix",
			Package:      "postfix",
			Description:  "邮件传输代理(MTA)，负责邮件的发送和接收",
			InstallCmd:   "apt-get install -y postfix",
			ConfigPath:   "/etc/postfix/main.cf",
			Required:     true,
			CheckCommand: "postconf mail_version",
		},
		{
			Name:         "Dovecot",
			Command:      "dovecot",
			Package:      "dovecot-core dovecot-imapd dovecot-pop3d",
			Description:  "IMAP/POP3服务器，提供邮件接收服务",
			InstallCmd:   "apt-get install -y dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd",
			ConfigPath:   "/etc/dovecot/dovecot.conf",
			Required:     true,
			CheckCommand: "dovecot --version",
		},
		{
			Name:         "Rspamd",
			Command:      "rspamd",
			Package:      "rspamd",
			Description:  "高性能反垃圾邮件过滤器",
			InstallCmd:   "apt-get install -y rspamd",
			ConfigPath:   "/etc/rspamd/rspamd.conf",
			Required:     true,
			CheckCommand: "rspamd --version",
		},
		{
			Name:         "OpenDKIM",
			Command:      "opendkim",
			Package:      "opendkim opendkim-tools",
			Description:  "DKIM邮件签名服务，提供邮件认证",
			InstallCmd:   "apt-get install -y opendkim opendkim-tools",
			ConfigPath:   "/etc/opendkim.conf",
			Required:     true,
			CheckCommand: "opendkim -V",
		},
		{
			Name:         "acme.sh",
			Command:      "acme.sh",
			Package:      "acme.sh",
			Description:  "Let's Encrypt证书自动化工具",
			InstallCmd:   "curl https://get.acme.sh | sh",
			ConfigPath:   "~/.acme.sh/acme.sh.env",
			Required:     false,
			CheckCommand: "acme.sh --version",
		},
		{
			Name:         "dig",
			Command:      "dig",
			Package:      "dnsutils",
			Description:  "DNS查询工具，用于DNS记录检测",
			InstallCmd:   "apt-get install -y dnsutils",
			ConfigPath:   "",
			Required:     true,
			CheckCommand: "dig -v",
		},
		{
			Name:         "openssl",
			Command:      "openssl",
			Package:      "openssl",
			Description:  "SSL/TLS工具包，用于证书管理",
			InstallCmd:   "apt-get install -y openssl",
			ConfigPath:   "",
			Required:     true,
			CheckCommand: "openssl version",
		},
	}
}

func (s *EnvironmentService) checkDependency(dep *ServiceDependency) {
	// 检查命令是否存在
	if _, err := exec.LookPath(dep.Command); err != nil {
		dep.Status = "missing"
		dep.Version = "未安装"
		return
	}
	
	// 尝试获取版本信息
	if dep.CheckCommand != "" {
		if version := s.getVersion(dep.CheckCommand); version != "" {
			dep.Status = "installed"
			dep.Version = version
		} else {
			dep.Status = "error"
			dep.Version = "版本获取失败"
		}
	} else {
		dep.Status = "installed"
		dep.Version = "已安装"
	}
}

func (s *EnvironmentService) getVersion(command string) string {
	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	
	version := strings.TrimSpace(string(output))
	// 清理版本字符串
	if len(version) > 100 {
		version = version[:100] + "..."
	}
	
	return version
}

func (s *EnvironmentService) getSystemRequirements() SystemRequirements {
	requirements := SystemRequirements{
		PortsOpen: []int{},
	}
	
	// 获取操作系统信息
	if output, err := exec.Command("uname", "-s").Output(); err == nil {
		requirements.OS = strings.TrimSpace(string(output))
	}
	
	// 获取架构信息
	if output, err := exec.Command("uname", "-m").Output(); err == nil {
		requirements.Architecture = strings.TrimSpace(string(output))
	}
	
	// 获取内核版本
	if output, err := exec.Command("uname", "-r").Output(); err == nil {
		requirements.Kernel = strings.TrimSpace(string(output))
	}
	
	// 检查是否有root权限
	requirements.HasRoot = s.checkRootPermission()
	
	// 检查端口状态
	mailPorts := []int{25, 465, 587, 993, 995, 8686}
	for _, port := range mailPorts {
		if s.isPortOpen(port) {
			requirements.PortsOpen = append(requirements.PortsOpen, port)
		}
	}
	
	// 获取磁盘空间
	if output, err := exec.Command("df", "-h", ".").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) > 1 {
			fields := strings.Fields(lines[1])
			if len(fields) > 3 {
				requirements.DiskSpace = fields[3] + " 可用"
			}
		}
	}
	
	// 获取内存信息
	if output, err := exec.Command("free", "-h").Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) > 1 {
			fields := strings.Fields(lines[1])
			if len(fields) > 1 {
				requirements.Memory = fields[1] + " 总内存"
			}
		}
	}
	
	return requirements
}

func (s *EnvironmentService) checkRootPermission() bool {
	cmd := exec.Command("id", "-u")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	uid := strings.TrimSpace(string(output))
	return uid == "0"
}

func (s *EnvironmentService) isPortOpen(port int) bool {
	cmd := exec.Command("netstat", "-tuln")
	output, err := cmd.Output()
	if err != nil {
		// 如果netstat不可用，尝试ss命令
		cmd = exec.Command("ss", "-tuln")
		output, err = cmd.Output()
		if err != nil {
			return false
		}
	}
	
	portStr := ":" + strconv.Itoa(port)
	return strings.Contains(string(output), portStr)
}

func (s *EnvironmentService) generateSummary(dependencies []ServiceDependency) EnvironmentSummary {
	summary := EnvironmentSummary{
		TotalServices: len(dependencies),
	}
	
	for _, dep := range dependencies {
		if dep.Status == "installed" {
			summary.InstalledServices++
		} else {
			summary.MissingServices++
			if dep.Required {
				summary.RequiredMissing++
			}
		}
	}
	
	return summary
}

func (s *EnvironmentService) InstallDependency(packageName string) error {
	log.Printf("开始安装依赖包: %s", packageName)
	
	// 更新包索引
	if err := s.runCommand("apt-get", "update"); err != nil {
		return fmt.Errorf("更新包索引失败: %v", err)
	}
	
	// 安装包
	if err := s.runCommand("apt-get", "install", "-y", packageName); err != nil {
		return fmt.Errorf("安装包失败: %v", err)
	}
	
	log.Printf("依赖包安装成功: %s", packageName)
	return nil
}

func (s *EnvironmentService) runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("命令执行失败 %s %v: %s", name, args, string(output))
		return err
	}
	return nil
}

func (s *EnvironmentService) GetInstallScript() string {
	return `#!/bin/bash
# ESemail 环境依赖安装脚本
set -e

echo "🚀 开始安装ESemail环境依赖..."

# 更新包索引
echo "📦 更新系统包索引..."
apt-get update

# 安装基础依赖
echo "⚙️  安装基础系统依赖..."
apt-get install -y curl wget gnupg2 software-properties-common apt-transport-https ca-certificates

# 安装Postfix
echo "📮 安装Postfix..."
DEBIAN_FRONTEND=noninteractive apt-get install -y postfix postfix-pcre

# 安装Dovecot
echo "📥 安装Dovecot..."
apt-get install -y dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-managesieved

# 安装Rspamd
echo "🛡️  安装Rspamd..."
apt-get install -y rspamd redis-server

# 安装OpenDKIM
echo "🔑 安装OpenDKIM..."
apt-get install -y opendkim opendkim-tools

# 安装其他工具
echo "🔧 安装辅助工具..."
apt-get install -y dnsutils openssl net-tools

# 安装acme.sh (可选)
echo "📜 安装acme.sh证书工具..."
curl https://get.acme.sh | sh -s email=admin@localhost || echo "acme.sh安装失败，可稍后手动安装"

# 启用服务但不启动（由ESemail管理）
echo "⚡ 配置系统服务..."
systemctl enable postfix dovecot rspamd opendkim redis-server
systemctl stop postfix dovecot rspamd opendkim redis-server || true

echo "✅ ESemail环境依赖安装完成！"
echo "💡 提示：服务已配置但未启动，请通过ESemail管理界面进行配置和启动。"
`
}
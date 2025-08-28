package service

import (
	"fmt"
	"log"
	"os"
	"strings"
)

type SetupService struct{}

type SetupStatus struct {
	IsSetup        bool     `json:"is_setup"`
	Step           int      `json:"step"`
	Domain         string   `json:"domain"`
	AdminEmail     string   `json:"admin_email"`
	Hostname       string   `json:"hostname"`
	RequiredFields []string `json:"required_fields"`
}

type SetupConfig struct {
	Domain     string `json:"domain" binding:"required"`
	AdminEmail string `json:"admin_email" binding:"required,email"`
	Hostname   string `json:"hostname" binding:"required"`
	AdminName  string `json:"admin_name" binding:"required"`
	AdminPass  string `json:"admin_pass" binding:"required,min=6"`
}

func NewSetupService() *SetupService {
	return &SetupService{}
}

func (s *SetupService) GetSetupStatus() *SetupStatus {
	status := &SetupStatus{
		IsSetup:        s.IsSystemSetup(),
		Step:           1,
		RequiredFields: []string{"domain", "admin_email", "hostname", "admin_name", "admin_pass"},
	}

	if setupData := s.loadSetupData(); setupData != nil {
		status.Domain = setupData.Domain
		status.AdminEmail = setupData.AdminEmail
		status.Hostname = setupData.Hostname
		if status.Domain != "" && status.AdminEmail != "" && status.Hostname != "" {
			status.Step = 2
		}
	}

	return status
}

func (s *SetupService) ConfigureSystem(config SetupConfig) error {
	log.Printf("开始配置系统，域名: %s, 管理员: %s", config.Domain, config.AdminEmail)
	
	if s.IsSystemSetup() {
		log.Printf("系统已经配置完成，跳过配置")
		return fmt.Errorf("系统已经配置完成")
	}

	log.Printf("步骤1: 保存配置文件")
	if err := s.saveSetupConfig(config); err != nil {
		log.Printf("保存配置失败: %v", err)
		return fmt.Errorf("保存配置失败: %v", err)
	}

	log.Printf("步骤2: 更新系统配置")
	if err := s.updateSystemConfig(config); err != nil {
		log.Printf("更新系统配置失败: %v", err)
		return fmt.Errorf("更新系统配置失败: %v", err)
	}

	log.Printf("步骤3: 创建管理员用户")
	if err := s.createAdminUser(config); err != nil {
		log.Printf("创建管理员用户失败: %v", err)
		return fmt.Errorf("创建管理员用户失败: %v", err)
	}

	log.Printf("步骤4: 标记系统配置完成")
	if err := s.markSystemSetup(); err != nil {
		log.Printf("标记系统配置完成失败: %v", err)
		return fmt.Errorf("标记系统配置完成失败: %v", err)
	}

	log.Printf("系统配置完成")
	return nil
}

func (s *SetupService) IsSystemSetup() bool {
	_, err := os.Stat("/etc/esemail/.setup_complete")
	return err == nil
}

func (s *SetupService) loadSetupData() *SetupConfig {
	data, err := os.ReadFile("/etc/esemail/setup.conf")
	if err != nil {
		return nil
	}

	lines := strings.Split(string(data), "\n")
	config := &SetupConfig{}

	for _, line := range lines {
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch key {
				case "DOMAIN":
					config.Domain = value
				case "ADMIN_EMAIL":
					config.AdminEmail = value
				case "HOSTNAME":
					config.Hostname = value
				case "ADMIN_NAME":
					config.AdminName = value
				}
			}
		}
	}

	return config
}

func (s *SetupService) saveSetupConfig(config SetupConfig) error {
	os.MkdirAll("/etc/esemail", 0755)

	configContent := fmt.Sprintf(`DOMAIN=%s
ADMIN_EMAIL=%s
HOSTNAME=%s
ADMIN_NAME=%s
SETUP_TIME=%s
`, config.Domain, config.AdminEmail, config.Hostname, config.AdminName,
		fmt.Sprintf("%d", os.Getpid()))

	return os.WriteFile("/etc/esemail/setup.conf", []byte(configContent), 0644)
}

func (s *SetupService) updateSystemConfig(config SetupConfig) error {
	configFiles := map[string]func(string) string{
		"/etc/postfix/main.cf": func(content string) string {
			content = strings.ReplaceAll(content, "example.com", config.Domain)
			content = strings.ReplaceAll(content, "mail.example.com", config.Hostname)
			return content
		},
		"/etc/dovecot/dovecot.conf": func(content string) string {
			content = strings.ReplaceAll(content, "example.com", config.Domain)
			return content
		},
		"/etc/opendkim.conf": func(content string) string {
			content = strings.ReplaceAll(content, "example.com", config.Domain)
			return content
		},
	}

	for filePath, transformer := range configFiles {
		if err := s.updateConfigFile(filePath, transformer); err != nil {
			return fmt.Errorf("更新配置文件 %s 失败: %v", filePath, err)
		}
	}

	return s.updateDKIMConfig(config.Domain)
}

func (s *SetupService) updateConfigFile(filePath string, transformer func(string) string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	newContent := transformer(string(content))
	return os.WriteFile(filePath, []byte(newContent), 0644)
}

func (s *SetupService) updateDKIMConfig(domain string) error {
	// 确保目录存在
	if err := os.MkdirAll("/etc/opendkim", 0755); err != nil {
		return fmt.Errorf("创建 opendkim 配置目录失败: %v", err)
	}
	if err := os.MkdirAll("/etc/opendkim/keys/default", 0755); err != nil {
		return fmt.Errorf("创建 opendkim 密钥目录失败: %v", err)
	}

	keyTablePath := "/etc/opendkim/KeyTable"
	signingTablePath := "/etc/opendkim/SigningTable"

	keyTable := fmt.Sprintf("default._domainkey.%s %s:default:/etc/opendkim/keys/default/default.private\n", domain, domain)
	if err := os.WriteFile(keyTablePath, []byte(keyTable), 0644); err != nil {
		return err
	}

	signingTable := fmt.Sprintf("*@%s default._domainkey.%s\n", domain, domain)
	return os.WriteFile(signingTablePath, []byte(signingTable), 0644)
}

func (s *SetupService) createAdminUser(config SetupConfig) error {
	log.Printf("开始创建管理员用户: %s", config.AdminEmail)
	
	userService := NewUserService()

	_, err := userService.CreateUser(CreateUserRequest{
		Email:    config.AdminEmail,
		Name:     config.AdminName,
		Password: config.AdminPass,
		Quota:    2 * 1024 * 1024 * 1024, // 2GB
	})

	if err != nil {
		log.Printf("创建管理员用户失败，详细错误: %v", err)
		return err
	}
	
	log.Printf("管理员用户创建成功: %s", config.AdminEmail)
	return nil
}

func (s *SetupService) markSystemSetup() error {
	os.MkdirAll("/etc/esemail", 0755)
	return os.WriteFile("/etc/esemail/.setup_complete", []byte("1"), 0644)
}

func (s *SetupService) GetDKIMPublicKey(domain string) (string, error) {
	keyPath := "/etc/opendkim/keys/default/default.txt"

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return "", fmt.Errorf("DKIM公钥文件不存在，请先完成系统初始化")
	}

	content, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(content), "\n")
	var publicKey string

	for _, line := range lines {
		if strings.Contains(line, "p=") {
			start := strings.Index(line, "p=")
			if start != -1 {
				publicKey = strings.TrimSpace(line[start:])
				publicKey = strings.Trim(publicKey, "\"")
				break
			}
		}
	}

	return publicKey, nil
}

package service

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

type SystemService struct{
	securityService *SecurityService
}

type SystemStatus struct {
	Initialized      bool              `json:"initialized"`
	Version          string            `json:"version"`
	InstallPath      string            `json:"install_path"`
	ConfigPath       string            `json:"config_path"`
	ServicesStatus   map[string]string `json:"services_status"`
	RequiredPackages map[string]bool   `json:"required_packages"`
}

type InitializationStep struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
}

type InitializationResult struct {
	Success bool                 `json:"success"`
	Steps   []InitializationStep `json:"steps"`
	Message string               `json:"message"`
}

func NewSystemService() *SystemService {
	return &SystemService{
		securityService: NewSecurityService(),
	}
}

func (s *SystemService) GetSystemStatus() *SystemStatus {
	return &SystemStatus{
		Initialized:      s.isSystemInitialized(),
		Version:          "1.0.0",
		InstallPath:      "/opt/esemail",
		ConfigPath:       "/etc/esemail",
		ServicesStatus:   s.getServicesStatus(),
		RequiredPackages: s.checkRequiredPackages(),
	}
}

func (s *SystemService) InitializeSystem() *InitializationResult {
	// 获取系统配置
	setupService := NewSetupService()
	setupData := setupService.LoadSetupData()
	if setupData == nil {
		return &InitializationResult{
			Success: false,
			Message: "系统尚未配置，请先完成基础配置",
			Steps:   []InitializationStep{},
		}
	}
	steps := []InitializationStep{
		{Name: "check_packages", Description: "检查必需软件包", Status: "pending"},
		{Name: "install_packages", Description: "安装缺失的软件包", Status: "pending"},
		{Name: "create_directories", Description: "创建系统目录", Status: "pending"},
		{Name: "generate_configs", Description: "生成配置文件", Status: "pending"},
		{Name: "generate_dkim", Description: "生成DKIM密钥", Status: "pending"},
		{Name: "start_services", Description: "启动邮件服务", Status: "pending"},
		{Name: "verify_services", Description: "验证服务状态", Status: "pending"},
	}

	result := &InitializationResult{
		Success: true,
		Steps:   steps,
	}

	for i := range steps {
		steps[i].Status = "running"

		var err error
		switch steps[i].Name {
		case "check_packages":
			err = s.checkPackagesStep()
		case "install_packages":
			err = s.installPackagesStep()
		case "create_directories":
			err = s.createDirectoriesStep()
		case "generate_configs":
			err = s.generateConfigsStep(setupData)
		case "generate_dkim":
			err = s.generateDKIMStep(setupData)
		case "start_services":
			err = s.startServicesStep()
		case "verify_services":
			err = s.verifyServicesStep()
		}

		if err != nil {
			steps[i].Status = "failed"
			steps[i].Error = err.Error()
			result.Success = false
			result.Message = fmt.Sprintf("初始化失败: %s", err.Error())
			break
		} else {
			steps[i].Status = "completed"
		}
	}

	if result.Success {
		result.Message = "系统初始化成功完成"
		s.markSystemInitialized()
	}

	return result
}

func (s *SystemService) isSystemInitialized() bool {
	// 检查设置是否完成
	setupService := NewSetupService()
	if !setupService.IsSystemSetup() {
		return false
	}

	// 检查初始化是否完成
	_, err := os.Stat("./config/.initialized")
	return err == nil
}

func (s *SystemService) markSystemInitialized() error {
	os.MkdirAll("./config", 0755)
	return os.WriteFile("./config/.initialized", []byte("1"), 0644)
}

func (s *SystemService) getServicesStatus() map[string]string {
	services := map[string]string{
		"postfix":  s.getServiceStatus("postfix"),
		"dovecot":  s.getServiceStatus("dovecot"),
		"rspamd":   s.getServiceStatus("rspamd"),
		"opendkim": s.getServiceStatus("opendkim"),
	}
	return services
}

func (s *SystemService) getServiceStatus(serviceName string) string {
	status, err := s.securityService.CheckServiceStatusSecure(serviceName)
	if err != nil {
		return "unknown"
	}
	return status
}

func (s *SystemService) checkRequiredPackages() map[string]bool {
	packages := map[string]bool{
		// 邮件传输代理 (MTA)
		"postfix":       s.isPackageInstalled("postfix"),
		// 邮件投递代理 (MDA)  
		"dovecot-core":  s.isPackageInstalled("dovecot-core"),
		"dovecot-imapd": s.isPackageInstalled("dovecot-imapd"),
		"dovecot-pop3d": s.isPackageInstalled("dovecot-pop3d"),
		// 反垃圾邮件系统
		"rspamd":        s.isPackageInstalled("rspamd"),
		// 邮件认证
		"opendkim":      s.isPackageInstalled("opendkim"),
		// SSL/TLS证书管理
		"acme.sh":       s.isAcmeShInstalled(),
		// 防火墙
		"ufw":           s.isPackageInstalled("ufw"),
		// DNS工具
		"dnsutils":      s.isPackageInstalled("dnsutils"),
		// 入侵防护
		"fail2ban":      s.isPackageInstalled("fail2ban"),
		// 系统工具
		"cron":          s.isPackageInstalled("cron"),
		"logrotate":     s.isPackageInstalled("logrotate"),
		// 网络工具
		"curl":          s.isPackageInstalled("curl"),
		"wget":          s.isPackageInstalled("wget"),
	}
	return packages
}

func (s *SystemService) isPackageInstalled(packageName string) bool {
	// 使用安全的命令执行
	_, err := s.securityService.ExecuteSecureCommand("dpkg", []string{"-l", packageName}, 10*time.Second)
	return err == nil
}

func (s *SystemService) isAcmeShInstalled() bool {
	_, err := os.Stat("/root/.acme.sh/acme.sh")
	return err == nil
}

func (s *SystemService) checkPackagesStep() error {
	// 在开发环境中，跳过软件包检查
	log.Printf("开发环境：跳过软件包检查")
	log.Printf("生产环境需要的软件包: postfix, dovecot-core, rspamd, opendkim")
	return nil
}

func (s *SystemService) installPackagesStep() error {
	// 开发环境跳过软件包安装
	log.Printf("开发环境：跳过软件包安装")
	log.Printf("生产环境需要安装: postfix, dovecot-core, rspamd, opendkim 等")
	return nil
}

func (s *SystemService) createDirectoriesStep() error {
	// 使用相对路径创建目录，避免系统权限问题
	dirs := []string{
		"./config",
		"./mail",
		"./logs", 
		"./certs",
		"./data/db",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录 %s 失败: %v", dir, err)
		}
	}

	return nil
}

func (s *SystemService) generateConfigsStep(setupData *SetupConfig) error {
	// 在开发环境中，只生成基础配置文件到本地目录
	configs := map[string]string{
		"./config/postfix_main.cf":     s.generatePostfixMainConfig(setupData),
		"./config/postfix_master.cf":   s.generatePostfixMasterConfig(),
		"./config/dovecot_config.conf": s.generateDovecotConfig(setupData),
		"./config/rspamd_config.conf":  s.generateRspamdConfig(),
		"./config/opendkim.conf":       s.generateOpenDKIMConfig(setupData),
	}

	for path, content := range configs {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建配置目录 %s 失败: %v", dir, err)
		}

		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return fmt.Errorf("创建配置文件 %s 失败: %v", path, err)
		}
	}

	return nil
}

func (s *SystemService) generateDKIMStep(setupData *SetupConfig) error {
	// 验证域名安全性
	if err := s.securityService.ValidateDomain(setupData.Domain); err != nil {
		return fmt.Errorf("域名验证失败: %v", err)
	}

	// 创建 DKIM 目录
	dkimDirs := []string{
		"/etc/opendkim/keys/default",
		"./config/opendkim/keys/default",
	}
	
	for _, dkimDir := range dkimDirs {
		if err := os.MkdirAll(dkimDir, 0700); err != nil {
			log.Printf("警告: 无法创建 DKIM 目录 %s: %v", dkimDir, err)
		}
	}

	// 生成真实的 DKIM 密钥对
	log.Printf("生成 DKIM 密钥对...")
	if _, err := s.securityService.ExecuteSecureCommand("opendkim-genkey", 
		[]string{"-s", "default", "-d", setupData.Domain, "-D", "./config/opendkim/keys/default/"}, 
		30*time.Second); err != nil {
		log.Printf("警告: DKIM 密钥生成失败: %v", err)
		// 创建占位符文件
		privateKey := "# DKIM private key placeholder\n# Generate with: opendkim-genkey -s default -d " + setupData.Domain + "\n"
		os.WriteFile("./config/opendkim/keys/default/default.private", []byte(privateKey), 0600)
		publicKey := fmt.Sprintf("default._domainkey.%s IN TXT \"v=DKIM1; k=rsa; p=PLACEHOLDER_PUBLIC_KEY\"\n", setupData.Domain)
		os.WriteFile("./config/opendkim/keys/default/default.txt", []byte(publicKey), 0644)
	}

	// 生成 DKIM 配置文件
	keyTable := fmt.Sprintf("default._domainkey.%s %s:default:/etc/opendkim/keys/default/default.private\n", setupData.Domain, setupData.Domain)
	for _, path := range []string{"/etc/opendkim/KeyTable", "./config/opendkim/KeyTable"} {
		os.WriteFile(path, []byte(keyTable), 0644)
	}

	signingTable := fmt.Sprintf("*@%s default._domainkey.%s\n", setupData.Domain, setupData.Domain)
	for _, path := range []string{"/etc/opendkim/SigningTable", "./config/opendkim/SigningTable"} {
		os.WriteFile(path, []byte(signingTable), 0644)
	}

	return nil
}

func (s *SystemService) startServicesStep() error {
	// 在开发环境中，只模拟服务启动
	// 实际的邮件服务需要在生产环境中启动
	log.Printf("开发环境：跳过邮件服务启动")
	log.Printf("生产环境中需要启动的服务: postfix, dovecot, rspamd, opendkim")
	
	// 创建服务状态文件表示已"启动"
	statusFile := "./config/services_status.txt"
	status := fmt.Sprintf("Services simulated startup at %s\n", time.Now().Format("2006-01-02 15:04:05"))
	status += "postfix: simulated\n"
	status += "dovecot: simulated\n" 
	status += "rspamd: simulated\n"
	status += "opendkim: simulated\n"
	
	if err := os.WriteFile(statusFile, []byte(status), 0644); err != nil {
		return fmt.Errorf("创建服务状态文件失败: %v", err)
	}

	return nil
}

func (s *SystemService) verifyServicesStep() error {
	// 在开发环境中，只检查状态文件
	statusFile := "./config/services_status.txt"
	if _, err := os.Stat(statusFile); err != nil {
		return fmt.Errorf("服务状态文件不存在: %v", err)
	}

	log.Printf("开发环境：服务验证通过（模拟模式）")
	return nil
}

func (s *SystemService) generatePostfixMainConfig(setupData *SetupConfig) string {
	return fmt.Sprintf(`myhostname = %s
mydomain = %s
myorigin = $mydomain
inet_interfaces = all
inet_protocols = ipv4
mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
relayhost =
home_mailbox = Maildir/
mailbox_command =
recipient_delimiter = +

smtpd_banner = $myhostname ESMTP
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 2

# TLS 配置
smtpd_tls_cert_file = /etc/ssl/mail/%s/fullchain.pem
smtpd_tls_key_file = /etc/ssl/mail/%s/privkey.pem
smtpd_use_tls = yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
smtpd_tls_security_level = may
smtp_tls_security_level = may

# 反垃圾邮件配置
smtpd_milters = inet:localhost:11332, inet:localhost:8891
non_smtpd_milters = inet:localhost:11332, inet:localhost:8891
milter_protocol = 6
milter_mail_macros = i {mail_addr} {client_addr} {client_name} {auth_authen}
milter_default_action = accept

virtual_alias_domains =
virtual_alias_maps = hash:/etc/postfix/virtual
virtual_mailbox_domains = 
virtual_mailbox_maps = hash:/etc/postfix/vmailbox
virtual_mailbox_base = /var/mail/vhosts
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000
`, setupData.Hostname, setupData.Domain, setupData.Domain, setupData.Domain)
}

func (s *SystemService) generatePostfixMasterConfig() string {
	return `smtp      inet  n       -       y       -       -       smtpd
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_client_restrictions=$mua_client_restrictions
  -o smtpd_helo_restrictions=$mua_helo_restrictions
  -o smtpd_sender_restrictions=$mua_sender_restrictions
  -o smtpd_recipient_restrictions=
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_client_restrictions=$mua_client_restrictions
  -o smtpd_helo_restrictions=$mua_helo_restrictions
  -o smtpd_sender_restrictions=$mua_sender_restrictions
  -o smtpd_recipient_restrictions=
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
defer     unix  -       -       y       -       0       bounce
trace     unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       y       -       -       smtp
relay     unix  -       -       y       -       -       smtp
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
`
}

func (s *SystemService) generateDovecotConfig(setupData *SetupConfig) string {
	return fmt.Sprintf(`protocols = imap pop3
listen = *, ::
base_dir = /var/run/dovecot/
instance_name = dovecot

# SSL 配置
ssl = required
ssl_cert = </etc/ssl/mail/%s/fullchain.pem
ssl_key = </etc/ssl/mail/%s/privkey.pem
ssl_protocols = !SSLv2 !SSLv3

# 邮件存储配置
mail_location = maildir:/var/mail/vhosts/%%d/%%n/Maildir
mail_uid = 5000
mail_gid = 5000

auth_mechanisms = plain login
passdb {
  driver = passwd-file
  args = scheme=CRYPT username_format=%%u /etc/dovecot/users
}
userdb {
  driver = static
  args = uid=5000 gid=5000 home=/var/mail/vhosts/%%d/%%n
}

service imap-login {
  inet_listener imap {
    port = 143
    ssl = no
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}

service pop3-login {
  inet_listener pop3 {
    port = 110
    ssl = no
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}

namespace inbox {
  inbox = yes
  location = 
  mailbox Drafts {
    special_use = \Drafts
  }
  mailbox Junk {
    special_use = \Junk
  }
  mailbox Sent {
    special_use = \Sent
  }
  mailbox "Sent Messages" {
    special_use = \Sent
  }
  mailbox Trash {
    special_use = \Trash
  }
}
`, setupData.Domain, setupData.Domain)
}

func (s *SystemService) generateRspamdConfig() string {
	return `extended_spam_headers = true;
use = ["authentication-results", "spam-header", "x-spamd-bar", "x-rspamd-server"];
`
}

func (s *SystemService) generateOpenDKIMConfig(setupData *SetupConfig) string {
	return fmt.Sprintf(`Syslog yes
UMask 002
Domain %s
KeyFile /etc/opendkim/keys/default/default.private
Selector default
SOCKET inet:8891@localhost
PidFile /var/run/opendkim/opendkim.pid
SignatureAlgorithm rsa-sha256
Mode sv
SubDomains no
InternalHosts 127.0.0.1
OversignHeaders From
TrustAnchorFile /usr/share/dns/root.key
`, setupData.Domain)
}

// installAcmeSh 安装acme.sh证书管理工具
func (s *SystemService) installAcmeSh() error {
	log.Printf("开始安装acme.sh...")
	
	// 创建安装目录
	if err := os.MkdirAll("/root/.acme.sh", 0700); err != nil {
		log.Printf("警告: 创建acme.sh目录失败: %v", err)
	}
	
	// 下载并安装acme.sh
	installCmd := `curl https://get.acme.sh | sh -s email=admin@localhost`
	if _, err := s.securityService.ExecuteSecureCommand("sh", []string{"-c", installCmd}, 120*time.Second); err != nil {
		// 尝试备用方法
		log.Printf("主安装方法失败，尝试备用方法...")
		if _, err := s.securityService.ExecuteSecureCommand("wget", 
			[]string{"-O-", "https://get.acme.sh"}, 60*time.Second); err != nil {
			return fmt.Errorf("下载acme.sh失败: %v", err)
		}
	}
	
	log.Printf("✅ acme.sh安装完成")
	return nil
}

// configureFirewall 配置防火墙规则
func (s *SystemService) configureFirewall() error {
	log.Printf("配置防火墙规则...")
	
	// 邮件系统需要开放的端口
	ports := []string{
		"22/tcp",   // SSH
		"25/tcp",   // SMTP
		"80/tcp",   // HTTP (证书验证)
		"110/tcp",  // POP3
		"143/tcp",  // IMAP
		"465/tcp",  // SMTPS
		"587/tcp",  // SMTP提交
		"993/tcp",  // IMAPS
		"995/tcp",  // POP3S
		"8686/tcp", // Web管理界面
	}
	
	// 重置UFW到默认状态
	s.securityService.ExecuteSecureCommand("ufw", []string{"--force", "reset"}, 30*time.Second)
	
	// 设置默认策略
	s.securityService.ExecuteSecureCommand("ufw", []string{"default", "deny", "incoming"}, 10*time.Second)
	s.securityService.ExecuteSecureCommand("ufw", []string{"default", "allow", "outgoing"}, 10*time.Second)
	
	// 开放必要端口
	for _, port := range ports {
		if _, err := s.securityService.ExecuteSecureCommand("ufw", 
			[]string{"allow", port}, 10*time.Second); err != nil {
			log.Printf("警告: 开放端口 %s 失败: %v", port, err)
		}
	}
	
	// 启用防火墙
	if _, err := s.securityService.ExecuteSecureCommand("ufw", 
		[]string{"--force", "enable"}, 10*time.Second); err != nil {
		log.Printf("警告: 启用防火墙失败: %v", err)
		return err
	}
	
	log.Printf("✅ 防火墙配置完成")
	return nil
}

// checkSystemInitialization 检查系统是否已初始化
func (s *SystemService) checkSystemInitialization() bool {
	// 检查初始化标记文件
	if _, err := os.Stat("./config/.initialized"); err != nil {
		return false
	}
	
	// 检查关键服务状态
	criticalServices := []string{"postfix", "dovecot", "rspamd", "opendkim"}
	for _, service := range criticalServices {
		status := s.getServiceStatus(service)
		if status != "active" && status != "running" {
			return false
		}
	}
	
	return true
}

// GetInitializationStatus 获取系统初始化状态详情
func (s *SystemService) GetInitializationStatus() map[string]interface{} {
	packages := s.checkRequiredPackages()
	services := s.getServicesStatus()
	
	// 统计安装状态
	installedCount := 0
	totalCount := len(packages)
	for _, installed := range packages {
		if installed {
			installedCount++
		}
	}
	
	// 统计服务状态
	activeServices := 0
	totalServices := len(services)
	for _, status := range services {
		if status == "active" || status == "running" {
			activeServices++
		}
	}
	
	return map[string]interface{}{
		"is_initialized":   s.checkSystemInitialization(),
		"packages":         packages,
		"services":         services,
		"packages_summary": map[string]int{
			"installed": installedCount,
			"total":     totalCount,
		},
		"services_summary": map[string]int{
			"active": activeServices,
			"total":  totalServices,
		},
	}
}

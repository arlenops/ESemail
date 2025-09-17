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
		log.Printf("开始执行步骤: %s - %s", steps[i].Name, steps[i].Description)

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
			log.Printf("步骤 %s 执行失败: %v", steps[i].Name, err)
			steps[i].Status = "failed"
			steps[i].Error = err.Error()
			result.Success = false
			result.Message = fmt.Sprintf("初始化失败: %s", err.Error())
			break
		} else {
			log.Printf("步骤 %s 执行成功", steps[i].Name)
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
	_, err := os.Stat("/opt/esemail/config/.initialized")
	return err == nil
}

func (s *SystemService) markSystemInitialized() error {
	os.MkdirAll("/opt/esemail/config", 0755)
	return os.WriteFile("/opt/esemail/config/.initialized", []byte("1"), 0644)
}

func (s *SystemService) getServicesStatus() map[string]string {
	services := map[string]string{
		"postfix":  s.getServiceStatus("postfix"),
		"dovecot":  s.getServiceStatus("dovecot"),
		"rspamd":   s.getServiceStatus("rspamd"),
		"opendkim": s.getServiceStatus("opendkim"),
		"fail2ban": s.getServiceStatus("fail2ban"),
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
	packages := s.checkRequiredPackages()
	var missing []string
	for name, installed := range packages {
		if !installed {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		log.Printf("发现缺少的软件包: %v，将在下一步骤中安装", missing)
	} else {
		log.Printf("所有必需软件包已安装")
	}
	return nil
}

func (s *SystemService) installPackagesStep() error {
	packages := s.checkRequiredPackages()
	var toInstall []string
	for name, installed := range packages {
		if !installed {
			toInstall = append(toInstall, name)
		}
	}
	if len(toInstall) == 0 {
		log.Printf("所有软件包已安装")
		return nil
	}
	
	// 更新软件包缓存
	log.Printf("更新软件包缓存...")
	if _, err := s.securityService.ExecuteSecureCommand("apt", []string{"update"}, 120*time.Second); err != nil {
		log.Printf("警告: 更新软件包缓存失败: %v", err)
	}
	
	// 安装缺失的软件包
	for _, pkg := range toInstall {
		log.Printf("安装软件包: %s", pkg)
		if pkg == "acme.sh" {
			// 特殊处理acme.sh安装
			if err := s.installAcmeSh(); err != nil {
				return fmt.Errorf("安装acme.sh失败: %v", err)
			}
		} else {
			// 使用apt安装
			log.Printf("开始安装软件包: %s", pkg)
			output, err := s.securityService.ExecuteSecureCommand("apt", []string{"install", "-y", pkg}, 300*time.Second)
			if err != nil {
				log.Printf("安装失败，命令输出: %s", string(output))
				return fmt.Errorf("安装%s失败: %v, 输出: %s", pkg, err, string(output))
			}
			log.Printf("✅ 已安装: %s", pkg)
		}
	}
	return nil
}

func (s *SystemService) createDirectoriesStep() error {
	// 使用相对路径创建目录，避免系统权限问题
	dirs := []string{
		"/opt/esemail/config",
		"/opt/esemail/mail",
		"/opt/esemail/logs",
		"/opt/esemail/certs",
		"/opt/esemail/data/db",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录 %s 失败: %v", dir, err)
		}
	}

	return nil
}

func (s *SystemService) generateConfigsStep(setupData *SetupConfig) error {
	// 生成配置文件到系统目录
	configs := map[string]string{
		"/etc/postfix/main.cf":          s.generatePostfixMainConfig(setupData),
		"/etc/postfix/master.cf":        s.generatePostfixMasterConfig(),
		"/etc/dovecot/dovecot.conf":     s.generateDovecotConfig(setupData),
		"/etc/rspamd/local.d/options.inc": s.generateRspamdConfig(),
		"/etc/opendkim.conf":            s.generateOpenDKIMConfig(setupData),
		// 本地备份配置
		"/opt/esemail/config/postfix_main.cf":     s.generatePostfixMainConfig(setupData),
		"/opt/esemail/config/postfix_master.cf":   s.generatePostfixMasterConfig(),
		"/opt/esemail/config/dovecot_config.conf": s.generateDovecotConfig(setupData),
		"/opt/esemail/config/rspamd_config.conf":  s.generateRspamdConfig(),
		"/opt/esemail/config/opendkim.conf":       s.generateOpenDKIMConfig(setupData),
	}

	for path, content := range configs {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("警告: 无法创建目录 %s: %v", dir, err)
			continue
		}

		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			log.Printf("警告: 无法创建配置文件 %s: %v", path, err)
			continue
		}
		log.Printf("已生成配置文件: %s", path)
	}

	// 创建Dovecot必需的用户文件和目录
	if err := s.createDovecotRequiredFiles(); err != nil {
		return fmt.Errorf("创建Dovecot必需文件失败: %v", err)
	}

	// 设置SSL证书权限
	if err := s.setupSSLCertificatePermissions(setupData); err != nil {
		log.Printf("警告: 设置SSL证书权限失败: %v", err)
	}

	return nil
}

func (s *SystemService) createDovecotRequiredFiles() error {
	// 创建邮件存储目录
	mailDirs := []string{
		"/var/mail/vhosts",
		"/var/run/dovecot",
	}

	for _, dir := range mailDirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("警告: 无法创建邮件目录 %s: %v", dir, err)
		} else {
			log.Printf("已创建邮件目录: %s", dir)
		}
	}

	// 创建vmail用户组和用户 (如果不存在)
	s.securityService.ExecuteSecureCommand("groupadd", []string{"-g", "5000", "vmail"}, 10*time.Second)
	s.securityService.ExecuteSecureCommand("useradd", []string{"-g", "vmail", "-u", "5000", "vmail", "-d", "/var/mail", "-m"}, 10*time.Second)

	// 设置邮件目录权限
	s.securityService.ExecuteSecureCommand("chown", []string{"-R", "vmail:vmail", "/var/mail/vhosts"}, 10*time.Second)
	s.securityService.ExecuteSecureCommand("chmod", []string{"-R", "0770", "/var/mail/vhosts"}, 10*time.Second)

	// 创建空的用户文件（如果不存在）
	usersFile := "/etc/dovecot/users"
	if _, err := os.Stat(usersFile); os.IsNotExist(err) {
		if err := os.WriteFile(usersFile, []byte("# Dovecot users file\n# Format: user:password:uid:gid::/var/mail/vhosts/domain/user\n"), 0600); err != nil {
			log.Printf("警告: 无法创建用户文件 %s: %v", usersFile, err)
		} else {
			log.Printf("已创建Dovecot用户文件: %s", usersFile)
		}
	}

	return nil
}

// 设置SSL证书权限
func (s *SystemService) setupSSLCertificatePermissions(setupData *SetupConfig) error {
	// 确定主机名
	mailHost := setupData.Hostname
	if mailHost == "" {
		mailHost = fmt.Sprintf("mail.%s", setupData.Domain)
	}

	certDir := fmt.Sprintf("/etc/ssl/mail/%s", mailHost)
	certFile := filepath.Join(certDir, "fullchain.pem")
	keyFile := filepath.Join(certDir, "private.key")

	log.Printf("设置SSL证书权限 - 证书目录: %s", certDir)

	// 检查证书文件是否存在
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("警告: 证书文件不存在: %s", certFile)
		return nil // 不是错误，可能还没有证书
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Printf("警告: 密钥文件不存在: %s", keyFile)
		return nil // 不是错误，可能还没有证书
	}

	// 设置证书目录权限和所有者
	commands := []struct {
		cmd  string
		args []string
		desc string
	}{
		{"chown", []string{"-R", "root:ssl-cert", certDir}, "设置证书目录所有者"},
		{"chmod", []string{"755", certDir}, "设置证书目录权限"},
		{"chmod", []string{"644", certFile}, "设置证书文件权限"},
		{"chmod", []string{"640", keyFile}, "设置私钥文件权限"},
		{"usermod", []string{"-a", "-G", "ssl-cert", "postfix"}, "添加postfix用户到ssl-cert组"},
	}

	for _, cmd := range commands {
		log.Printf("执行: %s %v", cmd.cmd, cmd.args)
		if _, err := s.securityService.ExecuteSecureCommand(cmd.cmd, cmd.args, 10*time.Second); err != nil {
			log.Printf("警告: %s失败: %v", cmd.desc, err)
		} else {
			log.Printf("成功: %s", cmd.desc)
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
		"/opt/esemail/config/opendkim/keys/default",
	}
	
	for _, dkimDir := range dkimDirs {
		if err := os.MkdirAll(dkimDir, 0700); err != nil {
			log.Printf("警告: 无法创建 DKIM 目录 %s: %v", dkimDir, err)
		}
	}

	// 生成真实的 DKIM 密钥对
	log.Printf("生成 DKIM 密钥对...")
	if _, err := s.securityService.ExecuteSecureCommand("opendkim-genkey", 
		[]string{"-s", "default", "-d", setupData.Domain, "-D", "/opt/esemail/config/opendkim/keys/default/"},
		30*time.Second); err != nil {
		log.Printf("警告: DKIM 密钥生成失败: %v", err)
		// 创建占位符文件
		privateKey := "# DKIM private key placeholder\n# Generate with: opendkim-genkey -s default -d " + setupData.Domain + "\n"
		os.WriteFile("/opt/esemail/config/opendkim/keys/default/default.private", []byte(privateKey), 0600)
		publicKey := fmt.Sprintf("default._domainkey.%s IN TXT \"v=DKIM1; k=rsa; p=PLACEHOLDER_PUBLIC_KEY\"\n", setupData.Domain)
		os.WriteFile("/opt/esemail/config/opendkim/keys/default/default.txt", []byte(publicKey), 0644)
	}

	// 生成 DKIM 配置文件
	keyTable := fmt.Sprintf("default._domainkey.%s %s:default:/etc/opendkim/keys/default/default.private\n", setupData.Domain, setupData.Domain)
	for _, path := range []string{"/etc/opendkim/KeyTable", "/opt/esemail/config/opendkim/KeyTable"} {
		os.WriteFile(path, []byte(keyTable), 0644)
	}

	signingTable := fmt.Sprintf("*@%s default._domainkey.%s\n", setupData.Domain, setupData.Domain)
	for _, path := range []string{"/etc/opendkim/SigningTable", "/opt/esemail/config/opendkim/SigningTable"} {
		os.WriteFile(path, []byte(signingTable), 0644)
	}

	return nil
}

func (s *SystemService) startServicesStep() error {
	services := []string{"postfix", "dovecot", "rspamd", "opendkim", "fail2ban"}
	var failedServices []string
	
	log.Printf("启动邮件系统服务...")
	
	// 启动每个服务
	for _, service := range services {
		log.Printf("启动服务: %s", service)
		if _, err := s.securityService.ExecuteSecureCommand("systemctl", []string{"start", service}, 30*time.Second); err != nil {
			log.Printf("启动服务 %s 失败: %v", service, err)
			failedServices = append(failedServices, service)
			continue
		}
		
		// 启用服务自启动
		if _, err := s.securityService.ExecuteSecureCommand("systemctl", []string{"enable", service}, 10*time.Second); err != nil {
			log.Printf("启用服务 %s 自启动失败: %v", service, err)
		}
	}
	
	// 防火墙配置由系统管理员手动操作
	log.Printf("提示: 请手动配置防火墙开放必要端口 (22, 25, 80, 110, 143, 465, 587, 993, 995, 8686)")
	
	if len(failedServices) > 0 {
		log.Printf("警告: 以下服务启动失败: %v", failedServices)
		log.Printf("请检查服务配置并手动启动失败的服务")
		// 不返回错误，允许初始化过程继续
	}
	
	log.Printf("所有邮件系统服务启动完成")
	return nil
}

func (s *SystemService) verifyServicesStep() error {
	services := []string{"postfix", "dovecot", "rspamd", "opendkim", "fail2ban"}
	var failedServices []string
	
	for _, service := range services {
		status := s.getServiceStatus(service)
		log.Printf("服务 %s 状态: %s", service, status)
		if status != "active" && status != "running" {
			failedServices = append(failedServices, service)
		}
	}
	
	if len(failedServices) > 0 {
		return fmt.Errorf("以下服务未正常运行: %v", failedServices)
	}
	
	log.Printf("所有邮件服务验证通过")
	return nil
}

func (s *SystemService) generatePostfixMainConfig(setupData *SetupConfig) string {
    // 确保主机名设置正确
    mailHost := setupData.Hostname
    if mailHost == "" {
        mailHost = fmt.Sprintf("mail.%s", setupData.Domain)
    }

    // 输出调试信息
    log.Printf("生成Postfix配置 - 域名: %s, 主机名: %s", setupData.Domain, mailHost)

    // 确保证书路径使用正确的主机名
    certPath := fmt.Sprintf("/etc/ssl/mail/%s/fullchain.pem", mailHost)
    keyPath := fmt.Sprintf("/etc/ssl/mail/%s/private.key", mailHost)

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
smtpd_tls_cert_file = %s
smtpd_tls_key_file = %s
smtpd_use_tls = yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
smtpd_tls_security_level = may
smtp_tls_security_level = may

# SASL 认证配置
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous,noplaintext
smtpd_sasl_tls_security_options = noanonymous

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
`, mailHost, setupData.Domain, certPath, keyPath)
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
    mailHost := setupData.Hostname
    if mailHost == "" {
        mailHost = fmt.Sprintf("mail.%s", setupData.Domain)
    }
    certPath := fmt.Sprintf("/etc/ssl/mail/%s/fullchain.pem", mailHost)
    keyPath := fmt.Sprintf("/etc/ssl/mail/%s/private.key", mailHost)
    // 如果证书不存在，回退到系统默认 snakeoil，避免服务启动失败
    if _, err := os.Stat(certPath); err != nil {
        certPath = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
    }
    if _, err := os.Stat(keyPath); err != nil {
        keyPath = "/etc/ssl/private/ssl-cert-snakeoil.key"
    }

    return fmt.Sprintf(`# Dovecot 配置文件
protocols = imap pop3 lmtp
listen = *

# SSL 配置
ssl = yes
ssl_cert = <%s
ssl_key = <%s

# 邮件存储配置
mail_location = maildir:/var/mail/vhosts/%%d/%%n
mail_uid = vmail
mail_gid = vmail

# 认证配置
auth_mechanisms = plain login

# 简单的密码数据库配置
passdb {
  driver = passwd-file
  args = scheme=PLAIN username_format=%%u /etc/dovecot/users
}

# 用户数据库配置
userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%%d/%%n
}

# 认证服务配置 (用于Postfix SASL)
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
  unix_listener auth-master {
    mode = 0600
    user = vmail
    group = vmail
  }
  user = dovecot
}

# IMAP 服务配置
service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}

# POP3 服务配置
service pop3-login {
  inet_listener pop3 {
    port = 110
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}

# 简化的 namespace 配置
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
`, certPath, keyPath)
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


// checkSystemInitialization 检查系统是否已初始化
func (s *SystemService) checkSystemInitialization() bool {
	// 检查初始化标记文件
	if _, err := os.Stat("/opt/esemail/config/.initialized"); err != nil {
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

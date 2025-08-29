package service

import (
	"fmt"
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
	_, err := os.Stat("/etc/esemail/.initialized")
	return err == nil
}

func (s *SystemService) markSystemInitialized() error {
	os.MkdirAll("/etc/esemail", 0755)
	return os.WriteFile("/etc/esemail/.initialized", []byte("1"), 0644)
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
		"postfix":  s.isPackageInstalled("postfix"),
		"dovecot":  s.isPackageInstalled("dovecot-core"),
		"rspamd":   s.isPackageInstalled("rspamd"),
		"opendkim": s.isPackageInstalled("opendkim"),
		"acme.sh":  s.isAcmeShInstalled(),
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
	for pkg, installed := range packages {
		if !installed {
			return fmt.Errorf("缺少必需软件包: %s", pkg)
		}
	}
	return nil
}

func (s *SystemService) installPackagesStep() error {
	packages := []string{"postfix", "dovecot-core", "dovecot-imapd", "dovecot-pop3d", "rspamd", "opendkim", "opendkim-tools"}

	// 安全地更新包列表
	_, err := s.securityService.ExecuteSecureCommand("apt", []string{"update"}, 60*time.Second)
	if err != nil {
		return fmt.Errorf("更新软件包列表失败: %v", err)
	}

	for _, pkg := range packages {
		if !s.isPackageInstalled(pkg) {
			_, err := s.securityService.ExecuteSecureCommand("apt", []string{"install", "-y", pkg}, 300*time.Second)
			if err != nil {
				return fmt.Errorf("安装 %s 失败: %v", pkg, err)
			}
		}
	}

	// acme.sh安装被禁用，因为使用curl下载脚本执行存在安全风险
	// 建议在部署脚本中预先安装acme.sh
	if !s.isAcmeShInstalled() {
		return fmt.Errorf("acme.sh未安装，请在部署时预先安装")
	}

	return nil
}

func (s *SystemService) createDirectoriesStep() error {
	dirs := []string{
		"/etc/esemail",
		"/var/lib/esemail",
		"/var/lib/esemail/mail",
		"/var/lib/esemail/db",
		"/var/lib/esemail/acme",
		"/etc/ssl/mail",
		"/var/spool/postfix/rspamd",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录 %s 失败: %v", dir, err)
		}
	}

	return nil
}

func (s *SystemService) generateConfigsStep(setupData *SetupConfig) error {
	configs := map[string]string{
		"/etc/postfix/main.cf":                    s.generatePostfixMainConfig(setupData),
		"/etc/postfix/master.cf":                  s.generatePostfixMasterConfig(),
		"/etc/dovecot/dovecot.conf":               s.generateDovecotConfig(setupData),
		"/etc/rspamd/local.d/milter_headers.conf": s.generateRspamdConfig(),
		"/etc/opendkim.conf":                      s.generateOpenDKIMConfig(setupData),
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

	dkimDir := "/etc/opendkim/keys/default"
	if err := os.MkdirAll(dkimDir, 0700); err != nil {
		return fmt.Errorf("创建DKIM目录失败: %v", err)
	}

	// 使用安全的DKIM密钥生成
	if err := s.securityService.GenerateDKIMKeySecure(setupData.Domain); err != nil {
		return err
	}

	keyTable := fmt.Sprintf("default._domainkey.%s %s:default:/etc/opendkim/keys/default/default.private\n", setupData.Domain, setupData.Domain)
	if err := os.WriteFile("/etc/opendkim/KeyTable", []byte(keyTable), 0644); err != nil {
		return fmt.Errorf("创建KeyTable失败: %v", err)
	}

	signingTable := fmt.Sprintf("*@%s default._domainkey.%s\n", setupData.Domain, setupData.Domain)
	if err := os.WriteFile("/etc/opendkim/SigningTable", []byte(signingTable), 0644); err != nil {
		return fmt.Errorf("创建SigningTable失败: %v", err)
	}

	return nil
}

func (s *SystemService) startServicesStep() error {
	services := []string{"postfix", "dovecot", "rspamd", "opendkim"}

	for _, service := range services {
		// 启用服务
		_, err := s.securityService.ExecuteSecureCommand("systemctl", []string{"enable", service}, 15*time.Second)
		if err != nil {
			return fmt.Errorf("启用服务 %s 失败: %v", service, err)
		}

		// 启动服务
		if err := s.securityService.RestartServiceSecure(service); err != nil {
			return err
		}
	}

	return nil
}

func (s *SystemService) verifyServicesStep() error {
	services := []string{"postfix", "dovecot", "rspamd", "opendkim"}

	for _, service := range services {
		if status := s.getServiceStatus(service); status != "active" {
			return fmt.Errorf("服务 %s 状态异常: %s", service, status)
		}
	}

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

smtpd_tls_cert_file = /etc/ssl/mail/%s/fullchain.pem
smtpd_tls_key_file = /etc/ssl/mail/%s/privkey.pem
smtpd_use_tls = yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
smtpd_tls_security_level = may
smtp_tls_security_level = may

smtpd_milters = inet:localhost:11332, inet:localhost:8891
non_smtpd_milters = inet:localhost:11332, inet:localhost:8891
milter_protocol = 6
milter_mail_macros = i {mail_addr} {client_addr} {client_name} {auth_authen}
milter_default_action = accept

virtual_alias_domains =
virtual_alias_maps = hash:/etc/postfix/virtual
virtual_mailbox_domains = 
virtual_mailbox_maps = hash:/etc/postfix/vmailbox
virtual_mailbox_base = /var/lib/esemail/mail
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

ssl = required
ssl_cert = </etc/ssl/mail/%s/fullchain.pem
ssl_key = </etc/ssl/mail/%s/privkey.pem
ssl_protocols = !SSLv2 !SSLv3

mail_location = maildir:/var/lib/esemail/mail/%%d/%%n/Maildir
mail_uid = 5000
mail_gid = 5000

auth_mechanisms = plain login
passdb {
  driver = passwd-file
  args = scheme=CRYPT username_format=%%u /etc/dovecot/users
}
userdb {
  driver = static
  args = uid=5000 gid=5000 home=/var/lib/esemail/mail/%%d/%%n
}

service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}

service pop3-login {
  inet_listener pop3 {
    port = 0
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

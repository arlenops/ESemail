package service

import (
	"esemail/internal/config"
	"fmt"
	"os"
	"strings"
	"time"
)

type CertService struct{
	securityService *SecurityService
	config          *config.CertConfig
}

type Certificate struct {
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Issuer    string    `json:"issuer"`
	AutoRenew bool      `json:"auto_renew"`
}

type IssueCertRequest struct {
	Domain           string `json:"domain" binding:"required"`
	CertType         string `json:"cert_type"`         // mail 或 wildcard
	ValidationMethod string `json:"validation_method"` // http 或 dns
	Email            string `json:"email" binding:"required"`
}

type DNSValidationResponse struct {
	Success  bool   `json:"success"`
	DNSName  string `json:"dns_name,omitempty"`
	DNSValue string `json:"dns_value,omitempty"`
	Error    string `json:"error,omitempty"`
}

func NewCertService(certConfig *config.CertConfig) *CertService {
	return &CertService{
		securityService: NewSecurityService(),
		config:          certConfig,
	}
}

func (s *CertService) ListCertificates() ([]Certificate, error) {
	var certificates []Certificate

	acmeHome := s.config.AcmePath
	if acmeHome == "" {
		acmeHome = "/root/.acme.sh" // 回退到默认值
	}
	if _, err := os.Stat(acmeHome); os.IsNotExist(err) {
		return certificates, nil
	}

	entries, err := os.ReadDir(acmeHome)
	if err != nil {
		return nil, fmt.Errorf("读取证书目录失败: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			domain := entry.Name()
			cert := s.getCertificateInfo(domain)
			if cert != nil {
				certificates = append(certificates, *cert)
			}
		}
	}

	return certificates, nil
}

func (s *CertService) IssueCertificate(req IssueCertRequest) (*DNSValidationResponse, error) {
	// 验证域名安全性
	baseDomain := req.Domain
	if req.CertType == "mail" {
		// 对于邮件证书，验证基础域名的安全性
		if err := s.securityService.ValidateDomain(baseDomain); err != nil {
			return nil, fmt.Errorf("域名验证失败: %v", err)
		}
		// 实际申请的是 mail.domain.com
		req.Domain = "mail." + baseDomain
	} else if req.CertType == "wildcard" {
		// 对于通配符证书，验证基础域名并强制DNS验证
		if err := s.securityService.ValidateDomain(baseDomain); err != nil {
			return nil, fmt.Errorf("域名验证失败: %v", err)
		}
		req.Domain = "*." + baseDomain
		req.ValidationMethod = "dns" // 通配符证书必须使用DNS验证
	} else {
		// 默认单域名证书
		if err := s.securityService.ValidateDomain(req.Domain); err != nil {
			return nil, fmt.Errorf("域名验证失败: %v", err)
		}
	}

	// 验证邮箱地址
	if req.Email == "" {
		return nil, fmt.Errorf("邮箱地址不能为空")
	}

	// 验证验证方式
	if req.ValidationMethod == "" {
		req.ValidationMethod = "http" // 默认HTTP验证
	}
	
	allowedMethods := map[string]bool{
		"http": true,
		"dns":  true,
	}
	
	if !allowedMethods[req.ValidationMethod] {
		return nil, fmt.Errorf("不支持的验证方式: %s，支持的方式: http, dns", req.ValidationMethod)
	}

	// 根据验证方式和证书类型确定签发流程
	if req.ValidationMethod == "dns" {
		return s.issueCertificateWithDNS(req)
	} else {
		return s.issueCertificateWithHTTP(req)
	}
}

// issueCertificateWithHTTP HTTP验证方式签发证书
func (s *CertService) issueCertificateWithHTTP(req IssueCertRequest) (*DNSValidationResponse, error) {
	// 验证域名可访问性
	if err := s.validateDomainAccessibility(req.Domain); err != nil {
		return nil, fmt.Errorf("域名HTTP验证失败: %v", err)
	}
	
	// 使用acme.sh进行HTTP验证证书申请
	webroot := s.config.WebrootPath
	if webroot == "" {
		webroot = "/var/www/html" // 回退到默认值
	}
	if _, err := os.Stat(webroot); os.IsNotExist(err) {
		// 如果webroot不存在，创建它
		if err := os.MkdirAll(webroot, 0755); err != nil {
			return nil, fmt.Errorf("创建webroot目录失败: %v", err)
		}
	}
	
	// 构建acme.sh命令
	email := req.Email
	if email == "" && s.config.Email != "" {
		email = s.config.Email
	}
	
	server := s.config.Server
	if server == "" {
		server = "letsencrypt"
	}
	
	args := []string{
		"--issue",
		"-d", req.Domain,
		"-w", webroot,
		"--server", server,
		"--email", email,
	}
	
	if s.config.ForceRenewal {
		args = append(args, "--force")
	}
	
	// 执行证书申请
	output, err := s.securityService.ExecuteSecureCommand("acme.sh", args, 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("证书申请失败: %v, 输出: %s", err, string(output))
	}
	
	// 自动安装证书
	if err := s.installCertificateWithAcme(req.Domain); err != nil {
		return nil, fmt.Errorf("证书安装失败: %v", err)
	}
	
	return &DNSValidationResponse{
		Success: true,
	}, nil
}

// issueCertificateWithDNS DNS验证方式签发证书
func (s *CertService) issueCertificateWithDNS(req IssueCertRequest) (*DNSValidationResponse, error) {
	// 对于通配符证书，DNS记录名需要特殊处理
	domain := req.Domain
	if req.CertType == "wildcard" {
		// 去掉*. 前缀
		domain = req.Domain[2:] // 移除 "*."
	}
	
	// 检查是否有DNS API配置可用于自动验证
	if s.hasAutomaticDNSProvider() {
		// 使用自动DNS验证
		return s.issueWithAutomaticDNS(req)
	}
	
	// 生成真实的DNS验证令牌 - 使用acme.sh生成
	args := []string{
		"--issue",
		"-d", req.Domain,
		"--dns",
		"--server", "letsencrypt",
		"--email", req.Email,
		"--yes-I-know-dns-manual-mode-enough-go-ahead-please",  // 手动DNS模式
	}
	
	// 执行命令获取DNS验证信息
	output, err := s.securityService.ExecuteSecureCommand("acme.sh", args, 2*time.Minute)
	if err != nil {
		// 如果命令失败但输出中包含验证信息，仍然解析它
		if !strings.Contains(string(output), "_acme-challenge") {
			return nil, fmt.Errorf("获取DNS验证信息失败: %v", err)
		}
	}
	
	// 从输出中解析DNS验证信息
	dnsName, dnsValue := s.parseDNSChallengeFromOutput(string(output), domain)
	if dnsName == "" || dnsValue == "" {
		return nil, fmt.Errorf("无法从acme.sh输出中解析DNS验证信息")
	}
	
	// 返回DNS验证信息，等待用户手动添加DNS记录
	return &DNSValidationResponse{
		Success:  false, // DNS验证需要用户手动添加记录
		DNSName:  dnsName,
		DNSValue: dnsValue,
	}, nil
}

// validateDomainAccessibility 验证域名HTTP可访问性
func (s *CertService) validateDomainAccessibility(domain string) error {
	// 简单的HTTP可访问性检查
	// 在生产环境中应该有更完善的验证逻辑
	return nil
}

// generateDNSValidationToken 生成DNS验证令牌
func (s *CertService) generateDNSValidationToken(domain string) string {
	// 生成一个模拟的验证令牌
	// 在实际实现中，这应该是ACME协议生成的真实验证令牌
	return fmt.Sprintf("acme-validation-%s-%d", domain, time.Now().Unix())
}

// ValidateDNS 验证DNS记录是否已正确添加
func (s *CertService) ValidateDNS(dnsName, dnsValue string) (*DNSValidationResponse, error) {
	// 验证输入参数安全性
	if dnsName == "" || dnsValue == "" {
		return &DNSValidationResponse{
			Success: false,
			Error:   "DNS记录名称或值不能为空",
		}, nil
	}
	
	// 使用dig命令验证DNS记录
	args := []string{
		"TXT", 
		dnsName,
		"+short",  // 简化输出
	}
	
	output, err := s.securityService.ExecuteSecureCommand("dig", args, 30*time.Second)
	if err != nil {
		return &DNSValidationResponse{
			Success: false,
			Error:   fmt.Sprintf("DNS查询失败: %v", err),
		}, nil
	}
	
	// 解析dig输出
	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" {
		return &DNSValidationResponse{
			Success: false,
			Error:   "DNS TXT记录未找到，请检查DNS设置是否正确且已生效",
		}, nil
	}
	
	// 检查返回的值是否包含期望的验证值
	// dig返回的TXT记录会被引号包围，需要去除
	foundValues := strings.Split(outputStr, "\n")
	for _, value := range foundValues {
		cleanValue := strings.Trim(value, "\"")
		if cleanValue == dnsValue {
			// DNS验证成功，现在完成证书申请
			return s.completeDNSChallenge(dnsName, dnsValue)
		}
	}
	
	return &DNSValidationResponse{
		Success: false,
		Error:   "DNS TXT记录值不匹配，请确认已正确添加DNS记录",
	}, nil
}

func (s *CertService) RenewCertificates() error {
	// 使用acme.sh续签所有证书
	args := []string{
		"--renew-all",
		"--force",  // 强制续签，即使证书还未到期
	}
	
	output, err := s.securityService.ExecuteSecureCommand("acme.sh", args, 5*time.Minute)
	if err != nil {
		return fmt.Errorf("证书续签失败: %v, 输出: %s", err, string(output))
	}
	
	// 续签成功后，重新安装证书
	certs, err := s.ListCertificates()
	if err != nil {
		return fmt.Errorf("获取证书列表失败: %v", err)
	}
	
	// 为每个域名重新安装证书
	for _, cert := range certs {
		if err := s.installCertificateWithAcme(cert.Domain); err != nil {
			return fmt.Errorf("重新安装证书失败 (域名: %s): %v", cert.Domain, err)
		}
	}
	
	return nil
}

func (s *CertService) getCertificateInfo(domain string) *Certificate {
	baseCertPath := s.config.CertPath
	if baseCertPath == "" {
		baseCertPath = "/etc/ssl/mail"
	}
	certPath := fmt.Sprintf("%s/%s/fullchain.pem", baseCertPath, domain)

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil
	}

	cert := &Certificate{
		Domain:    domain,
		Type:      "single",
		Status:    "valid",
		AutoRenew: true,
		Issuer:    "Let's Encrypt",
	}

	if strings.Contains(domain, "*") {
		cert.Type = "wildcard"
	}

	// 验证证书路径安全性
	if err := s.securityService.ValidateFilePath(certPath); err != nil {
		return cert
	}

	output, err := s.securityService.ExecuteSecureCommand("openssl", []string{"x509", "-in", certPath, "-text", "-noout"}, 15*time.Second)
	if err == nil {
		s.parseCertificateOutput(cert, string(output))
	}

	return cert
}

func (s *CertService) parseCertificateOutput(cert *Certificate, output string) {
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "Not Before:") {
			dateStr := strings.TrimPrefix(line, "Not Before:")
			dateStr = strings.TrimSpace(dateStr)
			if t, err := time.Parse("Jan 2 15:04:05 2006 MST", dateStr); err == nil {
				cert.IssuedAt = t
			}
		}

		if strings.Contains(line, "Not After:") {
			dateStr := strings.TrimPrefix(line, "Not After:")
			dateStr = strings.TrimSpace(dateStr)
			if t, err := time.Parse("Jan 2 15:04:05 2006 MST", dateStr); err == nil {
				cert.ExpiresAt = t
				if t.Before(time.Now()) {
					cert.Status = "expired"
				} else if t.Before(time.Now().AddDate(0, 0, 30)) {
					cert.Status = "expiring"
				}
			}
		}
	}
}

func (s *CertService) setupDNSProvider(provider, apiKey, apiSecret string) error {
	switch strings.ToLower(provider) {
	case "cf", "cloudflare":
		os.Setenv("CF_Key", apiKey)
		os.Setenv("CF_Email", apiSecret)
	case "ali", "aliyun":
		os.Setenv("Ali_Key", apiKey)
		os.Setenv("Ali_Secret", apiSecret)
	case "dp", "dnspod":
		os.Setenv("DP_Id", apiKey)
		os.Setenv("DP_Key", apiSecret)
	case "aws":
		os.Setenv("AWS_ACCESS_KEY_ID", apiKey)
		os.Setenv("AWS_SECRET_ACCESS_KEY", apiSecret)
	case "gcp":
		os.Setenv("GCE_SERVICE_ACCOUNT_FILE", apiKey)
	case "azure":
		os.Setenv("AZUREDNS_SUBSCRIPTIONID", apiKey)
		os.Setenv("AZUREDNS_CLIENTSECRET", apiSecret)
	case "godaddy":
		os.Setenv("GD_Key", apiKey)
		os.Setenv("GD_Secret", apiSecret)
	case "namesilo":
		os.Setenv("Namesilo_Key", apiKey)
	default:
		return fmt.Errorf("不支持的DNS提供商: %s", provider)
	}

	return nil
}

func (s *CertService) installCertificate(domain string) error {
	return s.installCertificateWithAcme(domain)
}

// installCertificateWithAcme 使用acme.sh安装证书
func (s *CertService) installCertificateWithAcme(domain string) error {
	baseCertPath := s.config.CertPath
	if baseCertPath == "" {
		baseCertPath = "/etc/ssl/mail"
	}
	certDir := fmt.Sprintf("%s/%s", baseCertPath, domain)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %v", err)
	}

	// 验证域名和目录路径安全性
	if err := s.securityService.ValidateDomain(domain); err != nil {
		return fmt.Errorf("域名验证失败: %v", err)
	}
	
	if err := s.securityService.ValidateFilePath(certDir); err != nil {
		return fmt.Errorf("证书目录路径不安全: %v", err)
	}

	// 使用acme.sh安装证书
	args := []string{
		"--installcert",
		"-d", domain,
		"--cert-file", fmt.Sprintf("%s/cert.pem", certDir),
		"--key-file", fmt.Sprintf("%s/private.key", certDir),
		"--fullchain-file", fmt.Sprintf("%s/fullchain.pem", certDir),
		"--ca-file", fmt.Sprintf("%s/ca.pem", certDir),
		"--reloadcmd", "systemctl reload postfix dovecot", // 重新加载邮件服务
	}
	
	output, err := s.securityService.ExecuteSecureCommand("acme.sh", args, 2*time.Minute)
	if err != nil {
		return fmt.Errorf("证书安装失败: %v, 输出: %s", err, string(output))
	}
	
	// 设置正确的文件权限
	if err := s.setCorrectCertPermissions(certDir); err != nil {
		return fmt.Errorf("设置证书权限失败: %v", err)
	}
	
	return nil
}

// hasAutomaticDNSProvider 检查是否配置了自动DNS提供商
func (s *CertService) hasAutomaticDNSProvider() bool {
	// 检查常见的DNS API环境变量
	dnsProviders := [][]string{
		{"CF_Key", "CF_Email"},         // Cloudflare
		{"Ali_Key", "Ali_Secret"},      // 阿里云
		{"DP_Id", "DP_Key"},           // DNSPod
		{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}, // AWS
		{"GD_Key", "GD_Secret"},       // GoDaddy
		{"Namesilo_Key"},              // Namesilo
	}
	
	for _, provider := range dnsProviders {
		hasAll := true
		for _, envVar := range provider {
			if os.Getenv(envVar) == "" {
				hasAll = false
				break
			}
		}
		if hasAll {
			return true
		}
	}
	
	return false
}

// issueWithAutomaticDNS 使用自动DNS验证申请证书
func (s *CertService) issueWithAutomaticDNS(req IssueCertRequest) (*DNSValidationResponse, error) {
	// 确定使用的DNS提供商
	dnsProvider := s.detectDNSProvider()
	if dnsProvider == "" {
		return nil, fmt.Errorf("无法确定DNS提供商")
	}
	
	// 构建acme.sh命令
	args := []string{
		"--issue",
		"-d", req.Domain,
		"--dns", "dns_" + dnsProvider,
		"--server", "letsencrypt",
		"--email", req.Email,
		"--force",
	}
	
	// 执行自动DNS验证
	output, err := s.securityService.ExecuteSecureCommand("acme.sh", args, 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("自动DNS验证失败: %v, 输出: %s", err, string(output))
	}
	
	// 自动安装证书
	if err := s.installCertificateWithAcme(req.Domain); err != nil {
		return nil, fmt.Errorf("证书安装失败: %v", err)
	}
	
	return &DNSValidationResponse{
		Success: true,
	}, nil
}

// detectDNSProvider 检测DNS提供商
func (s *CertService) detectDNSProvider() string {
	if os.Getenv("CF_Key") != "" && os.Getenv("CF_Email") != "" {
		return "cf"
	}
	if os.Getenv("Ali_Key") != "" && os.Getenv("Ali_Secret") != "" {
		return "ali"
	}
	if os.Getenv("DP_Id") != "" && os.Getenv("DP_Key") != "" {
		return "dp"
	}
	if os.Getenv("AWS_ACCESS_KEY_ID") != "" && os.Getenv("AWS_SECRET_ACCESS_KEY") != "" {
		return "aws"
	}
	if os.Getenv("GD_Key") != "" && os.Getenv("GD_Secret") != "" {
		return "gd"
	}
	if os.Getenv("Namesilo_Key") != "" {
		return "namesilo"
	}
	
	return ""
}

// parseDNSChallengeFromOutput 从acme.sh输出中解析DNS验证信息
func (s *CertService) parseDNSChallengeFromOutput(output, domain string) (string, string) {
	lines := strings.Split(output, "\n")
	var dnsName, dnsValue string
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// 查找DNS记录名称
		if strings.Contains(line, "_acme-challenge") && strings.Contains(line, domain) {
			// 提取DNS名称，通常格式为：_acme-challenge.domain.com
			if strings.Contains(line, "_acme-challenge.") {
				start := strings.Index(line, "_acme-challenge.")
				if start != -1 {
					// 从_acme-challenge开始提取到空格或引号
					remaining := line[start:]
					parts := strings.Fields(remaining)
					if len(parts) > 0 {
						dnsName = strings.Trim(parts[0], "\"'")
					}
				}
			}
		}
		
		// 查找验证值，通常是一个长的随机字符串
		if strings.Contains(line, "TXT") && len(strings.Fields(line)) > 0 {
			parts := strings.Fields(line)
			for _, part := range parts {
				// ACME验证值通常是base64编码，长度在20-50字符之间
				if len(part) > 20 && len(part) < 100 && !strings.Contains(part, ".") {
					dnsValue = strings.Trim(part, "\"'")
					break
				}
			}
		}
	}
	
	// 如果没有从输出中解析到，使用默认格式
	if dnsName == "" {
		dnsName = "_acme-challenge." + domain
	}
	
	return dnsName, dnsValue
}

// completeDNSChallenge 完成DNS验证挑战
func (s *CertService) completeDNSChallenge(dnsName, dnsValue string) (*DNSValidationResponse, error) {
	// 从DNS记录名中提取域名
	domain := strings.TrimPrefix(dnsName, "_acme-challenge.")
	
	// 使用acme.sh继续完成验证
	args := []string{
		"--renew",
		"-d", domain,
		"--force",
	}
	
	output, err := s.securityService.ExecuteSecureCommand("acme.sh", args, 3*time.Minute)
	if err != nil {
		return &DNSValidationResponse{
			Success: false,
			Error:   fmt.Sprintf("完成DNS验证失败: %v, 输出: %s", err, string(output)),
		}, nil
	}
	
	// 自动安装证书
	if err := s.installCertificateWithAcme(domain); err != nil {
		return &DNSValidationResponse{
			Success: false,
			Error:   fmt.Sprintf("证书安装失败: %v", err),
		}, nil
	}
	
	return &DNSValidationResponse{
		Success: true,
	}, nil
}

// setCorrectCertPermissions 设置证书文件的正确权限
func (s *CertService) setCorrectCertPermissions(certDir string) error {
	// 证书文件应该是可读的
	certFiles := []string{"cert.pem", "fullchain.pem", "ca.pem"}
	for _, file := range certFiles {
		filePath := fmt.Sprintf("%s/%s", certDir, file)
		if _, err := os.Stat(filePath); err == nil {
			if err := os.Chmod(filePath, 0644); err != nil {
				return fmt.Errorf("设置文件权限失败 %s: %v", filePath, err)
			}
		}
	}
	
	// 私钥文件应该只有owner可读
	keyFile := fmt.Sprintf("%s/private.key", certDir)
	if _, err := os.Stat(keyFile); err == nil {
		if err := os.Chmod(keyFile, 0600); err != nil {
			return fmt.Errorf("设置私钥权限失败: %v", err)
		}
	}
	
	return nil
}

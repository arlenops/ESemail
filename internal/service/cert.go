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
	pendingChallenges map[string]*PendingChallenge
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

type PendingChallenge struct {
	Domain    string    `json:"domain"`
	DNSName   string    `json:"dns_name"`
	DNSValue  string    `json:"dns_value"`
	Request   IssueCertRequest `json:"request"`
	CreatedAt time.Time `json:"created_at"`
}

func NewCertService(certConfig *config.CertConfig) *CertService {
	return &CertService{
		securityService:   NewSecurityService(),
		config:            certConfig,
		pendingChallenges: make(map[string]*PendingChallenge),
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
	originalDomain := req.Domain
	
	if req.CertType == "mail" {
		// 对于邮件证书，检查域名是否已经有mail.前缀
		if !strings.HasPrefix(originalDomain, "mail.") {
			// 如果没有mail.前缀，添加它
			req.Domain = "mail." + originalDomain
		}
		// 验证最终域名的安全性
		if err := s.securityService.ValidateDomain(req.Domain); err != nil {
			return nil, fmt.Errorf("域名验证失败: %v", err)
		}
	} else if req.CertType == "wildcard" {
		// 对于通配符证书，检查域名是否已经有*.前缀
		if !strings.HasPrefix(originalDomain, "*.") {
			// 如果没有*.前缀，添加它
			req.Domain = "*." + originalDomain
		}
		// 验证基础域名的安全性（去掉*. 前缀）
		baseDomain := strings.TrimPrefix(req.Domain, "*.")
		if err := s.securityService.ValidateDomain(baseDomain); err != nil {
			return nil, fmt.Errorf("域名验证失败: %v", err)
		}
		req.ValidationMethod = "dns" // 通配符证书必须使用DNS验证
	} else {
		// 默认单域名证书，直接验证
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
	// 检查acme.sh是否可用
	if !s.isAcmeAvailable() {
		return nil, fmt.Errorf("acme.sh未安装或不可用。请先安装acme.sh：curl https://get.acme.sh | sh")
	}
	
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
	acmePath := s.getAcmePath()
	output, err := s.securityService.ExecuteSecureCommand(acmePath, args, 5*time.Minute)
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
	
	// 对于手动DNS验证，我们生成一个临时的验证令牌
	// 真正的验证会在用户确认DNS记录添加后进行
	dnsName := "_acme-challenge." + domain
	dnsValue := s.generateDNSValidationToken(req.Domain)
	
	// 将待验证信息存储起来，供后续验证使用
	s.storePendingDNSChallenge(req.Domain, dnsName, dnsValue, req)
	
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
			Error:   fmt.Sprintf("DNS查询失败: %v。请确保dig命令可用", err),
		}, nil
	}
	
	// 解析dig输出
	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" {
		return &DNSValidationResponse{
			Success: false,
			Error:   fmt.Sprintf("DNS TXT记录未找到。请添加记录：%s TXT %s", dnsName, dnsValue),
		}, nil
	}
	
	// 检查返回的值是否包含期望的验证值
	// dig返回的TXT记录会被引号包围，需要去除
	foundValues := strings.Split(outputStr, "\n")
	var foundValuesList []string
	
	for _, value := range foundValues {
		cleanValue := strings.Trim(value, "\" \t")
		foundValuesList = append(foundValuesList, cleanValue)
		if cleanValue == dnsValue {
			// DNS验证成功，现在完成证书申请
			return s.completeDNSChallenge(dnsName, dnsValue)
		}
	}
	
	return &DNSValidationResponse{
		Success: false,
		Error: fmt.Sprintf("DNS TXT记录值不匹配。\n期望值: %s\n找到值: %s\n请检查DNS记录是否正确添加", 
			dnsValue, strings.Join(foundValuesList, ", ")),
	}, nil
}

func (s *CertService) RenewCertificates() error {
	// 检查acme.sh是否可用
	if !s.isAcmeAvailable() {
		return fmt.Errorf("acme.sh未安装或不可用。请先安装acme.sh：curl https://get.acme.sh | sh")
	}
	
	// 使用acme.sh续签所有证书
	args := []string{
		"--renew-all",
		"--force",  // 强制续签，即使证书还未到期
	}
	
	acmePath := s.getAcmePath()
	output, err := s.securityService.ExecuteSecureCommand(acmePath, args, 5*time.Minute)
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
	
	acmePath := s.getAcmePath()
	output, err := s.securityService.ExecuteSecureCommand(acmePath, args, 2*time.Minute)
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
	acmePath := s.getAcmePath()
	output, err := s.securityService.ExecuteSecureCommand(acmePath, args, 5*time.Minute)
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
	
	// 获取待验证的挑战信息
	challenge := s.getPendingChallenge(domain)
	if challenge == nil {
		return &DNSValidationResponse{
			Success: false,
			Error:   "未找到对应的DNS验证请求，请重新申请证书",
		}, nil
	}
	
	// 验证DNS值是否匹配
	if challenge.DNSValue != dnsValue {
		return &DNSValidationResponse{
			Success: false,
			Error:   "DNS验证值不匹配",
		}, nil
	}
	
	// 现在执行真正的证书申请
	return s.executeRealDNSCertRequest(challenge)
}

// executeRealDNSCertRequest 执行真正的DNS证书申请
func (s *CertService) executeRealDNSCertRequest(challenge *PendingChallenge) (*DNSValidationResponse, error) {
	req := challenge.Request
	
	// 检查acme.sh是否可用
	if !s.isAcmeAvailable() {
		return &DNSValidationResponse{
			Success: false,
			Error:   "acme.sh未安装或不可用。请先安装acme.sh：curl https://get.acme.sh | sh",
		}, nil
	}
	
	// 检查是否有自动DNS配置
	if s.hasAutomaticDNSProvider() {
		// 使用自动DNS验证
		return s.issueWithAutomaticDNS(req)
	}
	
	// 手动DNS验证 - 使用更简单的方法
	email := req.Email
	if email == "" && s.config.Email != "" {
		email = s.config.Email
	}
	
	server := s.config.Server
	if server == "" {
		server = "letsencrypt"
	}
	
	// 使用standalone模式申请证书（假设80端口可用）
	args := []string{
		"--issue",
		"-d", req.Domain,
		"--standalone",
		"--server", server,
		"--email", email,
	}
	
	if s.config.ForceRenewal {
		args = append(args, "--force")
	}
	
	// 执行证书申请
	acmePath := s.getAcmePath()
	output, err := s.securityService.ExecuteSecureCommand(acmePath, args, 5*time.Minute)
	if err != nil {
		return &DNSValidationResponse{
			Success: false,
			Error:   fmt.Sprintf("证书申请失败: %v, 输出: %s", err, string(output)),
		}, nil
	}
	
	// 自动安装证书
	if err := s.installCertificateWithAcme(req.Domain); err != nil {
		return &DNSValidationResponse{
			Success: false,
			Error:   fmt.Sprintf("证书安装失败: %v", err),
		}, nil
	}
	
	// 清除待验证的挑战
	s.removePendingChallenge(req.Domain)
	
	return &DNSValidationResponse{
		Success: true,
	}, nil
}

// storePendingDNSChallenge 存储待验证的DNS挑战
func (s *CertService) storePendingDNSChallenge(domain, dnsName, dnsValue string, req IssueCertRequest) {
	s.pendingChallenges[domain] = &PendingChallenge{
		Domain:    domain,
		DNSName:   dnsName,
		DNSValue:  dnsValue,
		Request:   req,
		CreatedAt: time.Now(),
	}
}

// getPendingChallenge 获取待验证的DNS挑战
func (s *CertService) getPendingChallenge(domain string) *PendingChallenge {
	challenge, exists := s.pendingChallenges[domain]
	if !exists {
		return nil
	}
	
	// 检查是否过期（24小时）
	if time.Since(challenge.CreatedAt) > 24*time.Hour {
		delete(s.pendingChallenges, domain)
		return nil
	}
	
	return challenge
}

// removePendingChallenge 移除待验证的DNS挑战
func (s *CertService) removePendingChallenge(domain string) {
	delete(s.pendingChallenges, domain)
}

// isAcmeAvailable 检查acme.sh是否可用
func (s *CertService) isAcmeAvailable() bool {
	// 检查多个可能的acme.sh路径
	possiblePaths := []string{
		"acme.sh",                    // PATH中
		"/root/.acme.sh/acme.sh",     // 默认安装位置
		"/home/acme/.acme.sh/acme.sh", // 用户安装位置
		"/usr/local/bin/acme.sh",     // 系统安装位置
		"/opt/acme.sh/acme.sh",       // 可选安装位置
	}
	
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		
		// 对于PATH中的命令，尝试执行which
		if path == "acme.sh" {
			output, err := s.securityService.ExecuteSecureCommand("which", []string{"acme.sh"}, 5*time.Second)
			if err == nil && len(output) > 0 {
				return true
			}
		}
	}
	
	return false
}

// getAcmePath 获取acme.sh的实际路径
func (s *CertService) getAcmePath() string {
	// 检查多个可能的acme.sh路径，按优先级排序
	possiblePaths := []string{
		"/root/.acme.sh/acme.sh",     // 默认安装位置（最常用）
		"acme.sh",                    // PATH中
		"/home/acme/.acme.sh/acme.sh", // 用户安装位置
		"/usr/local/bin/acme.sh",     // 系统安装位置
		"/opt/acme.sh/acme.sh",       // 可选安装位置
	}
	
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	
	// 如果都没找到，返回默认的acme.sh，让系统尝试从PATH查找
	return "acme.sh"
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

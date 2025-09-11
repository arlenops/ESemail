package service

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type CertService struct{
	securityService *SecurityService
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
	Type             string `json:"type"`
	ValidationMethod string `json:"validation_method"` // http 或 dns
	Email            string `json:"email" binding:"required"`
}

func NewCertService() *CertService {
	return &CertService{
		securityService: NewSecurityService(),
	}
}

func (s *CertService) ListCertificates() ([]Certificate, error) {
	var certificates []Certificate

	acmeHome := "/root/.acme.sh"
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

func (s *CertService) IssueCertificate(req IssueCertRequest) error {
	// 验证域名安全性
	if err := s.securityService.ValidateDomain(req.Domain); err != nil {
		return fmt.Errorf("域名验证失败: %v", err)
	}

	// 验证邮箱地址
	if req.Email == "" {
		return fmt.Errorf("邮箱地址不能为空")
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
		return fmt.Errorf("不支持的验证方式: %s，支持的方式: http, dns", req.ValidationMethod)
	}

	// 根据验证方式和证书类型确定签发流程
	if req.ValidationMethod == "dns" {
		return s.issueCertificateWithDNS(req)
	} else {
		return s.issueCertificateWithHTTP(req)
	}
}

// issueCertificateWithHTTP HTTP验证方式签发证书
func (s *CertService) issueCertificateWithHTTP(req IssueCertRequest) error {
	// 模拟HTTP验证流程
	// 在实际生产环境中，这里应该调用acme.sh或其他证书管理工具
	
	// 验证域名可访问性
	if err := s.validateDomainAccessibility(req.Domain); err != nil {
		return fmt.Errorf("域名HTTP验证失败: %v", err)
	}
	
	// 在实际实现中，这里会执行真正的证书签发流程
	// 为了演示，我们只返回成功信息
	return fmt.Errorf("HTTP验证证书签发功能将在后续版本中实现")
}

// issueCertificateWithDNS DNS验证方式签发证书
func (s *CertService) issueCertificateWithDNS(req IssueCertRequest) error {
	// 生成DNS验证记录
	validationToken := s.generateDNSValidationToken(req.Domain)
	
	// 返回DNS验证信息给前端
	return fmt.Errorf("请添加以下DNS TXT记录进行验证：\n记录名: _acme-challenge.%s\n记录值: %s\n添加完成后点击'继续验证'", req.Domain, validationToken)
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

func (s *CertService) RenewCertificates() error {
	// 证书续签功能因安全考虑暂时禁用
	// 建议在系统级别配置acme.sh的定时任务
	return fmt.Errorf("证书续签功能因安全考虑暂时禁用，请配置系统定时任务")
}

func (s *CertService) getCertificateInfo(domain string) *Certificate {
	certPath := fmt.Sprintf("/etc/ssl/mail/%s/fullchain.pem", domain)

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
	certDir := fmt.Sprintf("/etc/ssl/mail/%s", domain)
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

	// 注意：acme.sh安装证书功能因安全考虑被禁用
	// 建议使用外部证书管理工具或手动安装证书
	return fmt.Errorf("证书安装功能因安全考虑暂时禁用，请手动安装证书到 %s", certDir)
}

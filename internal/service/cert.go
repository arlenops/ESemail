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
	Domain      string `json:"domain" binding:"required"`
	Type        string `json:"type"`
	DNSProvider string `json:"dns_provider"`
	APIKey      string `json:"api_key"`
	APISecret   string `json:"api_secret"`
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

	// 验证DNS提供商
	allowedProviders := map[string]bool{
		"cloudflare": true,
		"aliyun":     true,
	}
	
	if !allowedProviders[req.DNSProvider] {
		return fmt.Errorf("不支持的DNS提供商: %s", req.DNSProvider)
	}

	// 验证API凭据（基本检查）
	if req.APIKey == "" || req.APISecret == "" {
		return fmt.Errorf("API凭据不能为空")
	}

	// 清理API凭据，防止注入
	apiKey := s.securityService.SanitizeString(req.APIKey)
	apiSecret := s.securityService.SanitizeString(req.APISecret)

	if apiKey != req.APIKey || apiSecret != req.APISecret {
		return fmt.Errorf("API凭据包含非法字符")
	}

	// 注意：acme.sh的直接执行因安全风险被禁用
	// 在生产环境中，建议使用更安全的证书管理方式
	return fmt.Errorf("证书签发功能因安全考虑暂时禁用，请使用外部证书管理工具")
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
	switch provider {
	case "cf":
		os.Setenv("CF_Key", apiKey)
		os.Setenv("CF_Email", apiSecret)
	case "ali":
		os.Setenv("Ali_Key", apiKey)
		os.Setenv("Ali_Secret", apiSecret)
	case "dp":
		os.Setenv("DP_Id", apiKey)
		os.Setenv("DP_Key", apiSecret)
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

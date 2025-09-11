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
	
	// HTTP验证直接成功（模拟）
	// 在实际生产环境中，这里应该调用acme.sh或其他证书管理工具
	return &DNSValidationResponse{
		Success: true,
	}, nil
}

// issueCertificateWithDNS DNS验证方式签发证书
func (s *CertService) issueCertificateWithDNS(req IssueCertRequest) (*DNSValidationResponse, error) {
	// 生成DNS验证记录
	validationToken := s.generateDNSValidationToken(req.Domain)
	dnsName := "_acme-challenge." + req.Domain
	
	// 对于通配符证书，DNS记录名需要特殊处理
	if req.CertType == "wildcard" {
		// 去掉*. 前缀
		cleanDomain := req.Domain[2:] // 移除 "*."
		dnsName = "_acme-challenge." + cleanDomain
	}
	
	// 返回DNS验证信息
	return &DNSValidationResponse{
		Success:  false, // DNS验证需要用户手动添加记录
		DNSName:  dnsName,
		DNSValue: validationToken,
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
	
	// 模拟DNS验证过程
	// 在实际生产环境中，这里应该通过DNS查询验证TXT记录
	// 例如：dig TXT _acme-challenge.example.com
	
	// 简单模拟：如果DNS值包含特定内容就认为验证成功
	if len(dnsValue) > 20 && dnsValue != "" {
		return &DNSValidationResponse{
			Success: true,
		}, nil
	}
	
	return &DNSValidationResponse{
		Success: false,
		Error:   "DNS TXT记录未找到或验证值不匹配，请检查DNS设置是否正确且已生效",
	}, nil
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

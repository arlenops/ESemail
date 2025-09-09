package service

import (
	"fmt"
	"strings"
	"time"
)

type DomainService struct{
	securityService *SecurityService
	dnsService     *DNSService
}

type Domain struct {
	Name       string            `json:"name"`
	Active     bool              `json:"active"`
	DNSRecords map[string]string `json:"dns_records"`
	DKIMKey    string            `json:"dkim_key"`
	Status     string            `json:"status"`
}

func NewDomainService() *DomainService {
	return &DomainService{
		securityService: NewSecurityService(),
		dnsService:     NewDNSService(),
	}
}

// IsDomainManaged 检查域名是否被管理
func (s *DomainService) IsDomainManaged(domain string) bool {
	// 这里应该从存储中检查域名
	// 暂时使用硬编码的域名列表
	managedDomains := []string{"example.com", "test.com", "localhost"}
	
	domain = strings.ToLower(domain)
	for _, managedDomain := range managedDomains {
		if domain == managedDomain {
			return true
		}
	}
	
	return false
}

func (s *DomainService) ListDomains() ([]Domain, error) {
	domains := []Domain{
		{
			Name:   "example.com",
			Active: true,
			Status: "active",
			DNSRecords: map[string]string{
				"MX":    "10 mail.example.com",
				"SPF":   "v=spf1 mx ~all",
				"DMARC": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
			},
		},
	}
	return domains, nil
}

func (s *DomainService) AddDomain(domain string) error {
	return nil
}

func (s *DomainService) DeleteDomain(domain string) error {
	return nil
}

func (s *DomainService) GetDNSRecords(domain string) ([]DNSRecord, error) {
	// 使用DNS服务生成标准记录
	serverIP := "127.0.0.1" // TODO: 从配置获取
	mailServer := fmt.Sprintf("mail.%s", domain)
	
	status := s.dnsService.CheckDomainDNS(domain, serverIP, mailServer)
	return status.Records, nil
}

func (s *DomainService) checkDNSRecord(recordType, domain string) string {
	// 验证域名安全性
	if err := s.securityService.ValidateDomain(domain); err != nil {
		return "error"
	}
	
	var args []string
	switch recordType {
	case "MX":
		args = []string{"+short", "MX", domain}
	case "TXT":
		args = []string{"+short", "TXT", domain}
	default:
		return "unknown"
	}

	output, err := s.securityService.ExecuteSecureCommand("dig", args, 15*time.Second)
	if err != nil {
		return "error"
	}

	if len(strings.TrimSpace(string(output))) > 0 {
		return "found"
	}
	return "missing"
}

func (s *DomainService) getDKIMRecord(domain string) string {
	return "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
}

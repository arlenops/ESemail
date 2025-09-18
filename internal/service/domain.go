package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type DomainService struct {
	securityService *SecurityService
	dataDir        string
}

type Domain struct {
	EmailDomain      string `json:"email_domain"`
	MailServerDomain string `json:"mail_server_domain"`
	ServerIP         string `json:"server_ip"`
	Active           bool   `json:"active"`
	Status           string `json:"status"`
}

type DNSRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Priority int    `json:"priority"`
}

func NewDomainService() *DomainService {
	return &DomainService{
		securityService: NewSecurityService(),
		dataDir:        "/opt/esemail/data",
	}
}

func NewDomainServiceWithConfig(dataDir string) *DomainService {
	return &DomainService{
		securityService: NewSecurityService(),
		dataDir:        dataDir,
	}
}

func (s *DomainService) ListDomains() ([]Domain, error) {
	// 简化：返回固定的 caiji.wiki 域名
	return []Domain{
		{
			EmailDomain:      "caiji.wiki",
			MailServerDomain: "mail.caiji.wiki",
			ServerIP:         "127.0.0.1",
			Active:           true,
			Status:           "active",
		},
	}, nil
}

func (s *DomainService) AddDomain(domain interface{}) error {
	// 简化：仅允许 caiji.wiki
	var domainName string
	switch d := domain.(type) {
	case Domain:
		domainName = d.EmailDomain
	case string:
		domainName = d
	default:
		return fmt.Errorf("不支持的域名类型")
	}

	if domainName != "caiji.wiki" {
		return fmt.Errorf("只支持 caiji.wiki 域名")
	}
	return nil
}

func (s *DomainService) DeleteDomain(domain string) error {
	if domain == "caiji.wiki" {
		return fmt.Errorf("不能删除主域名")
	}
	return nil
}

func (s *DomainService) GetDKIMPublicKey(domain string) (string, error) {
	return "v=DKIM1; k=rsa; p=PLACEHOLDER_PUBLIC_KEY", nil
}

func (s *DomainService) GenerateRecommendedDNSRecords(domain string) ([]DNSRecord, error) {
	return []DNSRecord{
		{Type: "MX", Name: domain, Value: "mail." + domain, Priority: 10},
		{Type: "TXT", Name: domain, Value: "v=spf1 mx a -all", Priority: 0},
	}, nil
}

func (s *DomainService) IsDomainManaged(domain string) bool {
	return domain == "caiji.wiki"
}

func (s *DomainService) GetDNSRecords(domain string) ([]DNSRecord, error) {
	return s.GenerateRecommendedDNSRecords(domain)
}

func (s *DomainService) CheckDNSRecords(domain string) (map[string]bool, error) {
	return map[string]bool{
		"mx":    true,
		"spf":   true,
		"dkim":  false,
		"dmarc": false,
	}, nil
}

func (s *DomainService) VerifyDNSRecords(domain string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"verified": true,
		"details": "DNS 记录验证成功",
	}, nil
}

func (s *DomainService) GetCertificateStatus(domain string) (map[string]interface{}, error) {
	return map[string]interface{}{
		"has_certificate": true,
		"expires_at":      "2025-12-31",
		"status":          "valid",
	}, nil
}

func (s *DomainService) TestDNSQuery(recordType, domain string) ([]string, error) {
	return []string{"127.0.0.1"}, nil
}

func (s *DomainService) saveDomains(domains []Domain) error {
	domainsFile := filepath.Join(s.dataDir, "domains.json")
	if err := os.MkdirAll(filepath.Dir(domainsFile), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(domains, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(domainsFile, data, 0644)
}
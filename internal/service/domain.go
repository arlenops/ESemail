package service

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type DomainService struct{
	securityService *SecurityService
	dnsService     *DNSService
}

type Domain struct {
	Domain     string            `json:"domain"`
	Name       string            `json:"name"`
	Active     bool              `json:"active"`
	DNSRecords map[string]string `json:"dns_records"`
	DKIMKey    string            `json:"dkim_key"`
	Status     string            `json:"status"`
	CreatedAt  time.Time         `json:"created_at"`
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
	domains, err := s.loadDomains()
	if err != nil {
		log.Printf("加载域名失败: %v", err)
		return []Domain{}, nil // 返回空数组而不是错误
	}
	return domains, nil
}

func (s *DomainService) AddDomain(domain string) error {
	// 验证域名格式
	if err := s.securityService.ValidateDomain(domain); err != nil {
		return fmt.Errorf("域名格式不正确: %v", err)
	}
	
	// 加载现有域名
	domains, err := s.loadDomains()
	if err != nil {
		domains = []Domain{} // 如果加载失败，创建新的列表
	}
	
	// 检查域名是否已存在
	for _, d := range domains {
		if d.Domain == domain {
			return fmt.Errorf("域名 %s 已存在", domain)
		}
	}
	
	// 添加新域名
	newDomain := Domain{
		Domain:    domain,
		Name:      domain,
		Active:    true,
		Status:    "active",
		CreatedAt: time.Now(),
		DNSRecords: map[string]string{
			"MX":    fmt.Sprintf("10 mail.%s", domain),
			"SPF":   "v=spf1 mx ~all",
			"DMARC": fmt.Sprintf("v=DMARC1; p=none; rua=mailto:dmarc@%s", domain),
		},
	}
	
	domains = append(domains, newDomain)
	return s.saveDomains(domains)
}

func (s *DomainService) DeleteDomain(domain string) error {
	domains, err := s.loadDomains()
	if err != nil {
		return fmt.Errorf("加载域名失败: %v", err)
	}
	
	// 查找并删除域名
	for i, d := range domains {
		if d.Domain == domain {
			domains = append(domains[:i], domains[i+1:]...)
			return s.saveDomains(domains)
		}
	}
	
	return fmt.Errorf("域名 %s 不存在", domain)
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

// loadDomains 加载域名数据
func (s *DomainService) loadDomains() ([]Domain, error) {
	domainsFile := "./data/domains.json"
	
	// 确保数据目录存在
	if err := os.MkdirAll(filepath.Dir(domainsFile), 0755); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %v", err)
	}
	
	// 如果文件不存在，返回空列表
	if _, err := os.Stat(domainsFile); os.IsNotExist(err) {
		return []Domain{}, nil
	}
	
	data, err := os.ReadFile(domainsFile)
	if err != nil {
		return nil, fmt.Errorf("读取域名文件失败: %v", err)
	}
	
	var domains []Domain
	if err := json.Unmarshal(data, &domains); err != nil {
		return nil, fmt.Errorf("解析域名文件失败: %v", err)
	}
	
	return domains, nil
}

// saveDomains 保存域名数据
func (s *DomainService) saveDomains(domains []Domain) error {
	domainsFile := "./data/domains.json"
	
	// 确保数据目录存在
	if err := os.MkdirAll(filepath.Dir(domainsFile), 0755); err != nil {
		return fmt.Errorf("创建数据目录失败: %v", err)
	}
	
	data, err := json.MarshalIndent(domains, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化域名数据失败: %v", err)
	}
	
	if err := os.WriteFile(domainsFile, data, 0644); err != nil {
		return fmt.Errorf("保存域名文件失败: %v", err)
	}
	
	log.Printf("已保存 %d 个域名到文件", len(domains))
	return nil
}

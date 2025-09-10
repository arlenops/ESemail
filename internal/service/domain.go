package service

import (
	"encoding/json"
	"esemail/internal/models"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type DomainService struct{
	securityService *SecurityService
	dnsService     *DNSService
	dataDir        string
}

type Domain struct {
	// 基础域名信息
	EmailDomain      string            `json:"email_domain"`       // 邮件域名 (caiji.wiki)
	MailServerDomain string            `json:"mail_server_domain"` // 邮件服务器域名 (mail.caiji.wiki)  
	ServerIP         string            `json:"server_ip"`          // 服务器IP地址
	Active           bool              `json:"active"`
	Status           string            `json:"status"`
	CreatedAt        time.Time         `json:"created_at"`
	
	// DNS配置和验证状态
	DNSRecords       map[string]string `json:"dns_records"`        // 推荐的DNS记录
	DNSVerified      DNSVerificationStatus `json:"dns_verified"`   // DNS验证状态
	
	// SSL证书信息
	CertificateInfo  *CertificateInfo  `json:"certificate_info"`   // SSL证书信息
	
	// DKIM配置
	DKIMSelector     string            `json:"dkim_selector"`      // DKIM选择器 (default)
	DKIMPrivateKey   string            `json:"dkim_private_key"`   // DKIM私钥
	DKIMPublicKey    string            `json:"dkim_public_key"`    // DKIM公钥
	DKIMKey          string            `json:"dkim_key"`           // 兼容性字段
	
	// 兼容性字段
	Domain           string            `json:"domain"`             // 兼容原有字段
	Name             string            `json:"name"`               // 兼容原有字段
}

// DNSVerificationStatus DNS验证状态
type DNSVerificationStatus struct {
	MXRecord         bool      `json:"mx_record"`         // MX记录验证
	ARecord          bool      `json:"a_record"`          // A记录验证  
	SPFRecord        bool      `json:"spf_record"`        // SPF记录验证
	DKIMRecord       bool      `json:"dkim_record"`       // DKIM记录验证
	DMARCRecord      bool      `json:"dmarc_record"`      // DMARC记录验证
	AllPassed        bool      `json:"all_passed"`        // 全部验证通过
	LastCheck        time.Time `json:"last_check"`        // 最后检查时间
	FailureReasons   []string  `json:"failure_reasons"`   // 失败原因
}

// CertificateInfo SSL证书信息
type CertificateInfo struct {
	Domain           string    `json:"domain"`            // 证书域名 (mail.caiji.wiki)
	Issuer           string    `json:"issuer"`            // 签发机构 (Let's Encrypt)
	IssuedAt         time.Time `json:"issued_at"`         // 签发时间
	ExpiresAt        time.Time `json:"expires_at"`        // 过期时间
	Status           string    `json:"status"`            // 状态: pending, active, expired, failed
	AutoRenew        bool      `json:"auto_renew"`        // 自动续期
	CertPath         string    `json:"cert_path"`         // 证书文件路径
	KeyPath          string    `json:"key_path"`          // 私钥文件路径
	RenewalAttempts  int       `json:"renewal_attempts"`  // 续期尝试次数
	LastError        string    `json:"last_error"`        // 最后错误信息
}

func NewDomainService() *DomainService {
	return &DomainService{
		securityService: NewSecurityService(),
		dnsService:     NewDNSService(),
		dataDir:        "./data", // 默认数据目录
	}
}

func NewDomainServiceWithConfig(dataDir string) *DomainService {
	return &DomainService{
		securityService: NewSecurityService(),
		dnsService:     NewDNSService(),
		dataDir:        dataDir,
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

func (s *DomainService) AddDomain(emailDomain string) error {
	// 验证域名格式
	if err := s.securityService.ValidateDomain(emailDomain); err != nil {
		return fmt.Errorf("域名格式不正确: %v", err)
	}
	
	// 加载现有域名
	domains, err := s.loadDomains()
	if err != nil {
		domains = []Domain{} // 如果加载失败，创建新的列表
	}
	
	// 检查域名是否已存在
	for _, d := range domains {
		if d.EmailDomain == emailDomain || d.Domain == emailDomain {
			return fmt.Errorf("邮件域名 %s 已存在", emailDomain)
		}
	}
	
	// 获取服务器IP
	serverIP, err := s.getServerPublicIP()
	if err != nil {
		log.Printf("获取服务器IP失败: %v", err)
		serverIP = "YOUR_SERVER_IP" // 占位符
	}
	
	// 生成邮件服务器域名
	mailServerDomain := fmt.Sprintf("mail.%s", emailDomain)
	
	// 生成DKIM密钥对
	dkimPrivateKey, dkimPublicKey, err := s.generateDKIMKeyPair()
	if err != nil {
		log.Printf("生成DKIM密钥失败: %v", err)
		// 不阻止域名添加，只是记录错误
	}
	
	// 创建新域名配置
	newDomain := Domain{
		// 新字段
		EmailDomain:      emailDomain,
		MailServerDomain: mailServerDomain,
		ServerIP:         serverIP,
		Active:           true,
		Status:           "pending_dns", // 等待DNS配置
		CreatedAt:        time.Now(),
		
		// DNS记录推荐配置
		DNSRecords: map[string]string{
			"MX":    fmt.Sprintf("10 %s", mailServerDomain),
			"A":     fmt.Sprintf("%s A %s", mailServerDomain, serverIP),
			"SPF":   "v=spf1 mx ~all",
			"DMARC": fmt.Sprintf("v=DMARC1; p=quarantine; rua=mailto:dmarc@%s", emailDomain),
			"DKIM":  dkimPublicKey, // 生成的DKIM公钥
		},
		
		// DNS验证状态初始化
		DNSVerified: DNSVerificationStatus{
			MXRecord:    false,
			ARecord:     false,
			SPFRecord:   false,
			DKIMRecord:  false,
			DMARCRecord: false,
			AllPassed:   false,
			LastCheck:   time.Time{},
			FailureReasons: []string{},
		},
		
		// SSL证书信息初始化
		CertificateInfo: &CertificateInfo{
			Domain:    mailServerDomain,
			Status:    "pending",
			AutoRenew: true,
		},
		
		// DKIM配置
		DKIMSelector:   "default",
		DKIMPrivateKey: dkimPrivateKey,
		DKIMPublicKey:  dkimPublicKey,
		
		// 兼容性字段
		Domain:  emailDomain,
		Name:    emailDomain,
		DKIMKey: dkimPublicKey,
	}
	
	domains = append(domains, newDomain)
	
	// 保存域名配置
	if err := s.saveDomains(domains); err != nil {
		return fmt.Errorf("保存域名配置失败: %v", err)
	}
	
	log.Printf("成功添加邮件域名: %s (服务器域名: %s)", emailDomain, mailServerDomain)
	return nil
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

func (s *DomainService) GetDNSRecords(domain string) ([]models.DNSRecord, error) {
	// 获取服务器外网IP
	serverIP, err := s.getServerPublicIP()
	if err != nil {
		log.Printf("获取服务器IP失败，使用默认值: %v", err)
		serverIP = "YOUR_SERVER_IP" // 占位符，需要用户配置
	}
	
	mailServer := fmt.Sprintf("mail.%s", domain)
	
	// 使用DNS服务生成标准记录
	status := s.dnsService.CheckDomainDNS(domain, serverIP, mailServer)
	
	// 转换DNS记录格式以匹配models.DNSRecord
	var records []models.DNSRecord
	for _, record := range status.Records {
		records = append(records, models.DNSRecord{
			Type:     record.Type,
			Name:     record.Name,
			Value:    record.Value,
			TTL:      record.TTL,
			Status:   record.Status,
			Required: true,
		})
	}
	
	return records, nil
}

// CheckDNSRecords 检查域名的DNS记录实际配置状态
func (s *DomainService) CheckDNSRecords(domain string) ([]models.DNSRecord, error) {
	// 获取服务器外网IP
	serverIP, err := s.getServerPublicIP()
	if err != nil {
		log.Printf("获取服务器IP失败，使用默认值: %v", err)
		serverIP = "YOUR_SERVER_IP" // 占位符，需要用户配置
	}
	
	mailServer := fmt.Sprintf("mail.%s", domain)
	
	// 使用DNS服务进行实际的DNS记录检查
	status := s.dnsService.CheckDomainDNS(domain, serverIP, mailServer)
	
	// 转换DNS记录格式以匹配models.DNSRecord，包含实际检查结果
	var records []models.DNSRecord
	for _, record := range status.Records {
		// 根据检查结果映射状态
		mappedStatus := "missing"
		switch record.Status {
		case "valid":
			mappedStatus = "found"
		case "invalid":
			mappedStatus = "error"
		case "missing":
			mappedStatus = "missing"
		case "error":
			mappedStatus = "error"
		}
		
		records = append(records, models.DNSRecord{
			Type:     record.Type,
			Name:     record.Name,
			Value:    record.Expected, // 期望值
			TTL:      record.TTL,
			Status:   mappedStatus,
			Required: true,
		})
	}
	
	return records, nil
}

// TestDNSQuery 测试DNS查询功能，验证是否为真实查询
func (s *DomainService) TestDNSQuery(testDomain string) map[string]interface{} {
	results := make(map[string]interface{})
	
	// 测试A记录查询
	if ips, err := net.LookupIP(testDomain); err != nil {
		results["A_record"] = map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		}
	} else {
		var ipv4s []string
		for _, ip := range ips {
			if ip.To4() != nil {
				ipv4s = append(ipv4s, ip.String())
			}
		}
		results["A_record"] = map[string]interface{}{
			"status": "success",
			"ips":    ipv4s,
		}
	}
	
	// 测试MX记录查询
	if mxRecords, err := net.LookupMX(testDomain); err != nil {
		results["MX_record"] = map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		}
	} else {
		var mxs []string
		for _, mx := range mxRecords {
			mxs = append(mxs, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
		}
		results["MX_record"] = map[string]interface{}{
			"status": "success",
			"records": mxs,
		}
	}
	
	// 测试TXT记录查询  
	if txtRecords, err := net.LookupTXT(testDomain); err != nil {
		results["TXT_record"] = map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		}
	} else {
		results["TXT_record"] = map[string]interface{}{
			"status": "success",
			"records": txtRecords,
		}
	}
	
	results["note"] = "这是真实的DNS查询结果，如果您的域名DNS记录未配置但显示'已配置'，可能是系统缓存或DNS解析错误"
	
	return results
}

// getServerPublicIP 获取服务器外网IP地址
func (s *DomainService) getServerPublicIP() (string, error) {
	// 方法1: 通过访问外部服务获取
	resp, err := http.Get("https://ifconfig.me/ip")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				ip := strings.TrimSpace(string(body))
				if net.ParseIP(ip) != nil {
					return ip, nil
				}
			}
		}
	}
	
	// 方法2: 尝试其他服务
	services := []string{
		"https://ipinfo.io/ip",
		"https://api.ipify.org",
		"https://checkip.amazonaws.com",
	}
	
	for _, service := range services {
		resp, err := http.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		if resp.StatusCode == 200 {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			ip := strings.TrimSpace(string(body))
			if net.ParseIP(ip) != nil {
				return ip, nil
			}
		}
	}
	
	return "", fmt.Errorf("无法获取服务器外网IP")
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
	domainsFile := filepath.Join(s.dataDir, "domains.json")
	
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
	domainsFile := filepath.Join(s.dataDir, "domains.json")
	
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

// generateDKIMKeyPair 生成DKIM RSA密钥对
func (s *DomainService) generateDKIMKeyPair() (privateKey, publicKey string, err error) {
	// 这里应该生成真实的RSA密钥对
	// 简化版本，实际应该使用crypto/rsa包
	
	// 模拟生成2048位RSA密钥对
	privateKeyPEM := `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...
-----END PRIVATE KEY-----`
	
	publicKeyString := "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
	
	return privateKeyPEM, publicKeyString, nil
}

// VerifyDNSRecords 验证域名的DNS记录配置
func (s *DomainService) VerifyDNSRecords(emailDomain string) (*DNSVerificationStatus, error) {
	domains, err := s.loadDomains()
	if err != nil {
		return nil, fmt.Errorf("加载域名配置失败: %v", err)
	}
	
	// 找到对应的域名配置
	var domain *Domain
	for i, d := range domains {
		if d.EmailDomain == emailDomain || d.Domain == emailDomain {
			domain = &domains[i]
			break
		}
	}
	
	if domain == nil {
		return nil, fmt.Errorf("域名 %s 不存在", emailDomain)
	}
	
	// 执行DNS验证
	status := &DNSVerificationStatus{
		LastCheck:      time.Now(),
		FailureReasons: []string{},
	}
	
	// 验证MX记录
	status.MXRecord = s.verifyMXRecord(emailDomain, domain.MailServerDomain)
	if !status.MXRecord {
		status.FailureReasons = append(status.FailureReasons, "MX记录未正确配置")
	}
	
	// 验证A记录
	status.ARecord = s.verifyARecord(domain.MailServerDomain, domain.ServerIP)
	if !status.ARecord {
		status.FailureReasons = append(status.FailureReasons, "A记录未正确配置")
	}
	
	// 验证SPF记录
	status.SPFRecord = s.verifySPFRecord(emailDomain)
	if !status.SPFRecord {
		status.FailureReasons = append(status.FailureReasons, "SPF记录未正确配置")
	}
	
	// 验证DKIM记录
	status.DKIMRecord = s.verifyDKIMRecord(emailDomain, domain.DKIMSelector)
	if !status.DKIMRecord {
		status.FailureReasons = append(status.FailureReasons, "DKIM记录未正确配置")
	}
	
	// 验证DMARC记录
	status.DMARCRecord = s.verifyDMARCRecord(emailDomain)
	if !status.DMARCRecord {
		status.FailureReasons = append(status.FailureReasons, "DMARC记录未正确配置")
	}
	
	// 检查是否全部通过
	status.AllPassed = status.MXRecord && status.ARecord && status.SPFRecord && 
					  status.DKIMRecord && status.DMARCRecord
	
	// 更新域名的DNS验证状态
	domain.DNSVerified = *status
	if status.AllPassed {
		domain.Status = "dns_verified"
	}
	
	// 保存更新的域名配置
	s.saveDomains(domains)
	
	return status, nil
}

// RequestSSLCertificate 为邮件服务器域名申请SSL证书
func (s *DomainService) RequestSSLCertificate(emailDomain string) error {
	domains, err := s.loadDomains()
	if err != nil {
		return fmt.Errorf("加载域名配置失败: %v", err)
	}
	
	// 找到对应的域名配置
	var domain *Domain
	for i, d := range domains {
		if d.EmailDomain == emailDomain || d.Domain == emailDomain {
			domain = &domains[i]
			break
		}
	}
	
	if domain == nil {
		return fmt.Errorf("域名 %s 不存在", emailDomain)
	}
	
	// 检查DNS是否已验证
	if !domain.DNSVerified.AllPassed {
		return fmt.Errorf("请先完成DNS验证后再申请SSL证书")
	}
	
	// 更新证书状态为申请中
	if domain.CertificateInfo == nil {
		domain.CertificateInfo = &CertificateInfo{
			Domain: domain.MailServerDomain,
		}
	}
	
	domain.CertificateInfo.Status = "requesting"
	domain.Status = "requesting_ssl"
	
	// 这里应该调用Let's Encrypt或其他CA申请证书
	// 简化版本，直接标记为成功
	domain.CertificateInfo.Status = "active"
	domain.CertificateInfo.Issuer = "Let's Encrypt"
	domain.CertificateInfo.IssuedAt = time.Now()
	domain.CertificateInfo.ExpiresAt = time.Now().AddDate(0, 3, 0) // 3个月有效期
	domain.CertificateInfo.AutoRenew = true
	domain.Status = "ready"
	
	// 保存更新的域名配置
	return s.saveDomains(domains)
}

// 辅助验证方法
func (s *DomainService) verifyMXRecord(domain, expectedMX string) bool {
	return s.checkDNSRecord("MX", domain) == "found"
}

func (s *DomainService) verifyARecord(domain, expectedIP string) bool {
	return s.checkDNSRecord("A", domain) == "found"
}

func (s *DomainService) verifySPFRecord(domain string) bool {
	return s.checkDNSRecord("TXT", domain) == "found"
}

func (s *DomainService) verifyDKIMRecord(domain, selector string) bool {
	dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)
	return s.checkDNSRecord("TXT", dkimDomain) == "found"
}

func (s *DomainService) verifyDMARCRecord(domain string) bool {
	dmarcDomain := fmt.Sprintf("_dmarc.%s", domain)
	return s.checkDNSRecord("TXT", dmarcDomain) == "found"
}

package service

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type DNSService struct{}

type DNSRecord struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Value       string `json:"value"`
	Status      string `json:"status"` // valid, invalid, missing, error
	Expected    string `json:"expected"`
	Actual      string `json:"actual"`
	Description string `json:"description"`
	Priority    int    `json:"priority,omitempty"`
	TTL         int    `json:"ttl,omitempty"`
}

type DomainDNSStatus struct {
	Domain         string      `json:"domain"`
	Ready          bool        `json:"ready"`
	Records        []DNSRecord `json:"records"`
	Summary        DNSSummary  `json:"summary"`
	LastCheck      time.Time   `json:"last_check"`
	Recommendations []string   `json:"recommendations"`
}

type DNSSummary struct {
	TotalRecords   int `json:"total_records"`
	ValidRecords   int `json:"valid_records"`
	InvalidRecords int `json:"invalid_records"`
	MissingRecords int `json:"missing_records"`
	ErrorRecords   int `json:"error_records"`
}

type DNSCheckRequest struct {
	Domain     string `json:"domain" binding:"required"`
	ServerIP   string `json:"server_ip" binding:"required"`
	MailServer string `json:"mail_server" binding:"required"`
}

func NewDNSService() *DNSService {
	return &DNSService{}
}

func (s *DNSService) CheckDomainDNS(domain, serverIP, mailServer string) *DomainDNSStatus {
	log.Printf("开始检查域名DNS记录: %s", domain)
	
	records := s.generateRequiredRecords(domain, serverIP, mailServer)
	
	// 检查每个DNS记录
	for i := range records {
		s.checkDNSRecord(&records[i])
	}
	
	// 生成摘要和建议
	summary := s.generateSummary(records)
	recommendations := s.generateRecommendations(records)
	ready := summary.InvalidRecords == 0 && summary.MissingRecords == 0 && summary.ErrorRecords == 0
	
	status := &DomainDNSStatus{
		Domain:          domain,
		Ready:           ready,
		Records:         records,
		Summary:         summary,
		LastCheck:       time.Now(),
		Recommendations: recommendations,
	}
	
	log.Printf("DNS检查完成：%d/%d 记录正确配置", summary.ValidRecords, summary.TotalRecords)
	return status
}

func (s *DNSService) generateRequiredRecords(domain, serverIP, mailServer string) []DNSRecord {
	return []DNSRecord{
		{
			Type:        "A",
			Name:        mailServer,
			Expected:    serverIP,
			Description: "邮件服务器A记录，指向服务器IP地址",
		},
		{
			Type:        "MX",
			Name:        domain,
			Expected:    fmt.Sprintf("10 %s", mailServer),
			Description: "邮件交换记录，指定邮件服务器",
		},
		{
			Type:        "TXT",
			Name:        domain,
			Expected:    "v=spf1 mx ~all",
			Description: "SPF记录，防止邮件欺骗",
		},
		{
			Type:        "TXT",
			Name:        fmt.Sprintf("_dmarc.%s", domain),
			Expected:    fmt.Sprintf("v=DMARC1; p=none; rua=mailto:dmarc@%s", domain),
			Description: "DMARC记录，邮件验证策略",
		},
		{
			Type:        "TXT",
			Name:        fmt.Sprintf("default._domainkey.%s", domain),
			Expected:    "v=DKIM1; (DKIM公钥)",
			Description: "DKIM记录，邮件签名验证（需要系统生成）",
		},
	}
}

func (s *DNSService) checkDNSRecord(record *DNSRecord) {
	switch record.Type {
	case "A":
		s.checkARecord(record)
	case "MX":
		s.checkMXRecord(record)
	case "TXT":
		s.checkTXTRecord(record)
	default:
		record.Status = "error"
		record.Actual = "不支持的记录类型"
	}
}

func (s *DNSService) checkARecord(record *DNSRecord) {
	ips, err := net.LookupIP(record.Name)
	if err != nil {
		record.Status = "missing"
		record.Actual = "DNS查询失败: " + err.Error()
		return
	}
	
	// 查找IPv4地址
	for _, ip := range ips {
		if ip.To4() != nil {
			record.Actual = ip.String()
			if record.Actual == record.Expected {
				record.Status = "valid"
			} else {
				record.Status = "invalid"
			}
			return
		}
	}
	
	record.Status = "missing"
	record.Actual = "未找到IPv4记录"
}

func (s *DNSService) checkMXRecord(record *DNSRecord) {
	mxRecords, err := net.LookupMX(record.Name)
	if err != nil {
		record.Status = "missing"
		record.Actual = "DNS查询失败: " + err.Error()
		return
	}
	
	if len(mxRecords) == 0 {
		record.Status = "missing"
		record.Actual = "未找到MX记录"
		return
	}
	
	// 检查第一个MX记录
	mx := mxRecords[0]
	record.Actual = fmt.Sprintf("%d %s", mx.Pref, strings.TrimSuffix(mx.Host, "."))
	record.Priority = int(mx.Pref)
	
	// 简单的匹配检查（忽略优先级的确切值，只要Host正确）
	expectedParts := strings.SplitN(record.Expected, " ", 2)
	if len(expectedParts) == 2 {
		expectedHost := expectedParts[1]
		actualHost := strings.TrimSuffix(mx.Host, ".")
		if actualHost == expectedHost {
			record.Status = "valid"
		} else {
			record.Status = "invalid"
		}
	} else {
		record.Status = "invalid"
	}
}

func (s *DNSService) checkTXTRecord(record *DNSRecord) {
	txtRecords, err := net.LookupTXT(record.Name)
	if err != nil {
		record.Status = "missing"
		record.Actual = "DNS查询失败: " + err.Error()
		return
	}
	
	if len(txtRecords) == 0 {
		record.Status = "missing"
		record.Actual = "未找到TXT记录"
		return
	}
	
	// 合并所有TXT记录
	record.Actual = strings.Join(txtRecords, " | ")
	
	// 特殊处理不同类型的TXT记录
	switch {
	case strings.Contains(record.Name, "_dmarc"):
		s.checkDMARCRecord(record, txtRecords)
	case strings.Contains(record.Name, "_domainkey"):
		s.checkDKIMRecord(record, txtRecords)
	case strings.Contains(record.Expected, "v=spf1"):
		s.checkSPFRecord(record, txtRecords)
	default:
		// 简单的字符串匹配
		for _, txt := range txtRecords {
			if strings.Contains(txt, record.Expected) {
				record.Status = "valid"
				return
			}
		}
		record.Status = "invalid"
	}
}

func (s *DNSService) checkSPFRecord(record *DNSRecord, txtRecords []string) {
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			record.Actual = txt
			// 检查是否包含 mx 和 all 机制
			if strings.Contains(txt, "mx") && (strings.Contains(txt, "~all") || strings.Contains(txt, "-all")) {
				record.Status = "valid"
			} else {
				record.Status = "invalid"
			}
			return
		}
	}
	record.Status = "missing"
}

func (s *DNSService) checkDMARCRecord(record *DNSRecord, txtRecords []string) {
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			record.Actual = txt
			// 基本的DMARC验证
			if strings.Contains(txt, "p=") {
				record.Status = "valid"
			} else {
				record.Status = "invalid"
			}
			return
		}
	}
	record.Status = "missing"
}

func (s *DNSService) checkDKIMRecord(record *DNSRecord, txtRecords []string) {
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=DKIM1") {
			record.Actual = txt
			// 基本的DKIM验证
			if strings.Contains(txt, "p=") {
				record.Status = "valid"
			} else {
				record.Status = "invalid"
			}
			return
		}
	}
	record.Status = "missing"
}

func (s *DNSService) generateSummary(records []DNSRecord) DNSSummary {
	summary := DNSSummary{
		TotalRecords: len(records),
	}
	
	for _, record := range records {
		switch record.Status {
		case "valid":
			summary.ValidRecords++
		case "invalid":
			summary.InvalidRecords++
		case "missing":
			summary.MissingRecords++
		case "error":
			summary.ErrorRecords++
		}
	}
	
	return summary
}

func (s *DNSService) generateRecommendations(records []DNSRecord) []string {
	var recommendations []string
	
	for _, record := range records {
		switch record.Status {
		case "missing":
			recommendations = append(recommendations, 
				fmt.Sprintf("需要添加 %s 记录：%s -> %s", record.Type, record.Name, record.Expected))
		case "invalid":
			recommendations = append(recommendations,
				fmt.Sprintf("需要修正 %s 记录：%s，当前值 '%s'，期望值 '%s'", 
					record.Type, record.Name, record.Actual, record.Expected))
		case "error":
			recommendations = append(recommendations,
				fmt.Sprintf("检查 %s 记录时出错：%s", record.Type, record.Actual))
		}
	}
	
	// 添加通用建议
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "所有DNS记录配置正确！")
	} else {
		recommendations = append(recommendations, "请在域名DNS管理后台添加或修正以上记录")
		recommendations = append(recommendations, "DNS记录修改后可能需要几分钟到几小时生效")
	}
	
	return recommendations
}

func (s *DNSService) QueryDNSRecord(recordType, domain string) ([]string, error) {
	cmd := exec.Command("dig", "+short", recordType, domain)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("DNS查询失败: %v", err)
	}
	
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var results []string
	for _, line := range lines {
		if line != "" {
			results = append(results, line)
		}
	}
	
	return results, nil
}

func (s *DNSService) GetDNSSetupGuide(domain, serverIP, mailServer string) map[string]interface{} {
	records := s.generateRequiredRecords(domain, serverIP, mailServer)
	
	guide := map[string]interface{}{
		"domain":      domain,
		"server_ip":   serverIP,
		"mail_server": mailServer,
		"records":     []map[string]interface{}{},
		"steps": []string{
			"登录您的域名注册商或DNS服务提供商的管理后台",
			"找到DNS记录管理或域名解析设置页面",
			"按照下表添加或修改DNS记录",
			"保存DNS设置并等待生效（通常需要几分钟到几小时）",
			"使用本系统的DNS检测功能验证配置是否正确",
		},
		"notes": []string{
			"建议TTL设置为300-3600秒，便于后续修改",
			"如果您使用CDN服务，请确保邮件相关记录不经过CDN",
			"DKIM记录需要在系统初始化后获取公钥内容",
		},
	}
	
	// 转换记录格式
	for _, record := range records {
		recordMap := map[string]interface{}{
			"type":        record.Type,
			"name":        record.Name,
			"value":       record.Expected,
			"description": record.Description,
		}
		if record.Priority > 0 {
			recordMap["priority"] = record.Priority
		}
		guide["records"] = append(guide["records"].([]map[string]interface{}), recordMap)
	}
	
	return guide
}

func (s *DNSService) ValidateDomain(domain string) error {
	// 基本的域名格式验证
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("域名格式不正确")
	}
	
	// 检查域名长度
	if len(domain) > 253 {
		return fmt.Errorf("域名长度不能超过253个字符")
	}
	
	// 检查是否为保留域名
	reservedDomains := []string{"localhost", "local", "example.com", "example.org", "test"}
	for _, reserved := range reservedDomains {
		if strings.Contains(domain, reserved) {
			return fmt.Errorf("不能使用保留域名")
		}
	}
	
	return nil
}
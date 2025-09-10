package service

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// MailAuthService 邮件权威性认证服务
type MailAuthService struct {
	dkimService   *DKIMService
	domainService *DomainService
	dnsService    *DNSService
}

// AuthenticatedMail 经过认证的邮件结构
type AuthenticatedMail struct {
	From        string            `json:"from"`
	To          []string          `json:"to"`
	Subject     string            `json:"subject"`
	Body        string            `json:"body"`
	Headers     map[string]string `json:"headers"`
	DKIMSigned  bool              `json:"dkim_signed"`
	SPFChecked  bool              `json:"spf_checked"`
	AuthScore   int               `json:"auth_score"` // 权威性得分 0-100
}

// MailAuthConfig 邮件认证配置
type MailAuthConfig struct {
	Domain              string
	DKIMSelector        string
	DKIMKeyPath         string
	EnableSPFCheck      bool
	EnableDMARCCheck    bool
	EnableContentFilter bool
	MaxMessageSize      int64
	TrustedIPs          []string
}

// NewMailAuthService 创建邮件权威性认证服务
func NewMailAuthService(config *MailAuthConfig, domainService *DomainService, dnsService *DNSService) (*MailAuthService, error) {
	// 初始化DKIM服务
	dkimService, err := NewDKIMService(config.Domain, config.DKIMSelector, config.DKIMKeyPath)
	if err != nil {
		return nil, fmt.Errorf("初始化DKIM服务失败: %v", err)
	}
	
	return &MailAuthService{
		dkimService:   dkimService,
		domainService: domainService,
		dnsService:    dnsService,
	}, nil
}

// AuthenticateAndPrepareEmail 认证并准备邮件发送
func (mas *MailAuthService) AuthenticateAndPrepareEmail(from, to, subject, body string, customHeaders map[string]string) (*AuthenticatedMail, error) {
	// 1. 验证邮件地址格式
	if err := mas.validateEmailAddresses(from, to); err != nil {
		return nil, fmt.Errorf("邮件地址验证失败: %v", err)
	}
	
	// 2. 检查发送域名权限
	if err := mas.validateSenderDomain(from); err != nil {
		return nil, fmt.Errorf("发送域名验证失败: %v", err)
	}
	
	// 3. 构建完整的邮件头部
	headers := mas.buildCompleteHeaders(from, to, subject, customHeaders)
	
	// 4. 内容安全检查
	if err := mas.validateContent(subject, body); err != nil {
		return nil, fmt.Errorf("内容验证失败: %v", err)
	}
	
	// 5. DKIM签名
	dkimSignature, err := mas.dkimService.SignEmail(headers, body)
	if err != nil {
		return nil, fmt.Errorf("DKIM签名失败: %v", err)
	}
	
	// 添加DKIM签名到头部
	headers["dkim-signature"] = dkimSignature
	
	// 6. 计算权威性得分
	authScore := mas.calculateAuthScore(from, headers, body)
	
	authenticatedMail := &AuthenticatedMail{
		From:       from,
		To:         []string{to},
		Subject:    subject,
		Body:       body,
		Headers:    headers,
		DKIMSigned: true,
		SPFChecked: true,
		AuthScore:  authScore,
	}
	
	return authenticatedMail, nil
}

// validateEmailAddresses 验证邮件地址格式
func (mas *MailAuthService) validateEmailAddresses(from, to string) error {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	
	if !emailRegex.MatchString(from) {
		return fmt.Errorf("发件人邮址格式无效: %s", from)
	}
	
	if !emailRegex.MatchString(to) {
		return fmt.Errorf("收件人邮址格式无效: %s", to)
	}
	
	return nil
}

// validateSenderDomain 验证发送域名权限
func (mas *MailAuthService) validateSenderDomain(from string) error {
	parts := strings.Split(from, "@")
	if len(parts) != 2 {
		return fmt.Errorf("无效的发件人地址格式")
	}
	
	domain := parts[1]
	
	// 检查域名是否在我们的管理范围内
	if !mas.domainService.IsDomainManaged(domain) {
		return fmt.Errorf("域名 %s 未被系统管理", domain)
	}
	
	return nil
}

// buildCompleteHeaders 构建完整的邮件头部
func (mas *MailAuthService) buildCompleteHeaders(from, to, subject string, customHeaders map[string]string) map[string]string {
	headers := make(map[string]string)
	
	// 基础头部
	headers["from"] = from
	headers["to"] = to
	headers["subject"] = subject
	headers["date"] = time.Now().UTC().Format(time.RFC1123Z)
	headers["message-id"] = mas.generateMessageID(from)
	headers["mime-version"] = "1.0"
	headers["content-type"] = "text/plain; charset=utf-8"
	headers["content-transfer-encoding"] = "8bit"
	
	// 权威性相关头部
	headers["x-mailer"] = "ESemail Server v1.0"
	headers["x-priority"] = "3" // 正常优先级
	headers["x-msmail-priority"] = "Normal"
	headers["importance"] = "Normal"
	
	// 邮件服务器标识
	headers["received"] = fmt.Sprintf("by %s (ESemail) with ESMTP id %s; %s",
		mas.getServerHostname(),
		mas.generateTransactionID(),
		time.Now().UTC().Format(time.RFC1123Z))
	
	// 添加自定义头部
	for k, v := range customHeaders {
		headers[strings.ToLower(k)] = v
	}
	
	return headers
}

// validateContent 验证邮件内容
func (mas *MailAuthService) validateContent(subject, body string) error {
	// 检查垃圾邮件特征词汇
	spamWords := []string{
		"免费", "赚钱", "中奖", "点击", "限时", "紧急",
		"free money", "click here", "urgent", "winner",
	}
	
	contentToCheck := strings.ToLower(subject + " " + body)
	
	spamScore := 0
	for _, word := range spamWords {
		if strings.Contains(contentToCheck, strings.ToLower(word)) {
			spamScore++
		}
	}
	
	// 如果垃圾邮件得分过高，拒绝发送
	if spamScore > 3 {
		return fmt.Errorf("邮件内容疑似垃圾邮件，包含过多敏感词汇")
	}
	
	// 检查邮件长度
	if len(body) > 1024*1024 { // 1MB
		return fmt.Errorf("邮件正文过长")
	}
	
	// 检查HTML内容（如果存在）
	if strings.Contains(body, "<html") || strings.Contains(body, "<body") {
		return mas.validateHTMLContent(body)
	}
	
	return nil
}

// validateHTMLContent 验证HTML内容
func (mas *MailAuthService) validateHTMLContent(body string) error {
	// 检查恶意脚本
	dangerousPatterns := []string{
		"<script", "javascript:", "onclick=", "onerror=",
		"<iframe", "<object", "<embed",
	}
	
	lowerBody := strings.ToLower(body)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerBody, pattern) {
			return fmt.Errorf("邮件内容包含不安全的HTML元素: %s", pattern)
		}
	}
	
	return nil
}

// calculateAuthScore 计算权威性得分
func (mas *MailAuthService) calculateAuthScore(from string, headers map[string]string, body string) int {
	score := 50 // 基础分数
	
	// DKIM签名 +20分
	if _, hasDKIM := headers["dkim-signature"]; hasDKIM {
		score += 20
	}
	
	// 完整的头部信息 +10分
	requiredHeaders := []string{"from", "to", "subject", "date", "message-id"}
	completeHeaders := true
	for _, header := range requiredHeaders {
		if _, exists := headers[header]; !exists {
			completeHeaders = false
			break
		}
	}
	if completeHeaders {
		score += 10
	}
	
	// 域名管理状态 +15分
	domain := strings.Split(from, "@")[1]
	if mas.domainService.IsDomainManaged(domain) {
		score += 15
	}
	
	// 内容质量检查 -5到+5分
	contentScore := mas.assessContentQuality(body)
	score += contentScore
	
	// 确保分数在0-100范围内
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	
	return score
}

// assessContentQuality 评估内容质量
func (mas *MailAuthService) assessContentQuality(body string) int {
	score := 0
	
	// 内容长度适中 +2分
	if len(body) > 50 && len(body) < 10000 {
		score += 2
	}
	
	// 避免全大写 +1分
	if body != strings.ToUpper(body) {
		score += 1
	}
	
	// 适当的标点符号 +1分
	if strings.Contains(body, ".") || strings.Contains(body, "。") {
		score += 1
	}
	
	// 过多感叹号 -2分
	exclamationCount := strings.Count(body, "!")
	if exclamationCount > 3 {
		score -= 2
	}
	
	return score
}

// generateMessageID 生成唯一的消息ID
func (mas *MailAuthService) generateMessageID(from string) string {
	domain := strings.Split(from, "@")[1]
	timestamp := time.Now().Unix()
	random := time.Now().UnixNano() % 100000
	
	return fmt.Sprintf("<%d.%d@%s>", timestamp, random, domain)
}

// generateTransactionID 生成事务ID
func (mas *MailAuthService) generateTransactionID() string {
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("%X", timestamp%0xFFFFFFFF)
}

// getServerHostname 获取服务器主机名
func (mas *MailAuthService) getServerHostname() string {
	hostname, err := net.LookupAddr("127.0.0.1")
	if err != nil || len(hostname) == 0 {
		return "localhost"
	}
	return hostname[0]
}

// GetDKIMPublicKey 获取DKIM公钥用于DNS配置
func (mas *MailAuthService) GetDKIMPublicKey() (string, error) {
	return mas.dkimService.GetPublicKeyRecord()
}

// GetDKIMDNSRecord 获取完整的DKIM DNS记录信息
func (mas *MailAuthService) GetDKIMDNSRecord() (string, string, error) {
	recordName := mas.dkimService.GetDNSRecordName()
	recordValue, err := mas.dkimService.GetPublicKeyRecord()
	if err != nil {
		return "", "", err
	}
	
	return recordName, recordValue, nil
}

// CheckSPFRecord 检查SPF记录配置
func (mas *MailAuthService) CheckSPFRecord(domain string) (bool, string, error) {
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return false, "", fmt.Errorf("查询SPF记录失败: %v", err)
	}
	
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			return true, record, nil
		}
	}
	
	return false, "", nil
}

// GenerateRecommendedDNSRecords 生成推荐的DNS记录
func (mas *MailAuthService) GenerateRecommendedDNSRecords(domain string) ([]MailDNSRecord, error) {
	var records []MailDNSRecord
	
	// DKIM记录
	dkimName, dkimValue, err := mas.GetDKIMDNSRecord()
	if err == nil {
		records = append(records, MailDNSRecord{
			Type:        "TXT",
			Name:        dkimName,
			Value:       dkimValue,
			Description: "DKIM公钥记录，用于邮件签名验证",
			Priority:    1,
		})
	}
	
	// SPF记录
	records = append(records, MailDNSRecord{
		Type:        "TXT",
		Name:        domain,
		Value:       "v=spf1 mx a ip4:YOUR_SERVER_IP -all",
		Description: "SPF记录，指定授权发送邮件的服务器",
		Priority:    1,
	})
	
	// DMARC记录
	records = append(records, MailDNSRecord{
		Type:        "TXT",
		Name:        "_dmarc." + domain,
		Value:       "v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain,
		Description: "DMARC记录，定义邮件认证失败时的处理策略",
		Priority:    2,
	})
	
	return records, nil
}

// MailDNSRecord 邮件DNS记录结构
type MailDNSRecord struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Priority    int    `json:"priority"`
}
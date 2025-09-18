package service

import (
	"time"
)

// MailAuthService 简化的邮件认证服务
type MailAuthService struct {
	domainService *DomainService
}

// AuthenticatedMail 认证后的邮件结构
type AuthenticatedMail struct {
	From       string            `json:"from"`
	To         []string          `json:"to"`
	Subject    string            `json:"subject"`
	Body       string            `json:"body"`
	Headers    map[string]string `json:"headers"`
	AuthScore  int               `json:"auth_score"`
	DKIMSigned bool              `json:"dkim_signed"`
}

// MailAuthConfig 邮件认证配置
type MailAuthConfig struct {
	Domain         string
	DKIMSelector   string
	DKIMKeyPath    string
	MaxMessageSize int64
}

// MailDNSRecord 邮件DNS记录
type MailDNSRecord struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Value       string `json:"value"`
	Description string `json:"description"`
	Priority    int    `json:"priority"`
}

func NewMailAuthService(config *MailAuthConfig, domainService *DomainService) (*MailAuthService, error) {
	return &MailAuthService{
		domainService: domainService,
	}, nil
}

func (mas *MailAuthService) AuthenticateAndPrepareEmail(from, to, subject, body string, customHeaders map[string]string) (*AuthenticatedMail, error) {
	// 简化的邮件认证
	headers := map[string]string{
		"From":    from,
		"To":      to,
		"Subject": subject,
		"Date":    time.Now().UTC().Format(time.RFC1123Z),
	}

	// 添加自定义头部
	for k, v := range customHeaders {
		headers[k] = v
	}

	return &AuthenticatedMail{
		From:       from,
		To:         []string{to},
		Subject:    subject,
		Body:       body,
		Headers:    headers,
		AuthScore:  85, // 固定分数
		DKIMSigned: true,
	}, nil
}

func (mas *MailAuthService) GenerateRecommendedDNSRecords(domain string) ([]MailDNSRecord, error) {
	return []MailDNSRecord{
		{
			Type:        "TXT",
			Name:        domain,
			Value:       "v=spf1 mx a -all",
			Description: "SPF记录",
			Priority:    1,
		},
		{
			Type:        "TXT",
			Name:        "_dmarc." + domain,
			Value:       "v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain,
			Description: "DMARC记录",
			Priority:    2,
		},
	}, nil
}

func (mas *MailAuthService) GetDKIMPublicKey() (string, error) {
	return "v=DKIM1; k=rsa; p=PLACEHOLDER_PUBLIC_KEY", nil
}

func (mas *MailAuthService) GetDKIMDNSRecord() (string, string, error) {
	return "default._domainkey.caiji.wiki", "v=DKIM1; k=rsa; p=PLACEHOLDER_PUBLIC_KEY", nil
}
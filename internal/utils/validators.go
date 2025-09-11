package utils

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// EmailValidator 邮件地址验证器
type EmailValidator struct {
	allowedDomains []string
	blockedDomains []string
}

// NewEmailValidator 创建邮件验证器
func NewEmailValidator(allowedDomains, blockedDomains []string) *EmailValidator {
	return &EmailValidator{
		allowedDomains: allowedDomains,
		blockedDomains: blockedDomains,
	}
}

// ValidateEmail 验证邮件地址格式和域名
func (v *EmailValidator) ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("邮件地址不能为空")
	}

	// 基础格式验证
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("邮件地址格式无效: %s", email)
	}

	// 提取域名
	domain := ExtractDomain(email)
	if domain == "" {
		return fmt.Errorf("无法提取域名: %s", email)
	}

	// 检查是否在黑名单中
	for _, blocked := range v.blockedDomains {
		if strings.EqualFold(domain, blocked) {
			return fmt.Errorf("域名已被禁用: %s", domain)
		}
	}

	// 如果有白名单，检查是否在白名单中
	if len(v.allowedDomains) > 0 {
		allowed := false
		for _, allowedDomain := range v.allowedDomains {
			if strings.EqualFold(domain, allowedDomain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("域名未在允许列表中: %s", domain)
		}
	}

	return nil
}

// DomainValidator 域名验证器
type DomainValidator struct{}

// NewDomainValidator 创建域名验证器
func NewDomainValidator() *DomainValidator {
	return &DomainValidator{}
}

// ValidateDomain 验证域名格式
func (v *DomainValidator) ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	// 域名格式验证
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("域名格式无效: %s", domain)
	}

	// 长度检查
	if len(domain) > 253 {
		return fmt.Errorf("域名过长: %s (最大253字符)", domain)
	}

	// 检查是否为保留域名
	reservedDomains := []string{
		"localhost", "local", "example.com", "test.com", 
		"invalid", "test", "example", "localhost.localdomain",
	}
	
	for _, reserved := range reservedDomains {
		if strings.EqualFold(domain, reserved) {
			return fmt.Errorf("不能使用保留域名: %s", domain)
		}
	}

	return nil
}

// ValidateMXRecord 验证MX记录
func (v *DomainValidator) ValidateMXRecord(domain string) error {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return fmt.Errorf("查询MX记录失败: %v", err)
	}

	if len(mxRecords) == 0 {
		return fmt.Errorf("域名 %s 没有MX记录", domain)
	}

	return nil
}

// PasswordValidator 密码验证器
type PasswordValidator struct {
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireNumber  bool
	RequireSpecial bool
}

// NewPasswordValidator 创建密码验证器
func NewPasswordValidator() *PasswordValidator {
	return &PasswordValidator{
		MinLength:      8,
		RequireUpper:   true,
		RequireLower:   true,
		RequireNumber:  true,
		RequireSpecial: false,
	}
}

// ValidatePassword 验证密码强度
func (v *PasswordValidator) ValidatePassword(password string) error {
	if len(password) < v.MinLength {
		return fmt.Errorf("密码长度至少需要%d个字符", v.MinLength)
	}

	if v.RequireUpper && !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return fmt.Errorf("密码必须包含大写字母")
	}

	if v.RequireLower && !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return fmt.Errorf("密码必须包含小写字母")
	}

	if v.RequireNumber && !regexp.MustCompile(`[0-9]`).MatchString(password) {
		return fmt.Errorf("密码必须包含数字")
	}

	if v.RequireSpecial && !regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password) {
		return fmt.Errorf("密码必须包含特殊字符")
	}

	return nil
}

// 工具函数

// ExtractDomain 从邮件地址提取域名
func ExtractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parts[1]))
}

// ExtractLocalPart 从邮件地址提取本地部分
func ExtractLocalPart(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

// NormalizeEmail 标准化邮件地址
func NormalizeEmail(email string) string {
	email = strings.TrimSpace(email)
	email = strings.ToLower(email)
	return email
}

// ValidateIPAddress 验证IP地址
func ValidateIPAddress(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("无效的IP地址: %s", ip)
	}
	return nil
}

// ValidatePort 验证端口号
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("端口号必须在1-65535之间: %d", port)
	}
	return nil
}

// ValidateNotEmpty 验证非空字符串
func ValidateNotEmpty(value, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s不能为空", fieldName)
	}
	return nil
}

// ValidateStringLength 验证字符串长度
func ValidateStringLength(value, fieldName string, minLen, maxLen int) error {
	length := len(strings.TrimSpace(value))
	if length < minLen {
		return fmt.Errorf("%s长度不能少于%d个字符", fieldName, minLen)
	}
	if maxLen > 0 && length > maxLen {
		return fmt.Errorf("%s长度不能超过%d个字符", fieldName, maxLen)
	}
	return nil
}
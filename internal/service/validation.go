package service

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type ValidationService struct {
	emailRegex    *regexp.Regexp
	domainRegex   *regexp.Regexp
	usernameRegex *regexp.Regexp
	passwordRegex *regexp.Regexp
	hostnameRegex *regexp.Regexp
	ipRegex       *regexp.Regexp
}

type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors"`
}

func NewValidationService() *ValidationService {
	return &ValidationService{
		emailRegex:    regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
		domainRegex:   regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`),
		usernameRegex: regexp.MustCompile(`^[a-zA-Z0-9_-]{3,32}$`),
		passwordRegex: regexp.MustCompile(`^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>?]{6,128}$`),
		hostnameRegex: regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`),
		ipRegex:       regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`),
	}
}

// ValidateEmail 验证邮箱格式
func (v *ValidationService) ValidateEmail(email string) *ValidationError {
	if email == "" {
		return &ValidationError{
			Field:   "email",
			Message: "邮箱地址不能为空",
			Code:    "EMAIL_EMPTY",
		}
	}

	if len(email) > 254 {
		return &ValidationError{
			Field:   "email",
			Message: "邮箱地址长度不能超过254个字符",
			Code:    "EMAIL_TOO_LONG",
		}
	}

	if !v.emailRegex.MatchString(email) {
		return &ValidationError{
			Field:   "email",
			Message: "邮箱地址格式不正确",
			Code:    "EMAIL_INVALID_FORMAT",
		}
	}

	// 检查危险字符
	if v.containsDangerousChars(email) {
		return &ValidationError{
			Field:   "email",
			Message: "邮箱地址包含非法字符",
			Code:    "EMAIL_DANGEROUS_CHARS",
		}
	}

	return nil
}

// ValidateDomain 验证域名格式
func (v *ValidationService) ValidateDomain(domain string) *ValidationError {
	if domain == "" {
		return &ValidationError{
			Field:   "domain",
			Message: "域名不能为空",
			Code:    "DOMAIN_EMPTY",
		}
	}

	if len(domain) > 253 {
		return &ValidationError{
			Field:   "domain",
			Message: "域名长度不能超过253个字符",
			Code:    "DOMAIN_TOO_LONG",
		}
	}

	if !v.domainRegex.MatchString(domain) {
		return &ValidationError{
			Field:   "domain",
			Message: "域名格式不正确",
			Code:    "DOMAIN_INVALID_FORMAT",
		}
	}

	// 检查危险字符
	if v.containsDangerousChars(domain) {
		return &ValidationError{
			Field:   "domain",
			Message: "域名包含非法字符",
			Code:    "DOMAIN_DANGEROUS_CHARS",
		}
	}

	return nil
}

// ValidateUsername 验证用户名
func (v *ValidationService) ValidateUsername(username string) *ValidationError {
	if username == "" {
		return &ValidationError{
			Field:   "username",
			Message: "用户名不能为空",
			Code:    "USERNAME_EMPTY",
		}
	}

	if len(username) < 3 || len(username) > 32 {
		return &ValidationError{
			Field:   "username",
			Message: "用户名长度必须在3-32个字符之间",
			Code:    "USERNAME_INVALID_LENGTH",
		}
	}

	if !v.usernameRegex.MatchString(username) {
		return &ValidationError{
			Field:   "username",
			Message: "用户名只能包含字母、数字、下划线和连字符",
			Code:    "USERNAME_INVALID_FORMAT",
		}
	}

	return nil
}

// ValidatePassword 验证密码强度
func (v *ValidationService) ValidatePassword(password string) *ValidationError {
	if password == "" {
		return &ValidationError{
			Field:   "password",
			Message: "密码不能为空",
			Code:    "PASSWORD_EMPTY",
		}
	}

	if len(password) < 6 {
		return &ValidationError{
			Field:   "password",
			Message: "密码长度不能少于6个字符",
			Code:    "PASSWORD_TOO_SHORT",
		}
	}

	if len(password) > 128 {
		return &ValidationError{
			Field:   "password",
			Message: "密码长度不能超过128个字符",
			Code:    "PASSWORD_TOO_LONG",
		}
	}

	// 检查密码复杂性
	var hasUpper, hasLower, hasDigit bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit {
		return &ValidationError{
			Field:   "password",
			Message: "密码必须包含大写字母、小写字母和数字",
			Code:    "PASSWORD_WEAK",
		}
	}

	return nil
}

// ValidateHostname 验证主机名
func (v *ValidationService) ValidateHostname(hostname string) *ValidationError {
	if hostname == "" {
		return &ValidationError{
			Field:   "hostname",
			Message: "主机名不能为空",
			Code:    "HOSTNAME_EMPTY",
		}
	}

	if len(hostname) > 253 {
		return &ValidationError{
			Field:   "hostname",
			Message: "主机名长度不能超过253个字符",
			Code:    "HOSTNAME_TOO_LONG",
		}
	}

	if !v.hostnameRegex.MatchString(hostname) {
		return &ValidationError{
			Field:   "hostname",
			Message: "主机名格式不正确",
			Code:    "HOSTNAME_INVALID_FORMAT",
		}
	}

	return nil
}

// ValidatePort 验证端口号
func (v *ValidationService) ValidatePort(port int) *ValidationError {
	if port < 1 || port > 65535 {
		return &ValidationError{
			Field:   "port",
			Message: "端口号必须在1-65535之间",
			Code:    "PORT_OUT_OF_RANGE",
		}
	}

	return nil
}

// ValidateIPAddress 验证IP地址
func (v *ValidationService) ValidateIPAddress(ip string) *ValidationError {
	if ip == "" {
		return &ValidationError{
			Field:   "ip",
			Message: "IP地址不能为空",
			Code:    "IP_EMPTY",
		}
	}

	if !v.ipRegex.MatchString(ip) {
		return &ValidationError{
			Field:   "ip",
			Message: "IP地址格式不正确",
			Code:    "IP_INVALID_FORMAT",
		}
	}

	return nil
}

// ValidateURL 验证URL格式
func (v *ValidationService) ValidateURL(urlStr string) *ValidationError {
	if urlStr == "" {
		return &ValidationError{
			Field:   "url",
			Message: "URL不能为空",
			Code:    "URL_EMPTY",
		}
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return &ValidationError{
			Field:   "url",
			Message: "URL格式不正确",
			Code:    "URL_INVALID_FORMAT",
		}
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return &ValidationError{
			Field:   "url",
			Message: "URL协议必须是http或https",
			Code:    "URL_INVALID_SCHEME",
		}
	}

	return nil
}

// ValidateQuota 验证配额大小
func (v *ValidationService) ValidateQuota(quota int64) *ValidationError {
	if quota < 0 {
		return &ValidationError{
			Field:   "quota",
			Message: "配额不能为负数",
			Code:    "QUOTA_NEGATIVE",
		}
	}

	// 最大配额限制为100GB
	maxQuota := int64(100 * 1024 * 1024 * 1024)
	if quota > maxQuota {
		return &ValidationError{
			Field:   "quota",
			Message: "配额不能超过100GB",
			Code:    "QUOTA_TOO_LARGE",
		}
	}

	return nil
}

// ValidateString 验证通用字符串
func (v *ValidationService) ValidateString(field, value string, minLen, maxLen int, required bool) *ValidationError {
	if required && value == "" {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("%s不能为空", field),
			Code:    "STRING_EMPTY",
		}
	}

	if len(value) < minLen {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("%s长度不能少于%d个字符", field, minLen),
			Code:    "STRING_TOO_SHORT",
		}
	}

	if maxLen > 0 && len(value) > maxLen {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("%s长度不能超过%d个字符", field, maxLen),
			Code:    "STRING_TOO_LONG",
		}
	}

	// 检查危险字符
	if v.containsDangerousChars(value) {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("%s包含非法字符", field),
			Code:    "STRING_DANGEROUS_CHARS",
		}
	}

	return nil
}

// ValidateInteger 验证整数
func (v *ValidationService) ValidateInteger(field, value string, min, max int64) *ValidationError {
	if value == "" {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("%s不能为空", field),
			Code:    "INTEGER_EMPTY",
		}
	}

	intValue, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("%s必须是整数", field),
			Code:    "INTEGER_INVALID",
		}
	}

	if intValue < min {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("%s不能小于%d", field, min),
			Code:    "INTEGER_TOO_SMALL",
		}
	}

	if intValue > max {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("%s不能大于%d", field, max),
			Code:    "INTEGER_TOO_LARGE",
		}
	}

	return nil
}

// ValidateDate 验证日期格式
func (v *ValidationService) ValidateDate(field, dateStr string) *ValidationError {
	if dateStr == "" {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("%s不能为空", field),
			Code:    "DATE_EMPTY",
		}
	}

	_, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("%s格式不正确，应为YYYY-MM-DD", field),
			Code:    "DATE_INVALID_FORMAT",
		}
	}

	return nil
}

// ValidateRequestSize 验证请求体大小
func (v *ValidationService) ValidateRequestSize(size int64, maxSize int64) *ValidationError {
	if size > maxSize {
		return &ValidationError{
			Field:   "request",
			Message: fmt.Sprintf("请求体大小不能超过%d字节", maxSize),
			Code:    "REQUEST_TOO_LARGE",
		}
	}

	return nil
}

// SanitizeInput 清理输入数据
func (v *ValidationService) SanitizeInput(input string) string {
	// 移除危险字符
	dangerous := []string{
		"<", ">", "\"", "'", "&", ";", "|", "$", "`", "\\",
		"\n", "\r", "\t", "\x00", "\x08", "\x0B", "\x0C",
	}

	result := input
	for _, char := range dangerous {
		result = strings.ReplaceAll(result, char, "")
	}

	// 去除首尾空格
	result = strings.TrimSpace(result)

	return result
}

// SanitizeHTML 清理HTML内容
func (v *ValidationService) SanitizeHTML(html string) string {
	// 移除所有HTML标签
	htmlTagRegex := regexp.MustCompile(`<[^>]*>`)
	result := htmlTagRegex.ReplaceAllString(html, "")

	// 解码HTML实体
	result = strings.ReplaceAll(result, "&lt;", "<")
	result = strings.ReplaceAll(result, "&gt;", ">")
	result = strings.ReplaceAll(result, "&amp;", "&")
	result = strings.ReplaceAll(result, "&quot;", "\"")
	result = strings.ReplaceAll(result, "&#39;", "'")

	return v.SanitizeInput(result)
}

// containsDangerousChars 检查是否包含危险字符
func (v *ValidationService) containsDangerousChars(input string) bool {
	dangerous := []string{
		";", "|", "&", "$", "`", "\"", "'", "\\", "<", ">",
		"(", ")", "{", "}", "[", "]", "\n", "\r", "\t", "\x00",
	}

	for _, char := range dangerous {
		if strings.Contains(input, char) {
			return true
		}
	}

	return false
}

// ValidateBatch 批量验证
func (v *ValidationService) ValidateBatch(validators ...func() *ValidationError) *ValidationResult {
	result := &ValidationResult{Valid: true, Errors: []ValidationError{}}

	for _, validator := range validators {
		if err := validator(); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, *err)
		}
	}

	return result
}

// CreateUserValidation 创建用户验证
func (v *ValidationService) CreateUserValidation(email, name, password string, quota int64) *ValidationResult {
	return v.ValidateBatch(
		func() *ValidationError { return v.ValidateEmail(email) },
		func() *ValidationError { return v.ValidateString("name", name, 1, 100, true) },
		func() *ValidationError { return v.ValidatePassword(password) },
		func() *ValidationError { return v.ValidateQuota(quota) },
	)
}

// LoginValidation 登录验证
func (v *ValidationService) LoginValidation(username, password string) *ValidationResult {
	return v.ValidateBatch(
		func() *ValidationError { return v.ValidateUsername(username) },
		func() *ValidationError { return v.ValidateString("password", password, 1, 128, true) },
	)
}

// SetupConfigValidation 系统配置验证
func (v *ValidationService) SetupConfigValidation(domain, hostname, adminEmail string) *ValidationResult {
	return v.ValidateBatch(
		func() *ValidationError { return v.ValidateDomain(domain) },
		func() *ValidationError { return v.ValidateHostname(hostname) },
		func() *ValidationError { return v.ValidateEmail(adminEmail) },
	)
}
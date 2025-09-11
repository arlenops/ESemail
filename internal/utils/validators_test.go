package utils

import (
	"testing"
)

func TestEmailValidator_ValidateEmail(t *testing.T) {
	tests := []struct {
		name           string
		validator      *EmailValidator
		email          string
		expectedError  bool
		errorMessage   string
	}{
		{
			name:          "有效邮箱地址",
			validator:     NewEmailValidator(nil, nil),
			email:         "user@example.com",
			expectedError: false,
		},
		{
			name:          "空邮箱地址",
			validator:     NewEmailValidator(nil, nil),
			email:         "",
			expectedError: true,
			errorMessage:  "邮件地址不能为空",
		},
		{
			name:          "无效格式",
			validator:     NewEmailValidator(nil, nil),
			email:         "invalid-email",
			expectedError: true,
			errorMessage:  "邮件地址格式无效",
		},
		{
			name:          "域名在黑名单中",
			validator:     NewEmailValidator(nil, []string{"blocked.com"}),
			email:         "user@blocked.com",
			expectedError: true,
			errorMessage:  "域名已被禁用",
		},
		{
			name:          "域名不在白名单中",
			validator:     NewEmailValidator([]string{"allowed.com"}, nil),
			email:         "user@notallowed.com",
			expectedError: true,
			errorMessage:  "域名未在允许列表中",
		},
		{
			name:          "域名在白名单中",
			validator:     NewEmailValidator([]string{"allowed.com"}, nil),
			email:         "user@allowed.com",
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.validator.ValidateEmail(tt.email)
			
			if tt.expectedError {
				if err == nil {
					t.Errorf("期望错误但没有收到错误")
				} else if tt.errorMessage != "" && !contains(err.Error(), tt.errorMessage) {
					t.Errorf("错误消息不匹配, 期望包含 '%s', 得到 '%s'", tt.errorMessage, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("期望没有错误但收到错误: %v", err)
				}
			}
		})
	}
}

func TestDomainValidator_ValidateDomain(t *testing.T) {
	validator := NewDomainValidator()
	
	tests := []struct {
		name          string
		domain        string
		expectedError bool
		errorMessage  string
	}{
		{
			name:          "有效域名",
			domain:        "example.com",
			expectedError: false,
		},
		{
			name:          "空域名",
			domain:        "",
			expectedError: true,
			errorMessage:  "域名不能为空",
		},
		{
			name:          "无效格式",
			domain:        "invalid..domain",
			expectedError: true,
			errorMessage:  "域名格式无效",
		},
		{
			name:          "保留域名",
			domain:        "localhost",
			expectedError: true,
			errorMessage:  "不能使用保留域名",
		},
		{
			name:          "域名过长",
			domain:        "a" + string(make([]byte, 250)) + ".com",
			expectedError: true,
			errorMessage:  "域名过长",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateDomain(tt.domain)
			
			if tt.expectedError {
				if err == nil {
					t.Errorf("期望错误但没有收到错误")
				} else if tt.errorMessage != "" && !contains(err.Error(), tt.errorMessage) {
					t.Errorf("错误消息不匹配, 期望包含 '%s', 得到 '%s'", tt.errorMessage, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("期望没有错误但收到错误: %v", err)
				}
			}
		})
	}
}

func TestPasswordValidator_ValidatePassword(t *testing.T) {
	validator := NewPasswordValidator()
	
	tests := []struct {
		name          string
		password      string
		expectedError bool
		errorMessage  string
	}{
		{
			name:          "有效密码",
			password:      "StrongP@ss123",
			expectedError: false,
		},
		{
			name:          "密码过短",
			password:      "123",
			expectedError: true,
			errorMessage:  "密码长度至少需要",
		},
		{
			name:          "缺少大写字母",
			password:      "weakpassword123",
			expectedError: true,
			errorMessage:  "密码必须包含大写字母",
		},
		{
			name:          "缺少小写字母",
			password:      "WEAKPASSWORD123",
			expectedError: true,
			errorMessage:  "密码必须包含小写字母",
		},
		{
			name:          "缺少数字",
			password:      "WeakPassword",
			expectedError: true,
			errorMessage:  "密码必须包含数字",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePassword(tt.password)
			
			if tt.expectedError {
				if err == nil {
					t.Errorf("期望错误但没有收到错误")
				} else if tt.errorMessage != "" && !contains(err.Error(), tt.errorMessage) {
					t.Errorf("错误消息不匹配, 期望包含 '%s', 得到 '%s'", tt.errorMessage, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("期望没有错误但收到错误: %v", err)
				}
			}
		})
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"user@example.com", "example.com"},
		{"test@DOMAIN.COM", "domain.com"},
		{"invalid-email", ""},
		{"user@", ""},
		{"@domain.com", "domain.com"},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			result := ExtractDomain(tt.email)
			if result != tt.expected {
				t.Errorf("ExtractDomain(%s) = %s, 期望 %s", tt.email, result, tt.expected)
			}
		})
	}
}

func TestExtractLocalPart(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"user@example.com", "user"},
		{"TEST@domain.com", "TEST"},
		{"invalid-email", ""},
		{"user@", "user"},
		{"@domain.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			result := ExtractLocalPart(tt.email)
			if result != tt.expected {
				t.Errorf("ExtractLocalPart(%s) = %s, 期望 %s", tt.email, result, tt.expected)
			}
		})
	}
}

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"  User@Example.COM  ", "user@example.com"},
		{"TEST@DOMAIN.COM", "test@domain.com"},
		{"user@example.com", "user@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			result := NormalizeEmail(tt.email)
			if result != tt.expected {
				t.Errorf("NormalizeEmail(%s) = %s, 期望 %s", tt.email, result, tt.expected)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		port          int
		expectedError bool
	}{
		{80, false},
		{443, false},
		{8080, false},
		{0, true},
		{-1, true},
		{65536, true},
		{70000, true},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.port)), func(t *testing.T) {
			err := ValidatePort(tt.port)
			if tt.expectedError && err == nil {
				t.Errorf("期望端口 %d 验证失败但成功了", tt.port)
			}
			if !tt.expectedError && err != nil {
				t.Errorf("期望端口 %d 验证成功但失败了: %v", tt.port, err)
			}
		})
	}
}

func TestValidateNotEmpty(t *testing.T) {
	tests := []struct {
		value         string
		fieldName     string
		expectedError bool
	}{
		{"valid", "字段", false},
		{"", "字段", true},
		{"  ", "字段", true},
		{"   value   ", "字段", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			err := ValidateNotEmpty(tt.value, tt.fieldName)
			if tt.expectedError && err == nil {
				t.Errorf("期望验证失败但成功了")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("期望验证成功但失败了: %v", err)
			}
		})
	}
}

func TestValidateStringLength(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		fieldName     string
		minLen        int
		maxLen        int
		expectedError bool
	}{
		{"有效长度", "test", "字段", 1, 10, false},
		{"太短", "a", "字段", 5, 10, true},
		{"太长", "verylongtext", "字段", 1, 5, true},
		{"在边界", "test", "字段", 4, 4, false},
		{"无最大限制", "verylongtext", "字段", 1, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStringLength(tt.value, tt.fieldName, tt.minLen, tt.maxLen)
			if tt.expectedError && err == nil {
				t.Errorf("期望验证失败但成功了")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("期望验证成功但失败了: %v", err)
			}
		})
	}
}

// 辅助函数
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		(s == substr || 
		 (len(s) > len(substr) && 
		  (s[:len(substr)] == substr || 
		   s[len(s)-len(substr):] == substr ||
		   containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// 基准测试
func BenchmarkValidateEmail(b *testing.B) {
	validator := NewEmailValidator(nil, nil)
	email := "test@example.com"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateEmail(email)
	}
}

func BenchmarkValidateDomain(b *testing.B) {
	validator := NewDomainValidator()
	domain := "example.com"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidateDomain(domain)
	}
}

func BenchmarkValidatePassword(b *testing.B) {
	validator := NewPasswordValidator()
	password := "StrongP@ss123"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.ValidatePassword(password)
	}
}
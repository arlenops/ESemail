package middleware

import (
	"bytes"
	"esemail/internal/service"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// RequestValidationMiddleware 请求验证中间件
func RequestValidationMiddleware(validationService *service.ValidationService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 验证请求方法
		if !isValidMethod(c.Request.Method) {
			c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "不支持的HTTP方法"})
			c.Abort()
			return
		}

		// 验证Content-Type
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			contentType := c.GetHeader("Content-Type")
			if !isValidContentType(contentType) {
				c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "不支持的Content-Type"})
				c.Abort()
				return
			}
		}

		// 验证请求体大小
		if c.Request.ContentLength > 0 {
			maxSize := int64(10 * 1024 * 1024) // 10MB
			if err := validationService.ValidateRequestSize(c.Request.ContentLength, maxSize); err != nil {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": err.Message})
				c.Abort()
				return
			}

			// 读取并验证请求体内容
			body, err := c.GetRawData()
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "无法读取请求体"})
				c.Abort()
				return
			}

			// 检查请求体是否包含危险内容
			if containsMaliciousContent(string(body)) {
				log.Printf("检测到恶意请求内容，来源IP: %s", c.ClientIP())
				c.JSON(http.StatusBadRequest, gin.H{"error": "请求包含非法内容"})
				c.Abort()
				return
			}

			// 重新设置请求体以供后续处理
			c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
		}

		// 验证查询参数
		for key, values := range c.Request.URL.Query() {
			for _, value := range values {
				if containsMaliciousContent(value) {
					log.Printf("检测到恶意查询参数: %s=%s, 来源IP: %s", key, value, c.ClientIP())
					c.JSON(http.StatusBadRequest, gin.H{"error": "查询参数包含非法内容"})
					c.Abort()
					return
				}
			}
		}

		// 验证请求头
		for key, values := range c.Request.Header {
			// 跳过一些标准头部
			if isStandardHeader(key) {
				continue
			}
			
			for _, value := range values {
				if containsMaliciousContent(value) {
					log.Printf("检测到恶意请求头: %s=%s, 来源IP: %s", key, value, c.ClientIP())
					c.JSON(http.StatusBadRequest, gin.H{"error": "请求头包含非法内容"})
					c.Abort()
					return
				}
			}
		}

		c.Next()
	}
}

// RateLimitMiddleware 简单的速率限制中间件
func RateLimitMiddleware() gin.HandlerFunc {
	// 存储每个IP的请求计数（实际项目中应使用Redis等外部存储）
	requestCounts := make(map[string]int)
	
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		// 简单的内存计数（仅用于演示）
		if count, exists := requestCounts[clientIP]; exists {
			if count > 100 { // 每分钟最多100个请求
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "请求过于频繁"})
				c.Abort()
				return
			}
			requestCounts[clientIP] = count + 1
		} else {
			requestCounts[clientIP] = 1
		}
		
		c.Next()
	}
}

// SecurityHeadersMiddleware 安全头部中间件
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 添加安全头部
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		
		c.Next()
	}
}

// IPWhitelistMiddleware IP白名单中间件（用于管理接口）
func IPWhitelistMiddleware(allowedIPs []string) gin.HandlerFunc {
	ipMap := make(map[string]bool)
	for _, ip := range allowedIPs {
		ipMap[ip] = true
	}
	
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		
		// 检查是否是本地访问
		if clientIP == "127.0.0.1" || clientIP == "::1" || clientIP == "localhost" {
			c.Next()
			return
		}
		
		if !ipMap[clientIP] {
			log.Printf("拒绝未授权IP访问: %s", clientIP)
			c.JSON(http.StatusForbidden, gin.H{"error": "访问被拒绝"})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// RequestLogMiddleware 请求日志中间件
func RequestLogMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("[%s] %s %s %d %s %s\n",
			param.TimeStamp.Format("2006-01-02 15:04:05"),
			param.ClientIP,
			param.Method,
			param.StatusCode,
			param.Path,
			param.Latency,
		)
	})
}

// isValidMethod 检查HTTP方法是否有效
func isValidMethod(method string) bool {
	validMethods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"PATCH":   true,
		"HEAD":    true,
		"OPTIONS": true,
	}
	return validMethods[method]
}

// isValidContentType 检查Content-Type是否有效
func isValidContentType(contentType string) bool {
	if contentType == "" {
		return true
	}
	
	validTypes := []string{
		"application/json",
		"application/x-www-form-urlencoded",
		"multipart/form-data",
		"text/plain",
		"text/html",
	}
	
	for _, validType := range validTypes {
		if strings.HasPrefix(strings.ToLower(contentType), validType) {
			return true
		}
	}
	
	return false
}

// isStandardHeader 检查是否是标准HTTP头部
func isStandardHeader(header string) bool {
	standardHeaders := map[string]bool{
		"Accept":             true,
		"Accept-Encoding":    true,
		"Accept-Language":    true,
		"Authorization":      true,
		"Content-Type":       true,
		"Content-Length":     true,
		"Cookie":             true,
		"Host":               true,
		"User-Agent":         true,
		"Referer":            true,
		"Origin":             true,
		"X-Forwarded-For":    true,
		"X-Real-IP":          true,
		"Connection":         true,
		"Cache-Control":      true,
		"If-None-Match":      true,
		"If-Modified-Since":  true,
	}
	return standardHeaders[header]
}

// containsMaliciousContent 检查内容是否包含恶意代码
func containsMaliciousContent(content string) bool {
	// 检查SQL注入模式
	sqlInjectionPatterns := []string{
		"'", "\"", ";", "--", "/*", "*/", "xp_", "sp_",
		"union", "select", "insert", "update", "delete",
		"drop", "create", "alter", "exec", "execute",
		"script", "javascript:", "vbscript:", "onload",
		"onerror", "onclick", "onmouseover", "onfocus",
		"<script", "</script>", "<iframe", "</iframe>",
		"eval(", "document.", "window.", "alert(",
		"${", "#{", "../", "..\\", "/etc/passwd",
		"cmd.exe", "powershell", "/bin/sh", "/bin/bash",
	}
	
	lowerContent := strings.ToLower(content)
	
	for _, pattern := range sqlInjectionPatterns {
		if strings.Contains(lowerContent, strings.ToLower(pattern)) {
			return true
		}
	}
	
	// 检查是否包含大量重复字符（可能是DoS攻击）
	if len(content) > 1000 {
		charCount := make(map[rune]int)
		for _, char := range content {
			charCount[char]++
			if charCount[char] > len(content)/2 {
				return true
			}
		}
	}
	
	return false
}
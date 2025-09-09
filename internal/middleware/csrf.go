package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// CSRFTokenStore CSRF令牌存储接口
type CSRFTokenStore interface {
	Set(sessionID, token string, expiry time.Duration) error
	Get(sessionID string) (string, error)
	Delete(sessionID string) error
}

// MemoryTokenStore 内存中的令牌存储（仅用于演示）
type MemoryTokenStore struct {
	tokens map[string]tokenData
	mutex  sync.RWMutex
}

type tokenData struct {
	token  string
	expiry time.Time
}

func NewMemoryTokenStore() *MemoryTokenStore {
	store := &MemoryTokenStore{
		tokens: make(map[string]tokenData),
	}
	
	// 启动清理过期令牌的goroutine
	go store.cleanupExpiredTokens()
	
	return store
}

func (m *MemoryTokenStore) Set(sessionID, token string, expiry time.Duration) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	m.tokens[sessionID] = tokenData{
		token:  token,
		expiry: time.Now().Add(expiry),
	}
	
	return nil
}

func (m *MemoryTokenStore) Get(sessionID string) (string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	data, exists := m.tokens[sessionID]
	if !exists {
		return "", fmt.Errorf("令牌不存在")
	}
	
	if time.Now().After(data.expiry) {
		return "", fmt.Errorf("令牌已过期")
	}
	
	return data.token, nil
}

func (m *MemoryTokenStore) Delete(sessionID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	delete(m.tokens, sessionID)
	return nil
}

func (m *MemoryTokenStore) cleanupExpiredTokens() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		m.mutex.Lock()
		now := time.Now()
		for sessionID, data := range m.tokens {
			if now.After(data.expiry) {
				delete(m.tokens, sessionID)
			}
		}
		m.mutex.Unlock()
	}
}

// CSRFConfig CSRF配置
type CSRFConfig struct {
	TokenStore       CSRFTokenStore
	TokenLength      int
	TokenExpiry      time.Duration
	CookieName       string
	HeaderName       string
	FormFieldName    string
	CookieSecure     bool
	CookieHTTPOnly   bool
	CookieSameSite   http.SameSite
	ErrorMessage     string
	SkipCheckPaths   []string
	TrustedOrigins   []string
}

// DefaultCSRFConfig 默认CSRF配置
func DefaultCSRFConfig() *CSRFConfig {
	return &CSRFConfig{
		TokenStore:       NewMemoryTokenStore(),
		TokenLength:      32,
		TokenExpiry:      24 * time.Hour,
		CookieName:       "csrf-token",
		HeaderName:       "X-CSRF-Token",
		FormFieldName:    "csrf_token",
		CookieSecure:     false, // 开发环境设置为false
		CookieHTTPOnly:   true,
		CookieSameSite:   http.SameSiteLaxMode, // 改为Lax模式
		ErrorMessage:     "CSRF令牌验证失败",
		SkipCheckPaths:   []string{"/api/v1/auth/login", "/api/v1/health", "/api/v1/setup/"},
		TrustedOrigins:   []string{},
	}
}

// CSRFMiddleware CSRF保护中间件
func CSRFMiddleware(config *CSRFConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultCSRFConfig()
	}
	
	return func(c *gin.Context) {
		// 检查是否需要跳过CSRF验证
		if shouldSkipCSRFCheck(c.Request.URL.Path, config.SkipCheckPaths) {
			c.Next()
			return
		}
		
		sessionID := getSessionID(c)
		if sessionID == "" {
			sessionID = generateSessionID()
			setSessionID(c, sessionID)
		}
		
		// GET请求生成新token
		if c.Request.Method == "GET" {
			token, err := generateCSRFToken(config.TokenLength)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "生成CSRF令牌失败"})
				c.Abort()
				return
			}
			
			// 存储token
			config.TokenStore.Set(sessionID, token, config.TokenExpiry)
			
			// 设置cookie
			c.SetCookie(
				config.CookieName,
				token,
				int(config.TokenExpiry.Seconds()),
				"/",
				"",
				config.CookieSecure,
				config.CookieHTTPOnly,
			)
			
			// 将token添加到响应头供JavaScript获取
			c.Header("X-CSRF-Token", token)
			
			c.Next()
			return
		}
		
		// POST/PUT/DELETE等请求验证token
		if isStateChangingMethod(c.Request.Method) {
			// 验证Origin头
			if !isValidOrigin(c.GetHeader("Origin"), config.TrustedOrigins) {
				c.JSON(http.StatusForbidden, gin.H{"error": "无效的请求来源"})
				c.Abort()
				return
			}
			
			// 获取客户端提交的token
			clientToken := getCSRFTokenFromRequest(c, config)
			if clientToken == "" {
				c.JSON(http.StatusForbidden, gin.H{"error": config.ErrorMessage})
				c.Abort()
				return
			}
			
			// 获取存储的token
			storedToken, err := config.TokenStore.Get(sessionID)
			if err != nil {
				c.JSON(http.StatusForbidden, gin.H{"error": config.ErrorMessage})
				c.Abort()
				return
			}
			
			// 验证token
			if !isValidToken(clientToken, storedToken) {
				c.JSON(http.StatusForbidden, gin.H{"error": config.ErrorMessage})
				c.Abort()
				return
			}
		}
		
		c.Next()
	}
}

// generateCSRFToken 生成CSRF令牌
func generateCSRFToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// generateSessionID 生成会话ID
func generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// getSessionID 从请求中获取会话ID
func getSessionID(c *gin.Context) string {
	// 首先尝试从cookie获取
	if cookie, err := c.Cookie("session-id"); err == nil {
		return cookie
	}
	
	// 然后尝试从header获取
	return c.GetHeader("X-Session-ID")
}

// setSessionID 设置会话ID
func setSessionID(c *gin.Context, sessionID string) {
	c.SetCookie(
		"session-id",
		sessionID,
		24*60*60, // 24小时
		"/",
		"",
		true,  // secure
		true,  // httpOnly
	)
}

// getCSRFTokenFromRequest 从请求中获取CSRF令牌
func getCSRFTokenFromRequest(c *gin.Context, config *CSRFConfig) string {
	// 首先尝试从header获取
	if token := c.GetHeader(config.HeaderName); token != "" {
		return token
	}
	
	// 然后尝试从form字段获取
	if token := c.PostForm(config.FormFieldName); token != "" {
		return token
	}
	
	// 最后尝试从cookie获取
	if cookie, err := c.Cookie(config.CookieName); err == nil {
		return cookie
	}
	
	return ""
}

// isValidToken 验证令牌是否有效
func isValidToken(clientToken, storedToken string) bool {
	if clientToken == "" || storedToken == "" {
		return false
	}
	
	// 使用常量时间比较防止时间攻击
	return subtle.ConstantTimeCompare([]byte(clientToken), []byte(storedToken)) == 1
}

// isStateChangingMethod 检查是否是状态改变的HTTP方法
func isStateChangingMethod(method string) bool {
	stateChangingMethods := map[string]bool{
		"POST":   true,
		"PUT":    true,
		"PATCH":  true,
		"DELETE": true,
	}
	return stateChangingMethods[method]
}

// shouldSkipCSRFCheck 检查是否应该跳过CSRF检查
func shouldSkipCSRFCheck(path string, skipPaths []string) bool {
	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

// isValidOrigin 检查Origin头是否有效
func isValidOrigin(origin string, trustedOrigins []string) bool {
	if origin == "" {
		return false
	}
	
	// 如果没有配置信任的源，则允许所有来源
	if len(trustedOrigins) == 0 {
		return true
	}
	
	for _, trusted := range trustedOrigins {
		if origin == trusted {
			return true
		}
	}
	
	return false
}

// GetCSRFTokenHandler 获取CSRF令牌的处理器
func GetCSRFTokenHandler(config *CSRFConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := getSessionID(c)
		if sessionID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "会话ID不存在"})
			return
		}
		
		token, err := config.TokenStore.Get(sessionID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "CSRF令牌不存在"})
			return
		}
		
		c.JSON(http.StatusOK, gin.H{"csrf_token": token})
	}
}
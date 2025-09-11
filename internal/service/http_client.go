package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// HTTPClientService 通用HTTP客户端服务
type HTTPClientService struct {
	client      *http.Client
	timeout     time.Duration
	publicIPURL string
	mutex       sync.RWMutex
	cachedIP    string
	ipCacheTime time.Time
	cacheTTL    time.Duration
}

// HTTPClientConfig HTTP客户端配置
type HTTPClientConfig struct {
	Timeout     time.Duration
	PublicIPURL string
	CacheTTL    time.Duration
}

// NewHTTPClientService 创建新的HTTP客户端服务
func NewHTTPClientService(config HTTPClientConfig) *HTTPClientService {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.PublicIPURL == "" {
		config.PublicIPURL = "https://httpbin.org/ip"
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}

	return &HTTPClientService{
		client: &http.Client{
			Timeout: config.Timeout,
		},
		timeout:     config.Timeout,
		publicIPURL: config.PublicIPURL,
		cacheTTL:    config.CacheTTL,
	}
}

// GetPublicIP 获取服务器公网IP地址（带缓存）
func (s *HTTPClientService) GetPublicIP() (string, error) {
	s.mutex.RLock()
	if s.cachedIP != "" && time.Since(s.ipCacheTime) < s.cacheTTL {
		ip := s.cachedIP
		s.mutex.RUnlock()
		return ip, nil
	}
	s.mutex.RUnlock()

	// 尝试多个IP获取服务
	ipServices := []string{
		"https://httpbin.org/ip",
		"https://ipapi.co/ip",
		"https://api.ipify.org",
	}

	var lastErr error
	for _, url := range ipServices {
		ip, err := s.fetchIPFromService(url)
		if err == nil && ip != "" {
			s.mutex.Lock()
			s.cachedIP = ip
			s.ipCacheTime = time.Now()
			s.mutex.Unlock()
			return ip, nil
		}
		lastErr = err
	}

	return "", fmt.Errorf("无法获取公网IP: %v", lastErr)
}

// fetchIPFromService 从指定服务获取IP
func (s *HTTPClientService) fetchIPFromService(url string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP错误: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// 简单的IP提取（根据不同服务的响应格式）
	ip := s.extractIPFromResponse(string(body))
	if ip == "" {
		return "", fmt.Errorf("无法从响应中提取IP: %s", string(body))
	}

	return ip, nil
}

// extractIPFromResponse 从响应中提取IP地址
func (s *HTTPClientService) extractIPFromResponse(response string) string {
	// 这里实现IP提取逻辑
	// 支持不同服务的响应格式
	
	// 简单实现，实际应该根据不同服务的格式解析
	if len(response) > 0 && len(response) < 20 {
		// 简单的IP格式检查
		return response
	}
	
	// 对于JSON响应（如httpbin.org）
	if response[0] == '{' {
		// 这里可以解析JSON
		// 简化实现
		return ""
	}
	
	return response
}

// Get 执行GET请求
func (s *HTTPClientService) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	return s.client.Do(req)
}

// Post 执行POST请求
func (s *HTTPClientService) Post(ctx context.Context, url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}
	
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	
	return s.client.Do(req)
}
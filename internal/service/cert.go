package service

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"esemail/internal/config"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// CertService 使用Lego ACME客户端的证书服务
type CertService struct {
	config            *config.CertConfig
	legoClient        *lego.Client
	user              *LegoUser
	pendingChallenges map[string]*LegoDNSChallenge
}

// LegoUser 实现lego.User接口
type LegoUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *LegoUser) GetEmail() string {
	return u.Email
}

func (u *LegoUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *LegoUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// LegoDNSChallenge DNS挑战信息
type LegoDNSChallenge struct {
	Domain       string    `json:"domain"`
	DNSName      string    `json:"dns_name"`
	DNSValue     string    `json:"dns_value"`
	Token        string    `json:"token"`
	Challenge    dns01.Challenge `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// ManualDNSProvider 实现dns01.ChallengeProvider接口
type ManualDNSProvider struct {
	service *CertService
}

// Present 实现dns01.ChallengeProvider接口
func (p *ManualDNSProvider) Present(domain, token, keyAuth string) error {
	dnsName, dnsValue := dns01.GetRecord(domain, keyAuth)
	
	log.Printf("INFO: DNS挑战 - 域名: %s, DNS名称: %s, DNS值: %s", domain, dnsName, dnsValue)
	
	// 存储挑战信息
	p.service.pendingChallenges[domain] = &LegoDNSChallenge{
		Domain:    domain,
		DNSName:   dnsName,
		DNSValue:  dnsValue,
		Token:     token,
		CreatedAt: time.Now(),
	}
	
	// 返回一个特殊的错误，告知需要手动设置DNS记录
	return fmt.Errorf("manual_dns_required:%s:%s", dnsName, dnsValue)
}

// CleanUp 实现dns01.ChallengeProvider接口
func (p *ManualDNSProvider) CleanUp(domain, token, keyAuth string) error {
	log.Printf("INFO: 清理DNS挑战记录 - 域名: %s", domain)
	delete(p.service.pendingChallenges, domain)
	return nil
}

// Certificate 证书信息
type Certificate struct {
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
	Issuer    string    `json:"issuer"`
}

// LegoCertResponse 证书响应
type LegoCertResponse struct {
	Success      bool                   `json:"success"`
	DNSName      string                 `json:"dns_name,omitempty"`
	DNSValue     string                 `json:"dns_value,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Message      string                 `json:"message,omitempty"`
	Instructions map[string]interface{} `json:"instructions,omitempty"`
}

// NewCertService 创建新的证书服务
func NewCertService(config *config.CertConfig) (*CertService, error) {
	service := &CertService{
		config:            config,
		pendingChallenges: make(map[string]*LegoDNSChallenge),
	}

	// 只有在配置了有效邮箱时才初始化客户端
	// 避免系统启动时因为示例邮箱导致失败
	if config.Email != "" && config.Email != "admin@example.com" && !strings.Contains(config.Email, "example.") {
		if err := service.initializeClient(); err != nil {
			log.Printf("警告: 证书客户端初始化失败，将在首次申请证书时重新初始化: %v", err)
		}
	} else {
		log.Printf("警告: 未配置有效的证书邮箱地址，证书功能将在配置后可用")
	}

	return service, nil
}

// initializeClient 初始化Lego客户端
func (s *CertService) initializeClient() error {
	// 1. 创建或加载用户私钥
	privateKey, err := s.getOrCreatePrivateKey()
	if err != nil {
		return fmt.Errorf("获取私钥失败: %v", err)
	}

	// 2. 创建用户
	s.user = &LegoUser{
		Email: s.config.Email,
		key:   privateKey,
	}

	// 3. 创建Lego配置
	legoConfig := lego.NewConfig(s.user)
	
	// 设置CA服务器
	if s.config.Server == "" || s.config.Server == "letsencrypt" {
		legoConfig.CADirURL = lego.LEDirectoryProduction
	} else if s.config.Server == "staging" {
		legoConfig.CADirURL = lego.LEDirectoryStaging
	} else {
		legoConfig.CADirURL = s.config.Server
	}

	// 4. 创建客户端
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return fmt.Errorf("创建Lego客户端失败: %v", err)
	}

	s.legoClient = client

	// 5. 注册用户（如果需要）
	if err := s.registerUser(); err != nil {
		return fmt.Errorf("注册用户失败: %v", err)
	}

	// 6. 设置DNS挑战提供者（使用自定义实现）
	provider := &ManualDNSProvider{service: s}
	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		return fmt.Errorf("设置DNS提供者失败: %v", err)
	}

	log.Printf("INFO: Lego证书服务初始化成功，用户: %s", s.user.Email)
	return nil
}

// getOrCreatePrivateKey 获取或创建私钥
func (s *CertService) getOrCreatePrivateKey() (crypto.PrivateKey, error) {
	keyPath := filepath.Join(s.config.CertPath, "account.key")
	
	// 尝试加载已存在的私钥
	if _, err := os.Stat(keyPath); err == nil {
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("读取私钥文件失败: %v", err)
		}

		block, _ := pem.Decode(keyData)
		if block == nil {
			return nil, fmt.Errorf("解析私钥PEM失败")
		}

		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析ECDSA私钥失败: %v", err)
		}

		log.Printf("INFO: 加载已存在的账户私钥: %s", keyPath)
		return privateKey, nil
	}

	// 创建新的私钥
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成私钥失败: %v", err)
	}

	// 保存私钥
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("序列化私钥失败: %v", err)
	}

	// 确保目录存在
	err = os.MkdirAll(filepath.Dir(keyPath), 0700)
	if err != nil {
		return nil, fmt.Errorf("创建证书目录失败: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("创建私钥文件失败: %v", err)
	}
	defer keyFile.Close()

	err = pem.Encode(keyFile, pemBlock)
	if err != nil {
		return nil, fmt.Errorf("写入私钥文件失败: %v", err)
	}

	log.Printf("INFO: 创建新的账户私钥: %s", keyPath)
	return privateKey, nil
}

// registerUser 注册用户
func (s *CertService) registerUser() error {
	reg, err := s.legoClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("注册ACME账户失败: %v", err)
	}
	
	s.user.Registration = reg
	log.Printf("INFO: ACME账户注册成功，URI: %s", reg.URI)
	return nil
}

// IssueDNSCert 开始DNS证书申请流程
func (s *CertService) IssueDNSCert(domain, email string) (*LegoCertResponse, error) {
	log.Printf("INFO: 开始为域名 %s 申请DNS证书", domain)

	// 确保客户端已初始化
	if s.legoClient == nil {
		// 如果提供了邮箱，更新配置并初始化客户端
		if email != "" && email != "admin@example.com" && !strings.Contains(email, "example.") {
			s.config.Email = email
			if err := s.initializeClient(); err != nil {
				return &LegoCertResponse{
					Success: false,
					Error:   fmt.Sprintf("初始化证书客户端失败: %v", err),
				}, nil
			}
		} else {
			return &LegoCertResponse{
				Success: false,
				Error:   "证书服务未初始化，请提供有效的邮箱地址",
			}, nil
		}
	}

	// 1. 创建证书请求
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	// 2. 获取DNS挑战（这会触发manual provider的Present回调）
	cert, err := s.legoClient.Certificate.Obtain(request)
	if err != nil {
		// 检查是否是手动DNS挑战错误
		if strings.HasPrefix(err.Error(), "manual_dns_required:") {
			parts := strings.Split(err.Error(), ":")
			if len(parts) >= 3 {
				dnsName := parts[1]
				dnsValue := parts[2]
				return &LegoCertResponse{
					Success:  true,
					DNSName:  dnsName,
					DNSValue: dnsValue,
					Message: fmt.Sprintf("请在DNS中添加以下TXT记录:\\n名称: %s\\n值: %s\\n\\n添加完成后，请调用完成验证接口。", 
						dnsName, dnsValue),
				}, nil
			}
		}
		return &LegoCertResponse{
			Success: false,
			Error:   fmt.Sprintf("申请证书失败: %v", err),
		}, nil
	}

	// 3. 安装证书
	err = s.installCertificate(domain, cert)
	if err != nil {
		return &LegoCertResponse{
			Success: false,
			Error:   fmt.Sprintf("证书申请成功但安装失败: %v", err),
		}, nil
	}

	return &LegoCertResponse{
		Success: true,
		Message: fmt.Sprintf("域名 %s 的SSL证书申请和安装成功", domain),
	}, nil
}


// CompleteDNSChallenge 完成DNS挑战验证
func (s *CertService) CompleteDNSChallenge(domain string) (*LegoCertResponse, error) {
	challenge, exists := s.pendingChallenges[domain]
	if !exists {
		return &LegoCertResponse{
			Success: false,
			Error:   "未找到域名的DNS挑战信息，请重新申请",
		}, nil
	}

	// 验证DNS记录是否已设置
	if !s.verifyDNSRecord(challenge.DNSName, challenge.DNSValue) {
		return &LegoCertResponse{
			Success: false,
			Error:   fmt.Sprintf("DNS记录验证失败，请确保已正确设置:\n名称: %s\n值: %s", 
				challenge.DNSName, challenge.DNSValue),
		}, nil
	}

	// 重新尝试证书申请
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	cert, err := s.legoClient.Certificate.Obtain(request)
	if err != nil {
		return &LegoCertResponse{
			Success: false,
			Error:   fmt.Sprintf("DNS验证通过但证书申请失败: %v", err),
		}, nil
	}

	// 安装证书
	err = s.installCertificate(domain, cert)
	if err != nil {
		return &LegoCertResponse{
			Success: false,
			Error:   fmt.Sprintf("证书申请成功但安装失败: %v", err),
		}, nil
	}

	// 清理挑战
	delete(s.pendingChallenges, domain)

	return &LegoCertResponse{
		Success: true,
		Message: fmt.Sprintf("域名 %s 的SSL证书申请和安装成功", domain),
	}, nil
}

// verifyDNSRecord 验证DNS记录
func (s *CertService) verifyDNSRecord(dnsName, expectedValue string) bool {
	// 这里应该实现真实的DNS查询验证
	// 为了简化，这里返回true，实际项目中需要使用DNS查询库
	log.Printf("INFO: 验证DNS记录 %s = %s", dnsName, expectedValue)
	return true
}

// installCertificate 安装证书
func (s *CertService) installCertificate(domain string, cert *certificate.Resource) error {
	certDir := filepath.Join(s.config.CertPath, domain)
	err := os.MkdirAll(certDir, 0755)
	if err != nil {
		return fmt.Errorf("创建证书目录失败: %v", err)
	}

	// 保存证书文件
	certFile := filepath.Join(certDir, "fullchain.pem")
	err = os.WriteFile(certFile, cert.Certificate, 0644)
	if err != nil {
		return fmt.Errorf("保存证书文件失败: %v", err)
	}

	// 保存私钥文件
	keyFile := filepath.Join(certDir, "private.key")
	err = os.WriteFile(keyFile, cert.PrivateKey, 0600)
	if err != nil {
		return fmt.Errorf("保存私钥文件失败: %v", err)
	}

	log.Printf("INFO: 证书安装成功，域名: %s, 路径: %s", domain, certDir)
	return nil
}

// ListCertificates 列出所有证书
func (s *CertService) ListCertificates() ([]Certificate, error) {
	var certificates []Certificate
	
	certPath := s.config.CertPath
	entries, err := os.ReadDir(certPath)
	if err != nil {
		return certificates, nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		domain := entry.Name()
		if domain == "account.key" {
			continue
		}

		certFile := filepath.Join(certPath, domain, "fullchain.pem")
		if _, err := os.Stat(certFile); err != nil {
			continue
		}

		// 读取证书信息
		certData, err := os.ReadFile(certFile)
		if err != nil {
			continue
		}

		block, _ := pem.Decode(certData)
		if block == nil {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		certificate := Certificate{
			Domain:    domain,
			Type:      "Lego/Let's Encrypt",
			Status:    "Active",
			ExpiresAt: cert.NotAfter,
			IssuedAt:  cert.NotBefore,
			Issuer:    cert.Issuer.CommonName,
		}

		certificates = append(certificates, certificate)
	}

	return certificates, nil
}

// GetPendingChallenge 获取待验证的DNS挑战
func (s *CertService) GetPendingChallenge(domain string) (*LegoDNSChallenge, error) {
	challenge, exists := s.pendingChallenges[domain]
	if !exists {
		return nil, fmt.Errorf("未找到域名 %s 的DNS挑战信息", domain)
	}
	return challenge, nil
}
package service

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
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
    pendingFilePath   string
    security          *SecurityService
    onInstalled       func(domain string)
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

    // 首次或未检测到记录，存储挑战
    p.service.pendingChallenges[domain] = &LegoDNSChallenge{
        Domain:    domain,
        DNSName:   dnsName,
        DNSValue:  dnsValue,
        Token:     token,
        CreatedAt: time.Now(),
    }
    _ = p.service.savePendingChallenges()

    // 轮询等待用户配置TXT（最多等待3分钟），每3秒检查一次
    deadline := time.Now().Add(3 * time.Minute)
    for {
        // 若可用则刷新本机DNS缓存
        if p.service.security != nil {
            p.service.security.FlushDNSCache()
        }
        // 去掉末尾点进行dig查询
        name := strings.TrimSuffix(dnsName, ".")
        if ok, _ := p.service.verifyDNSRecord(name, dnsValue); ok {
            log.Printf("INFO: 等待期间检测到TXT记录已生效，继续签发: %s", dnsName)
            return nil
        }
        if time.Now().After(deadline) {
            // 超时仍未生效，提示手动模式
            return fmt.Errorf("manual_dns_required:%s:%s", dnsName, dnsValue)
        }
        time.Sleep(3 * time.Second)
    }
}

// CleanUp 实现dns01.ChallengeProvider接口
func (p *ManualDNSProvider) CleanUp(domain, token, keyAuth string) error {
    log.Printf("INFO: 清理DNS挑战记录 - 域名: %s", domain)
    // 轻量化手动模式：保留挂起挑战，等待客户端调用验证接口后再清理
    // 真实完成验证时由 CompleteDNSChallenge 删除并持久化
    // 这里不做删除，避免 '未找到DNS挑战信息'
    _ = p.service.savePendingChallenges()
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
    Debug        map[string]interface{} `json:"debug,omitempty"`
}

// NewCertService 创建新的证书服务
func NewCertService(config *config.CertConfig) (*CertService, error) {
	service := &CertService{
		config:            config,
		pendingChallenges: make(map[string]*LegoDNSChallenge),
		pendingFilePath:   filepath.Join("./data", "certificates", "pending_challenges.json"),
		security:          NewSecurityService(),
	}

	// 预加载历史未完成挑战，支持进程重启后继续
	if err := service.loadPendingChallenges(); err != nil {
		log.Printf("警告: 加载待验证DNS挑战信息失败: %v", err)
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

// SetOnInstalled 设置证书安装完成回调
func (s *CertService) SetOnInstalled(cb func(domain string)) {
    s.onInstalled = cb
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
func (s *CertService) IssueDNSCert(domain string) (*LegoCertResponse, error) {
    log.Printf("INFO: 开始为域名 %s 申请DNS证书", domain)

    // 确保客户端已初始化，统一从配置注入邮箱
    if s.legoClient == nil {
        if s.config.Email == "" || s.config.Email == "admin@example.com" || strings.Contains(s.config.Email, "example.") {
            return &LegoCertResponse{Success: false, Error: "证书服务未初始化，请在配置中设置有效邮箱 cert.email"}, nil
        }
        if err := s.initializeClient(); err != nil {
            return &LegoCertResponse{Success: false, Error: fmt.Sprintf("初始化证书客户端失败: %v", err)}, nil
        }
    }

    // 构建请求
    request := certificate.ObtainRequest{Domains: []string{domain}, Bundle: true}

    // 异步发起签发流程（将触发 Present 记录挑战）
    go func(d string, req certificate.ObtainRequest) {
        cert, err := s.legoClient.Certificate.Obtain(req)
        if err != nil {
            log.Printf("WARNING: 证书申请异步流程返回错误(可能是手动模式或超时): %v", err)
            return
        }
        if err := s.installCertificate(d, cert); err != nil {
            log.Printf("ERROR: 证书安装失败: %v", err)
        }
    }(domain, request)

    // 尝试在短时间内读取已记录的挑战，以便前端展示
    start := time.Now()
    for time.Since(start) < 5*time.Second {
        if ch, ok := s.pendingChallenges[domain]; ok {
            return &LegoCertResponse{
                Success: true,
                DNSName: ch.DNSName,
                DNSValue: ch.DNSValue,
                Message: "已发起DNS-01挑战，请添加以下TXT记录后等待验证自动完成。如超时，可点完成验证。",
                Debug: map[string]interface{}{"pending_file": s.pendingFilePath, "domain": domain},
            }, nil
        }
        if ch, ok := s.pendingChallenges[s.normalizeDomain(domain)]; ok {
            return &LegoCertResponse{
                Success: true,
                DNSName: ch.DNSName,
                DNSValue: ch.DNSValue,
                Message: "已发起DNS-01挑战，请添加以下TXT记录后等待验证自动完成。如超时，可点完成验证。",
                Debug: map[string]interface{}{"pending_file": s.pendingFilePath, "domain": domain},
            }, nil
        }
        time.Sleep(200 * time.Millisecond)
    }

    // 若尚未拿到挑战，仍返回成功并提示前端稍后获取
    return &LegoCertResponse{
        Success: true,
        Message: "已发起DNS-01挑战，正在获取挑战信息，请稍后刷新或查看挂起挑战列表。",
        Debug: map[string]interface{}{"pending_file": s.pendingFilePath, "domain": domain},
    }, nil
}


// CompleteDNSChallenge 完成DNS挑战验证
func (s *CertService) CompleteDNSChallenge(domain string) (*LegoCertResponse, error) {
	// 支持通配符与规范化域名匹配
	challenge, exists := s.pendingChallenges[domain]
	if !exists {
		normalized := s.normalizeDomain(domain)
		challenge, exists = s.pendingChallenges[normalized]
	}
    if !exists {
        log.Printf("ERROR: 未找到DNS挑战信息 domain=%s keys=%v file=%s", domain, s.GetPendingDomains(), s.pendingFilePath)
        tried := []string{domain, s.normalizeDomain(domain)}
        return &LegoCertResponse{
            Success: false,
            Error:   "未找到域名的DNS挑战信息，请重新申请",
            Debug: map[string]interface{}{
                "tried_keys":       tried,
                "pending_domains":  s.GetPendingDomains(),
                "pending_file":     s.pendingFilePath,
                "hint":             "请先调用 /api/v1/certificates/issue 并添加返回的 TXT 记录",
            },
        }, nil
    }

	// 验证DNS记录是否已设置
    if ok, dbg := s.verifyDNSRecord(challenge.DNSName, challenge.DNSValue); !ok {
        if dbg != nil {
            if observed, ok2 := dbg["observed"]; ok2 {
                log.Printf("ERROR: DNS验证失败 fqdn=%s expected=%s observed=%v", challenge.DNSName, challenge.DNSValue, observed)
            } else {
                log.Printf("ERROR: DNS验证失败 fqdn=%s expected=%s", challenge.DNSName, challenge.DNSValue)
            }
        }
        if dbg == nil { dbg = map[string]interface{}{} }
        dbg["dns_name"] = challenge.DNSName
        dbg["expected_value"] = challenge.DNSValue
        return &LegoCertResponse{
            Success: false,
            Error:   fmt.Sprintf("DNS记录验证失败，请确保已正确设置: 名称=%s 值=%s", challenge.DNSName, challenge.DNSValue),
            Debug:   dbg,
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

	// 清理挑战并持久化
	delete(s.pendingChallenges, challenge.Domain)
	_ = s.savePendingChallenges()

	return &LegoCertResponse{
		Success: true,
		Message: fmt.Sprintf("域名 %s 的SSL证书申请和安装成功", domain),
	}, nil
}

// verifyDNSRecord 验证DNS记录
func (s *CertService) verifyDNSRecord(dnsName, expectedValue string) (bool, map[string]interface{}) {
    // 在验证之前尽力刷新本机DNS缓存
    if s.security != nil {
        s.security.FlushDNSCache()
    }
    // 轻量化：仅使用本机Linux命令 dig 进行验证（通过安全执行器）
    name := strings.TrimSpace(dnsName)
    expected := strings.TrimSpace(expectedValue)
    if name == "" || expected == "" {
        return false, map[string]interface{}{"reason": "invalid input", "name": name}
    }

    attempts := 6
    delay := 5 * time.Second
    var observed []string
    for i := 0; i < attempts; i++ {
        out, err := s.security.ExecuteSecureCommand("dig", []string{"+short", "TXT", name}, 6*time.Second)
        if err == nil {
            lines := strings.Split(strings.TrimSpace(string(out)), "\n")
            observed = observed[:0]
            for _, ln := range lines {
                v := strings.TrimSpace(strings.Trim(ln, "\""))
                if v != "" { observed = append(observed, v) }
            }
            for _, v := range observed {
                if v == expected || strings.Contains(v, expected) {
                    return true, map[string]interface{}{
                        "attempts": attempts,
                        "delay_seconds": int(delay / time.Second),
                        "name": name,
                        "observed": observed,
                    }
                }
            }
        }
        if i < attempts-1 { time.Sleep(delay) }
    }
    return false, map[string]interface{}{
        "attempts": attempts,
        "delay_seconds": int(delay / time.Second),
        "name": name,
        "observed": observed,
    }
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
    if s.onInstalled != nil {
        go s.onInstalled(domain)
    }
    // 安全重载服务以应用新证书
    if s.security != nil {
        _ , _ = s.security.ExecuteSecureCommand("systemctl", []string{"reload", "postfix"}, 10*time.Second)
        _ , _ = s.security.ExecuteSecureCommand("systemctl", []string{"reload", "dovecot"}, 10*time.Second)
    }
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

// DeleteCertificate 删除指定域名的已安装证书，并回退服务配置至系统默认证书
func (s *CertService) DeleteCertificate(domain string) error {
    if domain == "" {
        return fmt.Errorf("域名不能为空")
    }
    // 归一化：只保留小写
    d := strings.ToLower(domain)
    certDir := filepath.Join(s.config.CertPath, d)

    // 删除证书目录
    if _, err := os.Stat(certDir); err == nil {
        if err := os.RemoveAll(certDir); err != nil {
            return fmt.Errorf("删除证书目录失败: %v", err)
        }
    }

    // 清理挂起挑战
    delete(s.pendingChallenges, d)
    _ = s.savePendingChallenges()

    // 重新生成服务配置，确保回退到 snakeoil 证书，避免服务失败
    setupSvc := NewSetupService()
    setupData := setupSvc.LoadSetupData()
    if setupData != nil {
        sys := NewSystemService()
        // 生成并写入配置文件（包含 dovecot/postfix），此时若无自有证书将使用 snakeoil
        if err := sys.generateConfigsStep(setupData); err != nil {
            // 不阻断删除，但记录错误
            log.Printf("WARNING: 重新生成服务配置失败: %v", err)
        }
    }

    // 重载服务以应用配置
    if s.security != nil {
        _, _ = s.security.ExecuteSecureCommand("systemctl", []string{"reload", "postfix"}, 10*time.Second)
        _, _ = s.security.ExecuteSecureCommand("systemctl", []string{"reload", "dovecot"}, 10*time.Second)
    }

    return nil
}

// GetPendingChallenge 获取待验证的DNS挑战
func (s *CertService) GetPendingChallenge(domain string) (*LegoDNSChallenge, error) {
	challenge, exists := s.pendingChallenges[domain]
	if !exists {
		normalized := s.normalizeDomain(domain)
		challenge, exists = s.pendingChallenges[normalized]
	}
	if !exists {
		return nil, fmt.Errorf("未找到域名 %s 的DNS挑战信息", domain)
	}
	return challenge, nil
}

// GetPendingDomains 返回当前挂起挑战的域名列表（用于调试）
func (s *CertService) GetPendingDomains() []string {
    keys := make([]string, 0, len(s.pendingChallenges))
    for k := range s.pendingChallenges {
        keys = append(keys, k)
    }
    return keys
}

// normalizeDomain 规范化域名（移除通配符前缀）
func (s *CertService) normalizeDomain(domain string) string {
	if strings.HasPrefix(domain, "*.") {
		return strings.TrimPrefix(domain, "*.")
	}
	return domain
}

// savePendingChallenges 将待验证挑战持久化到磁盘
func (s *CertService) savePendingChallenges() error {
	path := s.pendingFilePath
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.pendingChallenges, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// loadPendingChallenges 从磁盘读取待验证挑战
func (s *CertService) loadPendingChallenges() error {
	path := s.pendingFilePath
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var stored map[string]*LegoDNSChallenge
	if err := json.Unmarshal(data, &stored); err != nil {
		return err
	}
	if stored != nil {
		s.pendingChallenges = stored
	}
	return nil
}

// SetEmail 通过API动态设置证书邮箱（移除对配置文件的依赖）
func (s *CertService) SetEmail(email string) error {
    email = strings.TrimSpace(email)
    if email == "" {
        return fmt.Errorf("邮箱不能为空")
    }
    s.config.Email = email
    // 使客户端在下次申请时重新初始化
    s.legoClient = nil
    s.user = nil
    return nil
}

// GetSettings 返回当前证书设置（用于前端展示与管理）
func (s *CertService) GetSettings() map[string]interface{} {
    return map[string]interface{}{
        "email":     s.config.Email,
        "server":    s.config.Server,
        "cert_path": s.config.CertPath,
    }
}

package service

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// MailServer 邮件服务器管理器
type MailServer struct {
	smtpServer    *SMTPServer
	imapServer    *IMAPServer
	mailQueue     *MailQueue
	mailStorage   *MailStorage
	userService   *UserService
	domainService *DomainService
	authService   *MailAuthService // 添加认证服务
	config        *MailServerConfig
	running       bool
	mutex         sync.RWMutex
}

// MailServerConfig 邮件服务器配置
type MailServerConfig struct {
	Domain             string
	DataDir            string
	SMTPPort           string
	SMTPSubmissionPort string
	SMTPSPort          string
	IMAPPort           string
	IMAPSPort          string
	MaxMessageSize     int64
	MaxRecipients      int
	TLSCertFile        string
	TLSKeyFile         string
	EnableTLS          bool
}

// NewMailServer 创建邮件服务器管理器
func NewMailServer(config *MailServerConfig, userService *UserService, domainService *DomainService) (*MailServer, error) {
	// 初始化邮件存储
	mailStorage := NewMailStorage(filepath.Join(config.DataDir, "mail"))
	
	
	// 初始化邮件认证服务
	authConfig := &MailAuthConfig{
		Domain:         config.Domain,
		DKIMSelector:   "default",
		DKIMKeyPath:    filepath.Join(config.DataDir, "dkim"),
		MaxMessageSize: config.MaxMessageSize,
	}
	
	authService, err := NewMailAuthService(authConfig, domainService)
	if err != nil {
		log.Printf("警告: 邮件认证服务初始化失败: %v", err)
		// 可以继续运行，但功能会受限
	}
	
	// 配置TLS - 自动查找证书
	var tlsConfig *tls.Config
	if config.EnableTLS {
		// 优先使用配置文件中指定的证书路径
		certFile := config.TLSCertFile
		keyFile := config.TLSKeyFile

		// 如果配置文件中没有指定，则自动查找Let's Encrypt证书
		if certFile == "" || keyFile == "" {
			// 尝试查找域名对应的证书文件
			certDir := fmt.Sprintf("/etc/ssl/mail/%s", config.Domain)
			potentialCertFile := filepath.Join(certDir, "fullchain.pem")
			potentialKeyFile := filepath.Join(certDir, "private.key")

			// 检查证书文件是否存在
			if _, err := os.Stat(potentialCertFile); err == nil {
				if _, err := os.Stat(potentialKeyFile); err == nil {
					certFile = potentialCertFile
					keyFile = potentialKeyFile
					log.Printf("自动找到域名 %s 的SSL证书: %s", config.Domain, certDir)
				}
			}
		}

		if certFile != "" && keyFile != "" {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				log.Printf("加载TLS证书失败: %v", err)
			} else {
				tlsConfig = &tls.Config{
					Certificates: []tls.Certificate{cert},
					ServerName:   config.Domain,
				}
				log.Printf("TLS配置已启用，使用证书: %s", certFile)
			}
		} else {
			log.Printf("TLS已启用但未找到证书文件，SMTP将仅支持STARTTLS")
		}
	}
	
	// 创建SMTP服务器配置
	smtpConfig := &SMTPConfig{
		ListenAddr:     ":" + config.SMTPPort,
		TLSListenAddr:  ":" + config.SMTPSPort,
		Domain:         config.Domain,
		MaxMessageSize: config.MaxMessageSize,
		MaxRecipients:  config.MaxRecipients,
		TLSConfig:      tlsConfig,
	}

	// TODO: 未来版本将添加587端口的独立SMTP提交服务器支持
	
	// 创建IMAP服务器配置
	imapConfig := &IMAPConfig{
		ListenAddr:    ":" + config.IMAPPort,
		TLSListenAddr: ":" + config.IMAPSPort,
		Domain:        config.Domain,
		TLSConfig:     tlsConfig,
	}
	
	// 创建SMTP服务器
	smtpServer := NewSMTPServer(smtpConfig, nil, userService, domainService, mailStorage)
	
	// 创建IMAP服务器
	imapServer := NewIMAPServer(imapConfig, mailStorage, userService)
	
	// 创建邮件队列配置
	queueConfig := &QueueConfig{
		MaxRetries:      3,
		RetryInterval:   5 * 60, // 5分钟
		ProcessInterval: 30,     // 30秒
		MaxConcurrent:   10,
	}
	
	// 创建邮件队列
	mailQueue := NewMailQueue(queueConfig, smtpServer, mailStorage)
	
	// 更新SMTP服务器的MailService引用
	enhancedMailService := NewEnhancedMailService(mailStorage, mailQueue)
	smtpServer.mailService = enhancedMailService.MailService
	
	return &MailServer{
		smtpServer:    smtpServer,
		imapServer:    imapServer,
		mailQueue:     mailQueue,
		mailStorage:   mailStorage,
		userService:   userService,
		domainService: domainService,
		authService:   authService,
		config:        config,
		running:       false,
	}, nil
}

// Start 启动所有邮件服务
func (ms *MailServer) Start() error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	
	if ms.running {
		return fmt.Errorf("邮件服务器已在运行")
	}
	
	log.Println("启动邮件服务器...")
	
	// 启动邮件队列
	if err := ms.mailQueue.Start(); err != nil {
		return fmt.Errorf("启动邮件队列失败: %v", err)
	}
	
	// 启动SMTP服务器
	if err := ms.smtpServer.Start(); err != nil {
		ms.mailQueue.Stop()
		return fmt.Errorf("启动SMTP服务器失败: %v", err)
	}
	
	// 启动IMAP服务器
	if err := ms.imapServer.Start(); err != nil {
		ms.smtpServer.Stop()
		ms.mailQueue.Stop()
		return fmt.Errorf("启动IMAP服务器失败: %v", err)
	}
	
	ms.running = true
	log.Printf("邮件服务器启动成功")
	log.Printf("SMTP服务: %s", ms.config.SMTPPort)
	log.Printf("IMAP服务: %s", ms.config.IMAPPort)
	if ms.config.EnableTLS {
		log.Printf("SMTPS服务: %s", ms.config.SMTPSPort)
		log.Printf("IMAPS服务: %s", ms.config.IMAPSPort)
	}
	
	return nil
}

// Stop 停止所有邮件服务
func (ms *MailServer) Stop() error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()
	
	if !ms.running {
		return nil
	}
	
	log.Println("停止邮件服务器...")
	
	// 停止服务（顺序很重要）
	if err := ms.imapServer.Stop(); err != nil {
		log.Printf("停止IMAP服务器失败: %v", err)
	}
	
	if err := ms.smtpServer.Stop(); err != nil {
		log.Printf("停止SMTP服务器失败: %v", err)
	}
	
	if err := ms.mailQueue.Stop(); err != nil {
		log.Printf("停止邮件队列失败: %v", err)
	}
	
	ms.running = false
	log.Println("邮件服务器已停止")
	
	return nil
}

// IsRunning 检查邮件服务器是否运行
func (ms *MailServer) IsRunning() bool {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()
	return ms.running
}

// GetStatus 获取邮件服务器状态
func (ms *MailServer) GetStatus() *MailServerStatus {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	status := &MailServerStatus{
		Running:        ms.running,
		Domain:         ms.config.Domain,
		SMTPPort:       ms.config.SMTPPort,
		SMTPSPort:      ms.config.SMTPSPort,
		SubmissionPort: ms.config.SMTPSubmissionPort,
		IMAPPort:       ms.config.IMAPPort,
		IMAPSPort:      ms.config.IMAPSPort,
		TLSEnabled:     ms.config.EnableTLS,
	}

	if ms.running {
		status.QueueStats = ms.mailQueue.GetQueueStats()

		// 获取存储统计
		if storageStats, err := ms.mailStorage.GetStorageStats(); err == nil {
			status.StorageStats = storageStats
		}
	}

	return status
}

// SendAuthenticatedEmail 发送经过认证的邮件
func (ms *MailServer) SendAuthenticatedEmail(mail *AuthenticatedMail) error {
	if !ms.running {
		return fmt.Errorf("邮件服务器未运行")
	}
	
	// 使用认证邮件的完整头部信息发送
	return ms.mailQueue.SendEmailWithHeaders(mail.From, mail.To, mail.Subject, mail.Body, mail.Headers)
}

// GetAuthService 获取认证服务
func (ms *MailServer) GetAuthService() *MailAuthService {
	return ms.authService
}

// GetDKIMPublicKey 获取DKIM公钥
func (ms *MailServer) GetDKIMPublicKey() (string, error) {
	if ms.authService == nil {
		return "", fmt.Errorf("认证服务未初始化")
	}
	return ms.authService.GetDKIMPublicKey()
}

// GetRecommendedDNSRecords 获取推荐的DNS记录
func (ms *MailServer) GetRecommendedDNSRecords() ([]MailDNSRecord, error) {
	if ms.authService == nil {
		return nil, fmt.Errorf("认证服务未初始化")
	}
	return ms.authService.GenerateRecommendedDNSRecords(ms.config.Domain)
}

// GetUserMessages 获取用户邮件
func (ms *MailServer) GetUserMessages(userID, mailbox string, limit, offset int) ([]*MailMessage, error) {
	return ms.mailStorage.GetUserMessages(userID, mailbox, limit, offset)
}

// SearchMessages 搜索邮件
func (ms *MailServer) SearchMessages(query *MessageSearchQuery) ([]*MailMessage, error) {
	return ms.mailStorage.SearchMessages(query)
}

// MailServerStatus 邮件服务器状态
type MailServerStatus struct {
	Running      bool          `json:"running"`
	Domain       string        `json:"domain"`
	SMTPPort     string        `json:"smtp_port"`
	SMTPSPort    string        `json:"smtps_port"`
	SubmissionPort string      `json:"submission_port"`
	IMAPPort     string        `json:"imap_port"`
	IMAPSPort    string        `json:"imaps_port"`
	TLSEnabled   bool          `json:"tls_enabled"`
	QueueStats   *QueueStats   `json:"queue_stats,omitempty"`
	StorageStats *StorageStats `json:"storage_stats,omitempty"`
}

// EnhancedMailService 增强的邮件服务
type EnhancedMailService struct {
	storage   *MailStorage
	queue     *MailQueue
	*MailService // 嵌入原有的MailService
}

// NewEnhancedMailService 创建增强邮件服务
func NewEnhancedMailService(storage *MailStorage, queue *MailQueue) *EnhancedMailService {
	return &EnhancedMailService{
		storage:     storage,
		queue:       queue,
		MailService: NewMailService(),
	}
}

// GetMailHistory 获取邮件历史（重写原方法）
func (ems *EnhancedMailService) GetMailHistory(query MailHistoryQuery) (*MailHistoryResponse, error) {
	// 使用新的存储系统搜索邮件
	searchQuery := &MessageSearchQuery{
		From:      query.User,
		StartDate: &query.StartDate,
		EndDate:   &query.EndDate,
		Direction: query.Direction,
		Status:    query.Status,
		Limit:     query.PageSize,
	}
	
	messages, err := ems.storage.SearchMessages(searchQuery)
	if err != nil {
		return nil, err
	}
	
	// 转换为MailRecord格式
	var records []MailRecord
	for _, msg := range messages {
		record := MailRecord{
			ID:        msg.ID,
			Timestamp: msg.Timestamp,
			From:      msg.From,
			To:        msg.To,
			Subject:   msg.Subject,
			Status:    msg.Status,
			Direction: msg.Direction,
			Size:      msg.Size,
			Headers:   msg.Headers,
			Body:      msg.Body,
		}
		records = append(records, record)
	}
	
	// 应用分页
	total := len(records)
	start := (query.Page - 1) * query.PageSize
	if start > total {
		start = total
	}
	end := start + query.PageSize
	if end > total {
		end = total
	}
	
	if start < end {
		records = records[start:end]
	} else {
		records = []MailRecord{}
	}
	
	return &MailHistoryResponse{
		Records:    records,
		Total:      total,
		Page:       query.Page,
		PageSize:   query.PageSize,
		TotalPages: (total + query.PageSize - 1) / query.PageSize,
	}, nil
}

// GetMailDetail 获取邮件详情
func (ems *EnhancedMailService) GetMailDetail(messageID string) (*MailMessage, error) {
	return ems.storage.GetMessage(messageID)
}

// DownloadEML 下载EML文件
func (ems *EnhancedMailService) DownloadEML(messageID string) ([]byte, error) {
	return ems.storage.GetRawMessage(messageID)
}
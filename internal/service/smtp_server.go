package service

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/jhillyerd/enmime"
	"github.com/google/uuid"
)

// SMTPServer SMTP服务器
type SMTPServer struct {
	server      *smtp.Server
	mailService *MailService
	userService *UserService
	domainService *DomainService
	storage     *MailStorage
	config      *SMTPConfig
}

// SMTPConfig SMTP配置
type SMTPConfig struct {
	ListenAddr     string
	TLSListenAddr  string
	Domain         string
	MaxMessageSize int64
	MaxRecipients  int
	TLSConfig      *tls.Config
}

// SMTPBackend SMTP后端处理器
type SMTPBackend struct {
	server *SMTPServer
}

// SMTPSession SMTP会话
type SMTPSession struct {
	backend *SMTPBackend
	from    string
	to      []string
	domain  string
}

// NewSMTPServer 创建SMTP服务器
func NewSMTPServer(config *SMTPConfig, mailService *MailService, userService *UserService, domainService *DomainService, storage *MailStorage) *SMTPServer {
	smtpServer := &SMTPServer{
		mailService:   mailService,
		userService:   userService,
		domainService: domainService,
		storage:       storage,
		config:        config,
	}

	backend := &SMTPBackend{server: smtpServer}
	
	server := smtp.NewServer(backend)
	server.Addr = config.ListenAddr
	server.Domain = config.Domain
	server.MaxMessageBytes = config.MaxMessageSize
	server.MaxRecipients = config.MaxRecipients
	server.AllowInsecureAuth = false
	server.AuthDisabled = false
	
	if config.TLSConfig != nil {
		server.TLSConfig = config.TLSConfig
	}

	smtpServer.server = server
	return smtpServer
}

// Start 启动SMTP服务器
func (s *SMTPServer) Start() error {
	log.Printf("启动SMTP服务器在 %s", s.config.ListenAddr)
	
	// 启动普通SMTP服务
	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			log.Printf("SMTP服务器错误: %v", err)
		}
	}()

	// 启动SMTPS服务（如果配置了TLS）
	if s.config.TLSListenAddr != "" && s.config.TLSConfig != nil {
		go func() {
			log.Printf("启动SMTPS服务器在 %s", s.config.TLSListenAddr)
			listener, err := tls.Listen("tcp", s.config.TLSListenAddr, s.config.TLSConfig)
			if err != nil {
				log.Printf("SMTPS监听失败: %v", err)
				return
			}
			if err := s.server.Serve(listener); err != nil {
				log.Printf("SMTPS服务器错误: %v", err)
			}
		}()
	}

	return nil
}

// Stop 停止SMTP服务器
func (s *SMTPServer) Stop() error {
	log.Println("停止SMTP服务器")
	return s.server.Close()
}

// NewSession 创建新的SMTP会话
func (b *SMTPBackend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	return &SMTPSession{
		backend: b,
		domain:  b.server.config.Domain,
	}, nil
}

// AuthPlain 处理PLAIN认证
func (s *SMTPSession) AuthPlain(username, password string) error {
	log.Printf("SMTP认证尝试: %s", username)
	
	// 验证用户凭据
	user, err := s.backend.server.userService.AuthenticateUser(username, password)
	if err != nil {
		log.Printf("SMTP认证失败: %s - %v", username, err)
		return fmt.Errorf("认证失败")
	}
	
	if !user.Active {
		log.Printf("SMTP认证失败: 用户已停用 %s", username)
		return fmt.Errorf("账户已停用")
	}
	
	log.Printf("SMTP认证成功: %s", username)
	return nil
}

// Mail 处理MAIL FROM命令
func (s *SMTPSession) Mail(from string, opts *smtp.MailOptions) error {
	log.Printf("SMTP MAIL FROM: %s", from)
	
	// 验证发件人域名
	domain := extractDomain(from)
	if !s.backend.server.domainService.IsDomainManaged(domain) {
		return fmt.Errorf("未管理的域名: %s", domain)
	}
	
	s.from = from
	return nil
}

// Rcpt 处理RCPT TO命令
func (s *SMTPSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	log.Printf("SMTP RCPT TO: %s", to)
	
	// 验证收件人
	domain := extractDomain(to)
	
	// 检查是否为本地域名
	if s.backend.server.domainService.IsDomainManaged(domain) {
		// 检查本地用户是否存在
		user, err := s.backend.server.userService.GetUserByEmail(to)
		if err != nil || user == nil {
			return fmt.Errorf("收件人不存在: %s", to)
		}
		if !user.Active {
			return fmt.Errorf("收件人账户已停用: %s", to)
		}
	}
	
	s.to = append(s.to, to)
	return nil
}

// Data 处理邮件内容
func (s *SMTPSession) Data(r io.Reader) error {
	log.Printf("SMTP DATA: 从 %s 到 %v", s.from, s.to)
	
	// 生成邮件ID
	messageID := uuid.New().String()
	
	// 读取邮件内容
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("读取邮件内容失败: %v", err)
	}
	
	// 解析邮件
	envelope, err := enmime.ReadEnvelope(strings.NewReader(string(data)))
	if err != nil {
		log.Printf("解析邮件失败: %v", err)
		// 即使解析失败也要保存原始内容
	}
	
	subject := ""
	headers := make(map[string]string)
	body := string(data)
	
	if envelope != nil {
		subject = envelope.GetHeader("Subject")
		// 提取重要头部信息
		for _, header := range []string{"From", "To", "Subject", "Date", "Message-ID", "Content-Type"} {
			if value := envelope.GetHeader(header); value != "" {
				headers[header] = value
			}
		}
		if envelope.Text != "" {
			body = envelope.Text
		} else if envelope.HTML != "" {
			body = envelope.HTML
		}
	}
	
	// 创建邮件记录
	mailRecord := &MailMessage{
		ID:          messageID,
		From:        s.from,
		To:          s.to,
		Subject:     subject,
		Body:        body,
		RawData:     string(data),
		Headers:     headers,
		Timestamp:   time.Now(),
		Status:      "received",
		Direction:   "inbound",
		Size:        int64(len(data)),
	}
	
	// 处理邮件投递
	for _, recipient := range s.to {
		if err := s.deliverMail(mailRecord, recipient); err != nil {
			log.Printf("投递邮件失败 %s -> %s: %v", s.from, recipient, err)
			// 对于投递失败的邮件，我们仍然记录但标记状态
			mailRecord.Status = "delivery_failed"
			mailRecord.ErrorMessage = err.Error()
		}
	}
	
	// 保存到存储
	if err := s.backend.server.storage.StoreMessage(mailRecord); err != nil {
		log.Printf("保存邮件失败: %v", err)
		return fmt.Errorf("保存邮件失败")
	}
	
	log.Printf("邮件处理完成: %s", messageID)
	return nil
}

// deliverMail 投递邮件
func (s *SMTPSession) deliverMail(mail *MailMessage, recipient string) error {
	domain := extractDomain(recipient)
	
	// 检查是否为本地域名
	if s.backend.server.domainService.IsDomainManaged(domain) {
		// 本地投递
		return s.deliverLocalMail(mail, recipient)
	} else {
		// 远程投递
		return s.deliverRemoteMail(mail, recipient)
	}
}

// deliverLocalMail 本地邮件投递
func (s *SMTPSession) deliverLocalMail(mail *MailMessage, recipient string) error {
	log.Printf("本地投递邮件: %s", recipient)
	
	// 获取用户信息
	user, err := s.backend.server.userService.GetUserByEmail(recipient)
	if err != nil {
		return fmt.Errorf("获取用户信息失败: %v", err)
	}
	
	// 检查配额
	if user.Quota > 0 && user.UsedQuota+mail.Size > user.Quota {
		return fmt.Errorf("用户配额不足: %s", recipient)
	}
	
	// 更新用户使用配额
	user.UsedQuota += mail.Size
	if err := s.backend.server.userService.SaveUser(user.ID, user); err != nil {
		log.Printf("更新用户配额失败: %v", err)
	}
	
	// 保存到用户邮箱
	return s.backend.server.storage.StoreUserMessage(user.ID, mail)
}

// deliverRemoteMail 远程邮件投递
func (s *SMTPSession) deliverRemoteMail(mail *MailMessage, recipient string) error {
	log.Printf("远程投递邮件: %s", recipient)
	
	domain := extractDomain(recipient)
	
	// 查询MX记录
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return fmt.Errorf("查询MX记录失败 %s: %v", domain, err)
	}
	
	if len(mxRecords) == 0 {
		return fmt.Errorf("未找到MX记录: %s", domain)
	}
	
	// 尝试连接到MX服务器投递邮件
	for _, mx := range mxRecords {
		if err := s.relayToMX(mail, recipient, mx.Host); err == nil {
			log.Printf("成功投递到 %s via %s", recipient, mx.Host)
			return nil
		} else {
			log.Printf("投递失败到 %s via %s: %v", recipient, mx.Host, err)
		}
	}
	
	return fmt.Errorf("所有MX服务器投递失败: %s", domain)
}

// relayToMX 转发到MX服务器
func (s *SMTPSession) relayToMX(mail *MailMessage, recipient string, mxHost string) error {
	// 连接到远程SMTP服务器
	conn, err := smtp.Dial(mxHost + ":25")
	if err != nil {
		return fmt.Errorf("连接MX服务器失败: %v", err)
	}
	defer conn.Close()
	
	// HELO
	if err := conn.Hello(s.domain); err != nil {
		return fmt.Errorf("HELO失败: %v", err)
	}
	
	// 尝试STARTTLS
	if ok, _ := conn.Extension("STARTTLS"); ok {
		tlsConfig := &tls.Config{ServerName: mxHost}
		if err := conn.StartTLS(tlsConfig); err != nil {
			log.Printf("STARTTLS失败 (继续明文): %v", err)
		}
	}
	
	// MAIL FROM
	if err := conn.Mail(mail.From, nil); err != nil {
		return fmt.Errorf("MAIL FROM失败: %v", err)
	}
	
	// RCPT TO
	if err := conn.Rcpt(recipient, nil); err != nil {
		return fmt.Errorf("RCPT TO失败: %v", err)
	}
	
	// DATA
	writer, err := conn.Data()
	if err != nil {
		return fmt.Errorf("DATA失败: %v", err)
	}
	
	if _, err := writer.Write([]byte(mail.RawData)); err != nil {
		writer.Close()
		return fmt.Errorf("发送数据失败: %v", err)
	}
	
	if err := writer.Close(); err != nil {
		return fmt.Errorf("完成数据发送失败: %v", err)
	}
	
	return nil
}

// Reset 重置会话
func (s *SMTPSession) Reset() {
	s.from = ""
	s.to = nil
}

// Logout 登出会话
func (s *SMTPSession) Logout() error {
	return nil
}

// extractDomain 从邮箱地址提取域名
func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(parts[1])
}
package service

import (
	"container/list"
	"fmt"
	"log"
	"sync"
	"time"
)

// MailQueue 邮件队列服务
type MailQueue struct {
	outboundQueue *list.List
	retryQueue    *list.List
	mutex         sync.RWMutex
	running       bool
	stopChan      chan bool
	smtpServer    *SMTPServer
	storage       *MailStorage
	config        *QueueConfig
}

// QueueConfig 队列配置
type QueueConfig struct {
	MaxRetries      int           // 最大重试次数
	RetryInterval   time.Duration // 重试间隔
	ProcessInterval time.Duration // 处理间隔
	MaxConcurrent   int           // 最大并发数
}

// QueuedMessage 队列中的邮件
type QueuedMessage struct {
	ID           string            `json:"id"`
	From         string            `json:"from"`
	To           []string          `json:"to"`
	RawData      string            `json:"raw_data"`
	Headers      map[string]string `json:"headers"`
	Subject      string            `json:"subject"`
	Priority     int               `json:"priority"`
	RetryCount   int               `json:"retry_count"`
	LastAttempt  time.Time         `json:"last_attempt"`
	NextAttempt  time.Time         `json:"next_attempt"`
	CreatedAt    time.Time         `json:"created_at"`
	Status       string            `json:"status"` // queued, processing, sent, failed
	ErrorMessage string            `json:"error_message,omitempty"`
}

// NewMailQueue 创建邮件队列
func NewMailQueue(config *QueueConfig, smtpServer *SMTPServer, storage *MailStorage) *MailQueue {
	return &MailQueue{
		outboundQueue: list.New(),
		retryQueue:    list.New(),
		stopChan:      make(chan bool),
		smtpServer:    smtpServer,
		storage:       storage,
		config:        config,
	}
}

// Start 启动队列处理
func (q *MailQueue) Start() error {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	
	if q.running {
		return fmt.Errorf("邮件队列已在运行")
	}
	
	q.running = true
	log.Println("启动邮件队列处理器")
	
	// 启动主处理协程
	go q.processQueue()
	
	// 启动重试处理协程
	go q.processRetryQueue()
	
	return nil
}

// Stop 停止队列处理
func (q *MailQueue) Stop() error {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	
	if !q.running {
		return nil
	}
	
	log.Println("停止邮件队列处理器")
	q.running = false
	close(q.stopChan)
	
	return nil
}

// Enqueue 入队邮件
func (q *MailQueue) Enqueue(msg *QueuedMessage) error {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	
	if msg.ID == "" {
		msg.ID = fmt.Sprintf("queue-%d", time.Now().UnixNano())
	}
	
	msg.Status = "queued"
	msg.CreatedAt = time.Now()
	msg.NextAttempt = time.Now()
	
	q.outboundQueue.PushBack(msg)
	
	log.Printf("邮件入队: %s -> %v (队列长度: %d)", msg.From, msg.To, q.outboundQueue.Len())
	
	return nil
}

// processQueue 处理主队列
func (q *MailQueue) processQueue() {
	ticker := time.NewTicker(q.config.ProcessInterval)
	defer ticker.Stop()
	
	semaphore := make(chan struct{}, q.config.MaxConcurrent)
	
	for {
		select {
		case <-q.stopChan:
			return
		case <-ticker.C:
			q.processOutboundMessages(semaphore)
		}
	}
}

// processOutboundMessages 处理出站邮件
func (q *MailQueue) processOutboundMessages(semaphore chan struct{}) {
	q.mutex.Lock()
	var messages []*QueuedMessage
	
	// 收集待处理的邮件
	for e := q.outboundQueue.Front(); e != nil; {
		next := e.Next()
		msg := e.Value.(*QueuedMessage)
		
		if msg.NextAttempt.Before(time.Now()) || msg.NextAttempt.Equal(time.Now()) {
			messages = append(messages, msg)
			q.outboundQueue.Remove(e)
		}
		
		e = next
	}
	q.mutex.Unlock()
	
	// 并发处理邮件
	for _, msg := range messages {
		select {
		case semaphore <- struct{}{}:
			go func(msg *QueuedMessage) {
				defer func() { <-semaphore }()
				q.deliverMessage(msg)
			}(msg)
		case <-q.stopChan:
			return
		}
	}
}

// deliverMessage 投递邮件
func (q *MailQueue) deliverMessage(msg *QueuedMessage) {
	log.Printf("处理队列邮件: %s -> %v (尝试 %d/%d)", 
		msg.From, msg.To, msg.RetryCount+1, q.config.MaxRetries)
	
	msg.Status = "processing"
	msg.LastAttempt = time.Now()
	msg.RetryCount++
	
	// 创建邮件消息对象
	mailMsg := &MailMessage{
		ID:        msg.ID,
		From:      msg.From,
		To:        msg.To,
		Subject:   msg.Subject,
		RawData:   msg.RawData,
		Headers:   msg.Headers,
		Timestamp: time.Now(),
		Status:    "sending",
		Direction: "outbound",
		Size:      int64(len(msg.RawData)),
	}
	
	// 尝试投递给每个收件人
	var failedRecipients []string
	var lastError error
	
	for _, recipient := range msg.To {
		if err := q.deliverToRecipient(mailMsg, recipient); err != nil {
			log.Printf("投递失败 %s -> %s: %v", msg.From, recipient, err)
			failedRecipients = append(failedRecipients, recipient)
			lastError = err
		} else {
			log.Printf("投递成功 %s -> %s", msg.From, recipient)
		}
	}
	
	if len(failedRecipients) == 0 {
		// 全部投递成功
		msg.Status = "sent"
		now := time.Now()
		mailMsg.DeliveryTime = &now
		mailMsg.Status = "sent"
		
		log.Printf("邮件投递完成: %s", msg.ID)
	} else {
		// 部分或全部投递失败
		msg.To = failedRecipients
		msg.ErrorMessage = lastError.Error()
		
		if msg.RetryCount >= q.config.MaxRetries {
			// 超过重试次数，标记为失败
			msg.Status = "failed"
			mailMsg.Status = "failed"
			mailMsg.ErrorMessage = fmt.Sprintf("投递失败，已达到最大重试次数: %v", lastError)
			
			log.Printf("邮件投递失败（最终）: %s -> %v", msg.From, failedRecipients)
		} else {
			// 加入重试队列
			msg.Status = "queued"
			msg.NextAttempt = time.Now().Add(q.calculateRetryDelay(msg.RetryCount))
			
			q.mutex.Lock()
			q.retryQueue.PushBack(msg)
			q.mutex.Unlock()
			
			log.Printf("邮件加入重试队列: %s -> %v (下次尝试: %v)", 
				msg.From, failedRecipients, msg.NextAttempt)
		}
	}
	
	// 保存邮件记录
	if err := q.storage.StoreMessage(mailMsg); err != nil {
		log.Printf("保存邮件记录失败: %v", err)
	}
}

// deliverToRecipient 投递给特定收件人
func (q *MailQueue) deliverToRecipient(msg *MailMessage, recipient string) error {
	domain := extractDomain(recipient)
	
	// 检查是否为本地域名
	if q.smtpServer.domainService.IsDomainManaged(domain) {
		// 本地投递
		return q.deliverLocalMessage(msg, recipient)
	} else {
		// 远程投递
		return q.deliverRemoteMessage(msg, recipient)
	}
}

// deliverLocalMessage 本地邮件投递
func (q *MailQueue) deliverLocalMessage(msg *MailMessage, recipient string) error {
	// 获取用户信息
	user, err := q.smtpServer.userService.GetUserByEmail(recipient)
	if err != nil {
		return fmt.Errorf("获取用户信息失败: %v", err)
	}
	
	if !user.Active {
		return fmt.Errorf("用户账户已停用: %s", recipient)
	}
	
	// 检查配额
	if user.Quota > 0 && user.UsedQuota+msg.Size > user.Quota {
		return fmt.Errorf("用户配额不足: %s", recipient)
	}
	
	// 保存到用户邮箱
	if err := q.storage.StoreUserMessage(user.ID, msg); err != nil {
		return fmt.Errorf("保存到用户邮箱失败: %v", err)
	}
	
	// 更新用户使用配额
	user.UsedQuota += msg.Size
	if err := q.smtpServer.userService.SaveUser(user.ID, user); err != nil {
		log.Printf("更新用户配额失败: %v", err)
	}
	
	return nil
}

// deliverRemoteMessage 远程邮件投递
func (q *MailQueue) deliverRemoteMessage(msg *MailMessage, recipient string) error {
	// 使用SMTP会话的远程投递逻辑
	session := &SMTPSession{
		backend: q.smtpServer.server.Backend.(*SMTPBackend),
		from:    msg.From,
		to:      []string{recipient},
		domain:  q.smtpServer.config.Domain,
	}
	
	return session.deliverRemoteMail(msg, recipient)
}

// processRetryQueue 处理重试队列
func (q *MailQueue) processRetryQueue() {
	ticker := time.NewTicker(q.config.RetryInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-q.stopChan:
			return
		case <-ticker.C:
			q.moveRetryToOutbound()
		}
	}
}

// moveRetryToOutbound 将重试队列中的邮件移动到出站队列
func (q *MailQueue) moveRetryToOutbound() {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	
	now := time.Now()
	for e := q.retryQueue.Front(); e != nil; {
		next := e.Next()
		msg := e.Value.(*QueuedMessage)
		
		if msg.NextAttempt.Before(now) || msg.NextAttempt.Equal(now) {
			q.retryQueue.Remove(e)
			q.outboundQueue.PushBack(msg)
		}
		
		e = next
	}
}

// calculateRetryDelay 计算重试延迟（指数退避）
func (q *MailQueue) calculateRetryDelay(retryCount int) time.Duration {
	baseDelay := q.config.RetryInterval
	delay := time.Duration(1<<uint(retryCount)) * baseDelay
	
	// 限制最大延迟时间为1小时
	maxDelay := time.Hour
	if delay > maxDelay {
		delay = maxDelay
	}
	
	return delay
}

// GetQueueStats 获取队列统计信息
func (q *MailQueue) GetQueueStats() *QueueStats {
	q.mutex.RLock()
	defer q.mutex.RUnlock()
	
	stats := &QueueStats{
		OutboundQueue: q.outboundQueue.Len(),
		RetryQueue:    q.retryQueue.Len(),
		Running:       q.running,
	}
	
	return stats
}

// QueueStats 队列统计信息
type QueueStats struct {
	OutboundQueue int  `json:"outbound_queue"`
	RetryQueue    int  `json:"retry_queue"`
	Running       bool `json:"running"`
}

// SendEmail 发送邮件（公开接口）
func (q *MailQueue) SendEmail(from string, to []string, subject string, body string, headers map[string]string) error {
	// 构建原始邮件数据
	rawData := q.buildRawMessage(from, to, subject, body, headers)
	
	msg := &QueuedMessage{
		From:     from,
		To:       to,
		Subject:  subject,
		RawData:  rawData,
		Headers:  headers,
		Priority: 0,
	}
	
	return q.Enqueue(msg)
}

// buildRawMessage 构建原始邮件格式
func (q *MailQueue) buildRawMessage(from string, to []string, subject string, body string, headers map[string]string) string {
	var rawMessage string
	
	// 基本头部
	rawMessage += fmt.Sprintf("From: %s\r\n", from)
	rawMessage += fmt.Sprintf("To: %s\r\n", joinStrings(to, ", "))
	rawMessage += fmt.Sprintf("Subject: %s\r\n", subject)
	rawMessage += fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	rawMessage += "Content-Type: text/plain; charset=utf-8\r\n"
	rawMessage += "MIME-Version: 1.0\r\n"
	
	// 自定义头部
	for key, value := range headers {
		if !isStandardHeader(key) {
			rawMessage += fmt.Sprintf("%s: %s\r\n", key, value)
		}
	}
	
	// 空行分隔头部和正文
	rawMessage += "\r\n"
	
	// 邮件正文
	rawMessage += body
	
	return rawMessage
}

// joinStrings 连接字符串
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}
	
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

// isStandardHeader 检查是否为标准头部
func isStandardHeader(header string) bool {
	standardHeaders := map[string]bool{
		"From":         true,
		"To":           true,
		"Cc":           true,
		"Bcc":          true,
		"Subject":      true,
		"Date":         true,
		"Content-Type": true,
		"MIME-Version": true,
	}
	return standardHeaders[header]
}

// SendEmailWithHeaders 发送邮件（完整头部版本）
func (q *MailQueue) SendEmailWithHeaders(from string, to []string, subject string, body string, headers map[string]string) error {
	// 这是SendEmail的别名方法，因为原方法已经支持完整头部信息
	return q.SendEmail(from, to, subject, body, headers)
}
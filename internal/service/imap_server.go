package service

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
	"github.com/emersion/go-imap/server"
	"github.com/emersion/go-message"
)

// IMAPServer IMAP服务器
type IMAPServer struct {
	server      *server.Server
	backend     *IMAPBackend
	config      *IMAPConfig
	storage     *MailStorage
	userService *UserService
}

// IMAPConfig IMAP配置
type IMAPConfig struct {
	ListenAddr    string
	TLSListenAddr string
	Domain        string
	TLSConfig     *tls.Config
}

// IMAPBackend IMAP后端
type IMAPBackend struct {
	storage     *MailStorage
	userService *UserService
	users       map[string]*IMAPUser
	mutex       sync.RWMutex
}

// IMAPUser IMAP用户
type IMAPUser struct {
	userID      string
	email       string
	storage     *MailStorage
	userService *UserService
	mailboxes   map[string]*IMAPMailbox
	mutex       sync.RWMutex
}

// IMAPMailbox IMAP邮箱
type IMAPMailbox struct {
	name        string
	user        *IMAPUser
	messages    map[uint32]*IMAPMessage
	lastUID     uint32
	uidValidity uint32
	flags       []string
	subscribed  bool
	mutex       sync.RWMutex
}

// IMAPMessage IMAP消息
type IMAPMessage struct {
	uid       uint32
	seqNum    uint32
	flags     []string
	date      time.Time
	size      uint32
	envelope  *imap.Envelope
	bodyStructure *imap.BodyStructure
	message   *MailMessage
}

// NewIMAPServer 创建IMAP服务器
func NewIMAPServer(config *IMAPConfig, storage *MailStorage, userService *UserService) *IMAPServer {
	backend := &IMAPBackend{
		storage:     storage,
		userService: userService,
		users:       make(map[string]*IMAPUser),
	}
	
	imapServer := server.New(backend)
	imapServer.Addr = config.ListenAddr
	imapServer.AllowInsecureAuth = false
	
	if config.TLSConfig != nil {
		imapServer.TLSConfig = config.TLSConfig
	}
	
	return &IMAPServer{
		server:      imapServer,
		backend:     backend,
		config:      config,
		storage:     storage,
		userService: userService,
	}
}

// Start 启动IMAP服务器
func (s *IMAPServer) Start() error {
	log.Printf("启动IMAP服务器在 %s", s.config.ListenAddr)
	
	// 启动普通IMAP服务
	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			log.Printf("IMAP服务器错误: %v", err)
		}
	}()
	
	// 启动IMAPS服务（如果配置了TLS）
	if s.config.TLSListenAddr != "" && s.config.TLSConfig != nil {
		go func() {
			log.Printf("启动IMAPS服务器在 %s", s.config.TLSListenAddr)
			listener, err := tls.Listen("tcp", s.config.TLSListenAddr, s.config.TLSConfig)
			if err != nil {
				log.Printf("IMAPS监听失败: %v", err)
				return
			}
			if err := s.server.Serve(listener); err != nil {
				log.Printf("IMAPS服务器错误: %v", err)
			}
		}()
	}
	
	return nil
}

// Stop 停止IMAP服务器
func (s *IMAPServer) Stop() error {
	log.Println("停止IMAP服务器")
	return s.server.Close()
}

// Login 用户登录
func (b *IMAPBackend) Login(connInfo *imap.ConnInfo, username, password string) (backend.User, error) {
	log.Printf("IMAP登录尝试: %s", username)
	
	// 验证用户凭据
	user, err := b.userService.AuthenticateUser(username, password)
	if err != nil {
		log.Printf("IMAP认证失败: %s - %v", username, err)
		return nil, fmt.Errorf("认证失败")
	}
	
	if !user.Active {
		log.Printf("IMAP认证失败: 用户已停用 %s", username)
		return nil, fmt.Errorf("账户已停用")
	}
	
	log.Printf("IMAP认证成功: %s", username)
	
	b.mutex.Lock()
	defer b.mutex.Unlock()
	
	imapUser, exists := b.users[user.ID]
	if !exists {
		imapUser = &IMAPUser{
			userID:      user.ID,
			email:       user.Email,
			storage:     b.storage,
			userService: b.userService,
			mailboxes:   make(map[string]*IMAPMailbox),
		}
		b.users[user.ID] = imapUser
	}
	
	// 初始化用户邮箱
	if err := imapUser.initializeMailboxes(); err != nil {
		return nil, fmt.Errorf("初始化邮箱失败: %v", err)
	}
	
	return imapUser, nil
}

// initializeMailboxes 初始化用户邮箱
func (u *IMAPUser) initializeMailboxes() error {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	
	// 从存储加载用户邮箱
	userMailbox, err := u.storage.GetUserMailbox(u.userID)
	if err != nil {
		return err
	}
	
	// 确保INBOX存在
	if _, exists := userMailbox.Mailboxes["INBOX"]; !exists {
		userMailbox.Mailboxes["INBOX"] = &MailBox{
			Name:        "INBOX",
			Messages:    make(map[string]*MailMessage),
			LastUID:     0,
			UIDValidity: uint32(time.Now().Unix()),
			Subscribed:  true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
	}
	
	// 创建IMAP邮箱对象
	for name, mailbox := range userMailbox.Mailboxes {
		imapMailbox := &IMAPMailbox{
			name:        name,
			user:        u,
			messages:    make(map[uint32]*IMAPMessage),
			lastUID:     mailbox.LastUID,
			uidValidity: mailbox.UIDValidity,
			flags:       []string{imap.SeenFlag, imap.AnsweredFlag, imap.FlaggedFlag, imap.DeletedFlag, imap.DraftFlag},
			subscribed:  mailbox.Subscribed,
		}
		
		// 加载消息
		seqNum := uint32(1)
		for _, msg := range mailbox.Messages {
			imapMsg := &IMAPMessage{
				uid:       imapMailbox.lastUID,
				seqNum:    seqNum,
				flags:     []string{},
				date:      msg.Timestamp,
				size:      uint32(msg.Size),
				envelope:  buildEnvelope(msg),
				bodyStructure: buildBodyStructure(msg),
				message:   msg,
			}
			imapMailbox.messages[seqNum] = imapMsg
			seqNum++
		}
		
		u.mailboxes[name] = imapMailbox
	}
	
	return nil
}

// Username 获取用户名
func (u *IMAPUser) Username() string {
	return u.email
}

// ListMailboxes 列出邮箱
func (u *IMAPUser) ListMailboxes(subscribed bool) ([]backend.Mailbox, error) {
	u.mutex.RLock()
	defer u.mutex.RUnlock()
	
	var mailboxes []backend.Mailbox
	for _, mailbox := range u.mailboxes {
		if !subscribed || mailbox.subscribed {
			mailboxes = append(mailboxes, mailbox)
		}
	}
	
	return mailboxes, nil
}

// GetMailbox 获取邮箱
func (u *IMAPUser) GetMailbox(name string) (backend.Mailbox, error) {
	u.mutex.RLock()
	defer u.mutex.RUnlock()
	
	mailbox, exists := u.mailboxes[name]
	if !exists {
		return nil, fmt.Errorf("邮箱不存在: %s", name)
	}
	
	return mailbox, nil
}

// CreateMailbox 创建邮箱
func (u *IMAPUser) CreateMailbox(name string) error {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	
	if _, exists := u.mailboxes[name]; exists {
		return fmt.Errorf("邮箱已存在: %s", name)
	}
	
	mailbox := &IMAPMailbox{
		name:        name,
		user:        u,
		messages:    make(map[uint32]*IMAPMessage),
		lastUID:     0,
		uidValidity: uint32(time.Now().Unix()),
		flags:       []string{imap.SeenFlag, imap.AnsweredFlag, imap.FlaggedFlag, imap.DeletedFlag, imap.DraftFlag},
		subscribed:  true,
	}
	
	u.mailboxes[name] = mailbox
	return nil
}

// DeleteMailbox 删除邮箱
func (u *IMAPUser) DeleteMailbox(name string) error {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	
	if name == "INBOX" {
		return fmt.Errorf("不能删除INBOX")
	}
	
	if _, exists := u.mailboxes[name]; !exists {
		return fmt.Errorf("邮箱不存在: %s", name)
	}
	
	delete(u.mailboxes, name)
	return nil
}

// RenameMailbox 重命名邮箱
func (u *IMAPUser) RenameMailbox(existingName, newName string) error {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	
	if existingName == "INBOX" {
		return fmt.Errorf("不能重命名INBOX")
	}
	
	mailbox, exists := u.mailboxes[existingName]
	if !exists {
		return fmt.Errorf("邮箱不存在: %s", existingName)
	}
	
	if _, exists := u.mailboxes[newName]; exists {
		return fmt.Errorf("目标邮箱已存在: %s", newName)
	}
	
	mailbox.name = newName
	u.mailboxes[newName] = mailbox
	delete(u.mailboxes, existingName)
	
	return nil
}

// Logout 登出
func (u *IMAPUser) Logout() error {
	return nil
}

// Name 获取邮箱名称
func (m *IMAPMailbox) Name() string {
	return m.name
}

// Info 获取邮箱信息
func (m *IMAPMailbox) Info() (*imap.MailboxInfo, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	info := &imap.MailboxInfo{
		Attributes: []string{},
		Delimiter:  "/",
		Name:       m.name,
	}
	
	if m.name == "INBOX" {
		info.Attributes = append(info.Attributes, "\\Inbox")
	}
	
	return info, nil
}

// Status 获取邮箱状态
func (m *IMAPMailbox) Status(items []imap.StatusItem) (*imap.MailboxStatus, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	status := &imap.MailboxStatus{
		Name:        m.name,
		Messages:    uint32(len(m.messages)),
		UidNext:     m.lastUID + 1,
		UidValidity: m.uidValidity,
	}
	
	for _, item := range items {
		switch item {
		case imap.StatusMessages:
			status.Messages = uint32(len(m.messages))
		case imap.StatusUidNext:
			status.UidNext = m.lastUID + 1
		case imap.StatusUidValidity:
			status.UidValidity = m.uidValidity
		case imap.StatusRecent:
			status.Recent = 0 // 简化实现
		case imap.StatusUnseen:
			unseen := uint32(0)
			for _, msg := range m.messages {
				if !contains(msg.flags, imap.SeenFlag) {
					unseen++
				}
			}
			status.Unseen = unseen
		}
	}
	
	return status, nil
}

// SetSubscribed 设置订阅状态
func (m *IMAPMailbox) SetSubscribed(subscribed bool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	m.subscribed = subscribed
	return nil
}

// Check 检查邮箱
func (m *IMAPMailbox) Check() error {
	return nil
}

// ListMessages 列出消息
func (m *IMAPMailbox) ListMessages(uid bool, seqSet *imap.SeqSet, items []imap.FetchItem, ch chan<- *imap.Message) error {
	defer close(ch)
	
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	for seqNum, msg := range m.messages {
		var id uint32
		if uid {
			id = msg.uid
		} else {
			id = seqNum
		}
		
		if seqSet.Contains(id) {
			imapMsg := &imap.Message{
				SeqNum: seqNum,
				Uid:    msg.uid,
			}
			
			for _, item := range items {
				switch item {
				case imap.FetchEnvelope:
					imapMsg.Envelope = msg.envelope
				case imap.FetchBodyStructure:
					imapMsg.BodyStructure = msg.bodyStructure
				case imap.FetchFlags:
					imapMsg.Flags = msg.flags
				case imap.FetchInternalDate:
					imapMsg.InternalDate = msg.date
				case imap.FetchRFC822Size:
					imapMsg.Size = msg.size
				case imap.FetchUid:
					imapMsg.Uid = msg.uid
				case imap.FetchRFC822:
					if msg.message != nil {
						imapMsg.Body = map[*imap.BodySectionName]imap.Literal{
							{}: strings.NewReader(msg.message.RawData),
						}
					}
				}
			}
			
			ch <- imapMsg
		}
	}
	
	return nil
}

// SearchMessages 搜索消息
func (m *IMAPMailbox) SearchMessages(uid bool, criteria *imap.SearchCriteria) ([]uint32, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	var results []uint32
	
	for seqNum, msg := range m.messages {
		if m.matchesCriteria(msg, criteria) {
			if uid {
				results = append(results, msg.uid)
			} else {
				results = append(results, seqNum)
			}
		}
	}
	
	return results, nil
}

// CreateMessage 创建消息
func (m *IMAPMailbox) CreateMessage(flags []string, date time.Time, body imap.Literal) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// 读取消息内容
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	
	// 创建邮件消息
	mailMsg := &MailMessage{
		ID:        fmt.Sprintf("imap-%d-%d", time.Now().Unix(), m.lastUID+1),
		From:      m.user.email,
		To:        []string{m.user.email},
		Subject:   "IMAP Created Message",
		Body:      string(data),
		RawData:   string(data),
		Headers:   make(map[string]string),
		Timestamp: date,
		Status:    "stored",
		Direction: "internal",
		Size:      int64(len(data)),
	}
	
	// 解析邮件头
	if envelope, err := message.Read(strings.NewReader(string(data))); err == nil {
		if header := envelope.Header; header.Fields() != nil {
			if subject := header.Get("Subject"); subject != "" {
				mailMsg.Subject = subject
			}
			if from := header.Get("From"); from != "" {
				mailMsg.From = from
			}
			if to := header.Get("To"); to != "" {
				mailMsg.To = []string{to}
			}
		}
	}
	
	// 保存到存储
	if err := m.user.storage.StoreUserMessage(m.user.userID, mailMsg); err != nil {
		return err
	}
	
	// 创建IMAP消息
	m.lastUID++
	seqNum := uint32(len(m.messages) + 1)
	
	imapMsg := &IMAPMessage{
		uid:           m.lastUID,
		seqNum:        seqNum,
		flags:         flags,
		date:          date,
		size:          uint32(len(data)),
		envelope:      buildEnvelope(mailMsg),
		bodyStructure: buildBodyStructure(mailMsg),
		message:       mailMsg,
	}
	
	m.messages[seqNum] = imapMsg
	
	return nil
}

// UpdateMessagesFlags 更新消息标志
func (m *IMAPMailbox) UpdateMessagesFlags(uid bool, seqSet *imap.SeqSet, operation imap.FlagsOp, flags []string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	for seqNum, msg := range m.messages {
		var id uint32
		if uid {
			id = msg.uid
		} else {
			id = seqNum
		}
		
		if seqSet.Contains(id) {
			switch operation {
			case imap.SetFlags:
				msg.flags = flags
			case imap.AddFlags:
				for _, flag := range flags {
					if !contains(msg.flags, flag) {
						msg.flags = append(msg.flags, flag)
					}
				}
			case imap.RemoveFlags:
				for _, flag := range flags {
					msg.flags = removeString(msg.flags, flag)
				}
			}
		}
	}
	
	return nil
}

// CopyMessages 复制消息
func (m *IMAPMailbox) CopyMessages(uid bool, seqSet *imap.SeqSet, destName string) error {
	// 获取目标邮箱
	destMailbox, err := m.user.GetMailbox(destName)
	if err != nil {
		return err
	}
	
	dest := destMailbox.(*IMAPMailbox)
	
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	for seqNum, msg := range m.messages {
		var id uint32
		if uid {
			id = msg.uid
		} else {
			id = seqNum
		}
		
		if seqSet.Contains(id) {
			// 创建消息副本
			err := dest.CreateMessage(msg.flags, msg.date, strings.NewReader(msg.message.RawData))
			if err != nil {
				return err
			}
		}
	}
	
	return nil
}

// Expunge 清除已删除的消息
func (m *IMAPMailbox) Expunge() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	var seqNums []uint32
	for seqNum, msg := range m.messages {
		if contains(msg.flags, imap.DeletedFlag) {
			seqNums = append(seqNums, seqNum)
		}
	}
	
	for _, seqNum := range seqNums {
		delete(m.messages, seqNum)
	}
	
	return nil
}

// buildEnvelope 构建邮件信封
func buildEnvelope(msg *MailMessage) *imap.Envelope {
	env := &imap.Envelope{
		Date:      msg.Timestamp,
		Subject:   msg.Subject,
		From:      []*imap.Address{{PersonalName: "", MailboxName: extractLocalPart(msg.From), HostName: extractDomain(msg.From)}},
		ReplyTo:   []*imap.Address{},
		Cc:        []*imap.Address{},
		Bcc:       []*imap.Address{},
	}
	
	for _, to := range msg.To {
		env.To = append(env.To, &imap.Address{
			PersonalName: "",
			MailboxName:  extractLocalPart(to),
			HostName:     extractDomain(to),
		})
	}
	
	if msgID, exists := msg.Headers["Message-ID"]; exists {
		env.MessageId = msgID
	}
	
	return env
}

// buildBodyStructure 构建邮件体结构
func buildBodyStructure(msg *MailMessage) *imap.BodyStructure {
	return &imap.BodyStructure{
		MIMEType:    "text",
		MIMESubType: "plain",
		Params:      map[string]string{"charset": "utf-8"},
		Size:        uint32(len(msg.Body)),
	}
}

// matchesCriteria 检查消息是否匹配搜索条件
func (m *IMAPMailbox) matchesCriteria(msg *IMAPMessage, criteria *imap.SearchCriteria) bool {
	// 简化的搜索实现
	if len(criteria.Text) > 0 {
		for _, text := range criteria.Text {
			if !strings.Contains(strings.ToLower(msg.message.Subject), strings.ToLower(text)) &&
			   !strings.Contains(strings.ToLower(msg.message.Body), strings.ToLower(text)) {
				return false
			}
		}
	}
	
	if len(criteria.Header) > 0 {
		for header, values := range criteria.Header {
			if headerValue, exists := msg.message.Headers[header]; exists {
				found := false
				for _, value := range values {
					if strings.Contains(strings.ToLower(headerValue), strings.ToLower(value)) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			} else {
				return false
			}
		}
	}
	
	return true
}

// 辅助函数
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func removeString(slice []string, item string) []string {
	var result []string
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}

func extractLocalPart(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}
	return parts[0]
}
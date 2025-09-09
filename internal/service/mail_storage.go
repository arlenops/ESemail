package service

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MailStorage 邮件存储服务
type MailStorage struct {
	baseDir string
	mutex   sync.RWMutex
}

// MailMessage 邮件消息结构
type MailMessage struct {
	ID           string            `json:"id"`
	From         string            `json:"from"`
	To           []string          `json:"to"`
	Subject      string            `json:"subject"`
	Body         string            `json:"body"`
	RawData      string            `json:"raw_data"`
	Headers      map[string]string `json:"headers"`
	Timestamp    time.Time         `json:"timestamp"`
	Status       string            `json:"status"` // received, sent, failed, queued
	Direction    string            `json:"direction"` // inbound, outbound
	Size         int64             `json:"size"`
	Attachments  []MailAttachment  `json:"attachments,omitempty"`
	ErrorMessage string            `json:"error_message,omitempty"`
	DeliveryTime *time.Time        `json:"delivery_time,omitempty"`
}

// MailAttachment 邮件附件
type MailAttachment struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Data        []byte `json:"data,omitempty"`
	FilePath    string `json:"file_path,omitempty"`
}

// MailBox 邮箱结构
type MailBox struct {
	Name        string                 `json:"name"`
	Messages    map[string]*MailMessage `json:"messages"`
	LastUID     uint32                 `json:"last_uid"`
	UIDValidity uint32                 `json:"uid_validity"`
	Subscribed  bool                   `json:"subscribed"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// UserMailbox 用户邮箱
type UserMailbox struct {
	UserID    string              `json:"user_id"`
	Mailboxes map[string]*MailBox `json:"mailboxes"`
	mutex     sync.RWMutex        `json:"-"`
}

// NewMailStorage 创建邮件存储服务
func NewMailStorage(baseDir string) *MailStorage {
	storage := &MailStorage{
		baseDir: baseDir,
	}
	
	// 确保目录存在
	os.MkdirAll(filepath.Join(baseDir, "messages"), 0755)
	os.MkdirAll(filepath.Join(baseDir, "users"), 0755)
	os.MkdirAll(filepath.Join(baseDir, "attachments"), 0755)
	
	return storage
}

// StoreMessage 存储邮件消息
func (s *MailStorage) StoreMessage(msg *MailMessage) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	if msg.ID == "" {
		msg.ID = uuid.New().String()
	}
	
	// 存储邮件元数据
	metaPath := filepath.Join(s.baseDir, "messages", fmt.Sprintf("%s.json", msg.ID))
	metaData, err := json.MarshalIndent(msg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化邮件元数据失败: %v", err)
	}
	
	if err := os.WriteFile(metaPath, metaData, 0644); err != nil {
		return fmt.Errorf("保存邮件元数据失败: %v", err)
	}
	
	// 存储原始邮件数据
	rawPath := filepath.Join(s.baseDir, "messages", fmt.Sprintf("%s.eml", msg.ID))
	if err := os.WriteFile(rawPath, []byte(msg.RawData), 0644); err != nil {
		return fmt.Errorf("保存原始邮件失败: %v", err)
	}
	
	// 处理附件
	for i, attachment := range msg.Attachments {
		if len(attachment.Data) > 0 {
			attachmentPath := filepath.Join(s.baseDir, "attachments", fmt.Sprintf("%s_%d_%s", msg.ID, i, attachment.Filename))
			if err := os.WriteFile(attachmentPath, attachment.Data, 0644); err != nil {
				return fmt.Errorf("保存附件失败: %v", err)
			}
			msg.Attachments[i].FilePath = attachmentPath
			msg.Attachments[i].Data = nil // 清空内存中的数据
		}
	}
	
	return nil
}

// GetMessage 获取邮件消息
func (s *MailStorage) GetMessage(messageID string) (*MailMessage, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	metaPath := filepath.Join(s.baseDir, "messages", fmt.Sprintf("%s.json", messageID))
	data, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("邮件不存在: %s", messageID)
		}
		return nil, fmt.Errorf("读取邮件元数据失败: %v", err)
	}
	
	var msg MailMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("解析邮件元数据失败: %v", err)
	}
	
	return &msg, nil
}

// GetRawMessage 获取原始邮件内容
func (s *MailStorage) GetRawMessage(messageID string) ([]byte, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	rawPath := filepath.Join(s.baseDir, "messages", fmt.Sprintf("%s.eml", messageID))
	return os.ReadFile(rawPath)
}

// StoreUserMessage 存储用户邮件
func (s *MailStorage) StoreUserMessage(userID string, msg *MailMessage) error {
	mailbox, err := s.getUserMailbox(userID)
	if err != nil {
		return fmt.Errorf("获取用户邮箱失败: %v", err)
	}
	
	// 确保INBOX存在
	if _, exists := mailbox.Mailboxes["INBOX"]; !exists {
		mailbox.Mailboxes["INBOX"] = &MailBox{
			Name:        "INBOX",
			Messages:    make(map[string]*MailMessage),
			LastUID:     0,
			UIDValidity: uint32(time.Now().Unix()),
			Subscribed:  true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
	}
	
	inbox := mailbox.Mailboxes["INBOX"]
	inbox.LastUID++
	inbox.Messages[msg.ID] = msg
	inbox.UpdatedAt = time.Now()
	
	// 先存储邮件本身
	if err := s.StoreMessage(msg); err != nil {
		return err
	}
	
	// 然后更新用户邮箱索引
	return s.saveUserMailbox(mailbox)
}

// getUserMailbox 获取用户邮箱
func (s *MailStorage) getUserMailbox(userID string) (*UserMailbox, error) {
	mailboxPath := filepath.Join(s.baseDir, "users", fmt.Sprintf("%s.json", userID))
	
	if _, err := os.Stat(mailboxPath); os.IsNotExist(err) {
		// 创建新邮箱
		mailbox := &UserMailbox{
			UserID:    userID,
			Mailboxes: make(map[string]*MailBox),
		}
		return mailbox, nil
	}
	
	data, err := os.ReadFile(mailboxPath)
	if err != nil {
		return nil, fmt.Errorf("读取用户邮箱失败: %v", err)
	}
	
	var mailbox UserMailbox
	if err := json.Unmarshal(data, &mailbox); err != nil {
		return nil, fmt.Errorf("解析用户邮箱失败: %v", err)
	}
	
	if mailbox.Mailboxes == nil {
		mailbox.Mailboxes = make(map[string]*MailBox)
	}
	
	return &mailbox, nil
}

// saveUserMailbox 保存用户邮箱
func (s *MailStorage) saveUserMailbox(mailbox *UserMailbox) error {
	mailboxPath := filepath.Join(s.baseDir, "users", fmt.Sprintf("%s.json", mailbox.UserID))
	
	data, err := json.MarshalIndent(mailbox, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化用户邮箱失败: %v", err)
	}
	
	return os.WriteFile(mailboxPath, data, 0644)
}

// GetUserMailbox 获取用户邮箱（公开方法）
func (s *MailStorage) GetUserMailbox(userID string) (*UserMailbox, error) {
	return s.getUserMailbox(userID)
}

// GetUserMessages 获取用户邮件列表
func (s *MailStorage) GetUserMessages(userID, mailboxName string, limit, offset int) ([]*MailMessage, error) {
	mailbox, err := s.getUserMailbox(userID)
	if err != nil {
		return nil, err
	}
	
	box, exists := mailbox.Mailboxes[mailboxName]
	if !exists {
		return []*MailMessage{}, nil
	}
	
	// 收集消息并按时间排序
	messages := make([]*MailMessage, 0, len(box.Messages))
	for _, msg := range box.Messages {
		messages = append(messages, msg)
	}
	
	// 按时间降序排序（最新的在前）
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Timestamp.After(messages[j].Timestamp)
	})
	
	// 应用分页
	start := offset
	if start > len(messages) {
		return []*MailMessage{}, nil
	}
	
	end := start + limit
	if end > len(messages) {
		end = len(messages)
	}
	
	return messages[start:end], nil
}

// DeleteMessage 删除邮件
func (s *MailStorage) DeleteMessage(messageID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	// 删除元数据文件
	metaPath := filepath.Join(s.baseDir, "messages", fmt.Sprintf("%s.json", messageID))
	if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除邮件元数据失败: %v", err)
	}
	
	// 删除原始邮件文件
	rawPath := filepath.Join(s.baseDir, "messages", fmt.Sprintf("%s.eml", messageID))
	if err := os.Remove(rawPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除原始邮件失败: %v", err)
	}
	
	return nil
}

// GetAttachment 获取附件
func (s *MailStorage) GetAttachment(messageID string, attachmentID string) (*MailAttachment, io.ReadCloser, error) {
	msg, err := s.GetMessage(messageID)
	if err != nil {
		return nil, nil, err
	}
	
	for _, attachment := range msg.Attachments {
		if attachment.ID == attachmentID {
			if attachment.FilePath != "" {
				file, err := os.Open(attachment.FilePath)
				if err != nil {
					return nil, nil, fmt.Errorf("打开附件文件失败: %v", err)
				}
				return &attachment, file, nil
			}
			return &attachment, nil, nil
		}
	}
	
	return nil, nil, fmt.Errorf("附件不存在: %s", attachmentID)
}

// SearchMessages 搜索邮件
func (s *MailStorage) SearchMessages(query *MessageSearchQuery) ([]*MailMessage, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	var results []*MailMessage
	
	messagesDir := filepath.Join(s.baseDir, "messages")
	entries, err := os.ReadDir(messagesDir)
	if err != nil {
		return nil, fmt.Errorf("读取消息目录失败: %v", err)
	}
	
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		
		messageID := strings.TrimSuffix(entry.Name(), ".json")
		msg, err := s.GetMessage(messageID)
		if err != nil {
			continue
		}
		
		if s.matchesQuery(msg, query) {
			results = append(results, msg)
		}
	}
	
	// 按时间排序
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.After(results[j].Timestamp)
	})
	
	// 应用限制
	if query.Limit > 0 && len(results) > query.Limit {
		results = results[:query.Limit]
	}
	
	return results, nil
}

// MessageSearchQuery 邮件搜索查询
type MessageSearchQuery struct {
	From      string
	To        string
	Subject   string
	Body      string
	StartDate *time.Time
	EndDate   *time.Time
	Status    string
	Direction string
	Limit     int
}

// matchesQuery 检查邮件是否匹配查询条件
func (s *MailStorage) matchesQuery(msg *MailMessage, query *MessageSearchQuery) bool {
	if query.From != "" && !strings.Contains(strings.ToLower(msg.From), strings.ToLower(query.From)) {
		return false
	}
	
	if query.To != "" {
		found := false
		for _, to := range msg.To {
			if strings.Contains(strings.ToLower(to), strings.ToLower(query.To)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	if query.Subject != "" && !strings.Contains(strings.ToLower(msg.Subject), strings.ToLower(query.Subject)) {
		return false
	}
	
	if query.Body != "" && !strings.Contains(strings.ToLower(msg.Body), strings.ToLower(query.Body)) {
		return false
	}
	
	if query.StartDate != nil && msg.Timestamp.Before(*query.StartDate) {
		return false
	}
	
	if query.EndDate != nil && msg.Timestamp.After(*query.EndDate) {
		return false
	}
	
	if query.Status != "" && msg.Status != query.Status {
		return false
	}
	
	if query.Direction != "" && msg.Direction != query.Direction {
		return false
	}
	
	return true
}

// GetStorageStats 获取存储统计信息
func (s *MailStorage) GetStorageStats() (*StorageStats, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	stats := &StorageStats{
		TotalMessages: 0,
		TotalSize:     0,
		UserStats:     make(map[string]*UserStorageStats),
	}
	
	// 统计消息
	messagesDir := filepath.Join(s.baseDir, "messages")
	entries, err := os.ReadDir(messagesDir)
	if err != nil {
		return stats, nil
	}
	
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			stats.TotalMessages++
		} else if strings.HasSuffix(entry.Name(), ".eml") {
			if info, err := entry.Info(); err == nil {
				stats.TotalSize += info.Size()
			}
		}
	}
	
	// 统计用户邮箱
	usersDir := filepath.Join(s.baseDir, "users")
	userEntries, err := os.ReadDir(usersDir)
	if err == nil {
		for _, entry := range userEntries {
			if !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			
			userID := strings.TrimSuffix(entry.Name(), ".json")
			mailbox, err := s.getUserMailbox(userID)
			if err != nil {
				continue
			}
			
			userStats := &UserStorageStats{
				UserID:        userID,
				MessageCount:  0,
				TotalSize:     0,
				MailboxCount:  len(mailbox.Mailboxes),
			}
			
			for _, box := range mailbox.Mailboxes {
				userStats.MessageCount += len(box.Messages)
				for _, msg := range box.Messages {
					userStats.TotalSize += msg.Size
				}
			}
			
			stats.UserStats[userID] = userStats
		}
	}
	
	return stats, nil
}

// StorageStats 存储统计信息
type StorageStats struct {
	TotalMessages int                          `json:"total_messages"`
	TotalSize     int64                        `json:"total_size"`
	UserStats     map[string]*UserStorageStats `json:"user_stats"`
}

// UserStorageStats 用户存储统计
type UserStorageStats struct {
	UserID       string `json:"user_id"`
	MessageCount int    `json:"message_count"`
	TotalSize    int64  `json:"total_size"`
	MailboxCount int    `json:"mailbox_count"`
}
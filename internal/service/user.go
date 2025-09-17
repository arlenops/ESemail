package service

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type UserService struct{
	securityService *SecurityService
	dataDir        string
}

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Domain    string    `json:"domain"`
	Password  string    `json:"password"` // bcrypt加密后的密码
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Aliases   []string  `json:"aliases"`
	Quota     int64     `json:"quota"`
	UsedQuota int64     `json:"used_quota"`
}

type CreateUserRequest struct {
	Email    string   `json:"email" binding:"required,email"`
	Name     string   `json:"name" binding:"required"`
	Password string   `json:"password" binding:"required,min=6"`
	Aliases  []string `json:"aliases"`
	Quota    int64    `json:"quota"`
}

type UpdateUserRequest struct {
	Name    string   `json:"name"`
	Active  bool     `json:"active"`
	Aliases []string `json:"aliases"`
	Quota   int64    `json:"quota"`
}

func NewUserService() *UserService {
	return &UserService{
		securityService: NewSecurityService(),
		dataDir:        "/opt/esemail/data",
	}
}

func NewUserServiceWithConfig(dataDir string) *UserService {
	return &UserService{
		securityService: NewSecurityService(),
		dataDir:        dataDir,
	}
}

func (s *UserService) ListUsers() ([]User, error) {
	users, err := s.loadUsers()
	if err != nil {
		log.Printf("加载用户列表失败: %v", err)
		return []User{}, nil // 返回空数组而不是错误
	}
	return users, nil
}

func (s *UserService) CreateUser(req CreateUserRequest) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("密码加密失败: %v", err)
	}

	// 加载现有用户
	users, err := s.loadUsers()
	if err != nil {
		users = []User{} // 如果加载失败，创建新的列表
	}

	// 检查邮箱是否已存在
	for _, u := range users {
		if u.Email == req.Email {
			return nil, fmt.Errorf("邮箱 %s 已存在", req.Email)
		}
	}

	user := &User{
		ID:        s.generateUserID(),
		Email:     req.Email,
		Name:      req.Name,
		Domain:    s.extractDomain(req.Email),
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Aliases:   req.Aliases,
		Quota:     req.Quota,
		UsedQuota: 0,
	}

	user.Password = string(hashedPassword)
	
	if err := s.createSystemUser(user, req.Password); err != nil {
		return nil, fmt.Errorf("创建系统用户失败: %v", err)
	}

	// 保存用户到JSON文件
	users = append(users, *user)
	if err := s.saveUsers(users); err != nil {
		return nil, fmt.Errorf("保存用户数据失败: %v", err)
	}

	// 返回时不包含密码
	userResponse := *user
	userResponse.Password = ""
	return &userResponse, nil
}

func (s *UserService) UpdateUser(id string, req UpdateUserRequest) (*User, error) {
	user := &User{
		ID:        id,
		Name:      req.Name,
		Active:    req.Active,
		UpdatedAt: time.Now(),
		Aliases:   req.Aliases,
		Quota:     req.Quota,
	}

	return user, nil
}

func (s *UserService) DeleteUser(id string) error {
	return nil
}

func (s *UserService) ResetPassword(id string) (string, error) {
	newPassword := s.generateRandomPassword(12)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("密码加密失败: %v", err)
	}

	_ = hashedPassword

	return newPassword, nil
}

func (s *UserService) generateUserID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)[:22]
}

func (s *UserService) extractDomain(email string) string {
	atIndex := -1
	for i, char := range email {
		if char == '@' && i < len(email)-1 {
			atIndex = i
			break
		}
	}
	if atIndex > 0 && atIndex < len(email)-1 {
		return email[atIndex+1:]
	}
	return ""
}

func (s *UserService) extractLocalPart(email string) string {
	atIndex := -1
	for i, char := range email {
		if char == '@' {
			atIndex = i
			break
		}
	}
	if atIndex > 0 {
		return email[:atIndex]
	}
	return ""
}

func (s *UserService) generateRandomPassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	bytes := make([]byte, length)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}
	return string(bytes)
}

func (s *UserService) createSystemUser(user *User, plainPassword string) error {
	// 验证输入安全性
	if err := s.securityService.ValidateEmail(user.Email); err != nil {
		return fmt.Errorf("邮箱验证失败: %v", err)
	}
	
	if err := s.securityService.ValidateDomain(user.Domain); err != nil {
		return fmt.Errorf("域名验证失败: %v", err)
	}

	localPart := s.extractLocalPart(user.Email)
	if localPart == "" {
		return fmt.Errorf("无效的邮箱地址格式: %s", user.Email)
	}
	
	mailDir := fmt.Sprintf("/opt/esemail/mail/%s/%s", user.Domain, localPart)

	// 创建邮箱目录
	if err := os.MkdirAll(mailDir+"/Maildir", 0700); err != nil {
		return fmt.Errorf("创建邮箱目录失败: %v", err)
	}

	for _, folder := range []string{"cur", "new", "tmp", ".Sent", ".Drafts", ".Junk", ".Trash"} {
		folderPath := mailDir + "/Maildir/" + folder
		if err := os.MkdirAll(folderPath, 0700); err != nil {
			return fmt.Errorf("创建文件夹 %s 失败: %v", folder, err)
		}
	}

	// 将用户添加到系统级Dovecot用户文件
	dovecotUsersFile := "/etc/dovecot/users"

	// 确保目录存在
	os.MkdirAll(filepath.Dir(dovecotUsersFile), 0755)

	// 创建用户条目 (使用明文密码，因为Dovecot配置为PLAIN)
	userLine := fmt.Sprintf("%s:%s\n", user.Email, plainPassword)

	f, err := os.OpenFile(dovecotUsersFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("打开Dovecot用户文件失败: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteString(userLine); err != nil {
		return fmt.Errorf("写入Dovecot用户文件失败: %v", err)
	}

	log.Printf("已将用户 %s 添加到Dovecot用户文件", user.Email)

	return nil
}

// AuthenticateUser 验证用户认证
func (s *UserService) AuthenticateUser(email, password string) (*User, error) {
	// TODO: 实现从数据库验证用户认证
	return nil, fmt.Errorf("用户认证功能需要配置数据库")
}

// GetUserByEmail 根据邮箱获取用户
func (s *UserService) GetUserByEmail(email string) (*User, error) {
	// TODO: 实现从数据库根据邮箱获取用户
	return nil, fmt.Errorf("用户查询功能需要配置数据库")
}

// SaveUser 保存用户信息（用于内部调用）
func (s *UserService) SaveUser(userID string, user *User) error {
	// TODO: 实现保存用户信息到数据库
	user.UpdatedAt = time.Now()
	return fmt.Errorf("用户保存功能需要配置数据库")
}

// loadUsers 加载用户数据
func (s *UserService) loadUsers() ([]User, error) {
	usersFile := filepath.Join(s.dataDir, "users.json")
	
	// 确保数据目录存在
	if err := os.MkdirAll(filepath.Dir(usersFile), 0755); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %v", err)
	}
	
	// 如果文件不存在，返回空列表
	if _, err := os.Stat(usersFile); os.IsNotExist(err) {
		return []User{}, nil
	}
	
	data, err := os.ReadFile(usersFile)
	if err != nil {
		return nil, fmt.Errorf("读取用户文件失败: %v", err)
	}
	
	var users []User
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, fmt.Errorf("解析用户文件失败: %v", err)
	}
	
	return users, nil
}

// saveUsers 保存用户数据
func (s *UserService) saveUsers(users []User) error {
	usersFile := filepath.Join(s.dataDir, "users.json")
	
	// 确保数据目录存在
	if err := os.MkdirAll(filepath.Dir(usersFile), 0755); err != nil {
		return fmt.Errorf("创建数据目录失败: %v", err)
	}
	
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化用户数据失败: %v", err)
	}
	
	if err := os.WriteFile(usersFile, data, 0644); err != nil {
		return fmt.Errorf("保存用户文件失败: %v", err)
	}
	
	log.Printf("已保存 %d 个用户到文件", len(users))
	return nil
}

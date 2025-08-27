package service

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type UserService struct{}

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Domain    string    `json:"domain"`
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
	return &UserService{}
}

func (s *UserService) ListUsers() ([]User, error) {
	users := []User{
		{
			ID:        "1",
			Email:     "admin@example.com",
			Name:      "Administrator",
			Domain:    "example.com",
			Active:    true,
			CreatedAt: time.Now().AddDate(0, -1, 0),
			UpdatedAt: time.Now(),
			Aliases:   []string{"postmaster@example.com"},
			Quota:     1024 * 1024 * 1024,
			UsedQuota: 50 * 1024 * 1024,
		},
	}
	return users, nil
}

func (s *UserService) CreateUser(req CreateUserRequest) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("密码加密失败: %v", err)
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

	if err := s.createSystemUser(user, string(hashedPassword)); err != nil {
		return nil, fmt.Errorf("创建系统用户失败: %v", err)
	}

	return user, nil
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
	parts := []string{}
	for i, char := range email {
		if char == '@' && i < len(email)-1 {
			parts = []string{email[:i], email[i+1:]}
			break
		}
	}
	if len(parts) == 2 {
		return parts[1]
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

func (s *UserService) createSystemUser(user *User, hashedPassword string) error {
	mailDir := fmt.Sprintf("/var/lib/esemail/mail/%s/%s", user.Domain, user.Email[:len(user.Email)-len(user.Domain)-1])

	if err := os.MkdirAll(mailDir+"/Maildir", 0700); err != nil {
		return fmt.Errorf("创建邮箱目录失败: %v", err)
	}

	for _, folder := range []string{"cur", "new", "tmp", ".Sent", ".Drafts", ".Junk", ".Trash"} {
		folderPath := mailDir + "/Maildir/" + folder
		if err := os.MkdirAll(folderPath, 0700); err != nil {
			return fmt.Errorf("创建文件夹 %s 失败: %v", folder, err)
		}
	}

	cmd := exec.Command("chown", "-R", "5000:5000", mailDir)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("设置邮箱目录权限失败: %v", err)
	}

	userLine := fmt.Sprintf("%s:{CRYPT}%s\n", user.Email, hashedPassword)
	f, err := os.OpenFile("/etc/dovecot/users", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("打开用户文件失败: %v", err)
	}
	defer f.Close()

	if _, err := f.WriteString(userLine); err != nil {
		return fmt.Errorf("写入用户文件失败: %v", err)
	}

	return nil
}

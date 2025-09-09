package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v5"
)

type AuthService struct {
	jwtSecret []byte
	userStore map[string]*AdminUser // 临时存储，后续替换为数据库
}

type AdminUser struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token      string     `json:"token"`
	ExpiresAt  time.Time  `json:"expires_at"`
	User       *AdminUser `json:"user"`
}

type JWTClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func NewAuthService() *AuthService {
	// 生成随机JWT密钥
	secret := make([]byte, 32)
	rand.Read(secret)
	
	service := &AuthService{
		jwtSecret: secret,
		userStore: make(map[string]*AdminUser),
	}
	
	// 创建默认管理员用户
	service.createDefaultAdmin()
	
	return service
}

func (s *AuthService) createDefaultAdmin() error {
	// 检查是否已存在管理员
	for _, user := range s.userStore {
		if user.Username == "admin" {
			return nil
		}
	}
	
	// 设置默认密码为admin
	defaultPassword := "admin"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(defaultPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("生成密码哈希失败: %v", err)
	}
	
	adminUser := &AdminUser{
		ID:           s.generateUserID(),
		Username:     "admin",
		Email:        "admin@localhost",
		PasswordHash: string(hashedPassword),
		IsActive:     true,
		CreatedAt:    time.Now(),
	}
	
	s.userStore[adminUser.ID] = adminUser
	
	// 记录默认密码（仅用于首次设置）
	fmt.Printf("🔑 默认管理员账户已创建:\n")
	fmt.Printf("   用户名: admin\n")
	fmt.Printf("   密码: %s\n", defaultPassword)
	fmt.Printf("   请立即登录并修改密码！\n\n")
	
	return nil
}

func (s *AuthService) Login(req LoginRequest) (*LoginResponse, error) {
	// 查找用户
	var user *AdminUser
	for _, u := range s.userStore {
		if u.Username == req.Username {
			user = u
			break
		}
	}
	
	if user == nil {
		return nil, errors.New("用户名或密码错误")
	}
	
	if !user.IsActive {
		return nil, errors.New("账户已被禁用")
	}
	
	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, errors.New("用户名或密码错误")
	}
	
	// 更新最后登录时间
	user.LastLogin = time.Now()
	
	// 生成JWT令牌
	expiresAt := time.Now().Add(24 * time.Hour)
	claims := &JWTClaims{
		UserID:   user.ID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "esemail",
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("生成令牌失败: %v", err)
	}
	
	return &LoginResponse{
		Token:     tokenString,
		ExpiresAt: expiresAt,
		User:      user,
	}, nil
}

func (s *AuthService) VerifyToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("无效的签名方法: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	
	if err != nil {
		return nil, err
	}
	
	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		// 验证用户是否仍然有效
		user := s.GetUserByID(claims.UserID)
		if user == nil || !user.IsActive {
			return nil, errors.New("用户无效")
		}
		return claims, nil
	}
	
	return nil, errors.New("无效的令牌")
}

func (s *AuthService) GetUserByID(userID string) *AdminUser {
	return s.userStore[userID]
}

func (s *AuthService) ChangePassword(userID, oldPassword, newPassword string) error {
	user := s.GetUserByID(userID)
	if user == nil {
		return errors.New("用户不存在")
	}
	
	// 验证旧密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return errors.New("原密码错误")
	}
	
	// 验证新密码强度
	if len(newPassword) < 8 {
		return errors.New("密码长度至少8位")
	}
	
	// 生成新密码哈希
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("生成密码哈希失败: %v", err)
	}
	
	user.PasswordHash = string(hashedPassword)
	return nil
}

func (s *AuthService) generateUserID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (s *AuthService) generateRandomPassword() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	bytes := make([]byte, 12)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}
	return string(bytes)
}
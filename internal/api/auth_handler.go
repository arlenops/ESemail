package api

import (
	"esemail/internal/service"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	authService       *service.AuthService
	validationService *service.ValidationService
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

func NewAuthHandler(authService *service.AuthService, validationService *service.ValidationService) *AuthHandler {
	return &AuthHandler{
		authService:       authService,
		validationService: validationService,
	}
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req service.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("登录请求参数错误: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误: " + err.Error()})
		return
	}

	// 验证输入数据
	validationResult := h.validationService.LoginValidation(req.Username, req.Password)
	if !validationResult.Valid {
		log.Printf("登录数据验证失败: %+v", validationResult.Errors)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":  "输入数据验证失败",
			"errors": validationResult.Errors,
		})
		return
	}

	// 清理输入数据
	req.Username = h.validationService.SanitizeInput(req.Username)
	req.Password = h.validationService.SanitizeInput(req.Password)
	
	log.Printf("用户登录尝试: %s, 来源IP: %s", req.Username, c.ClientIP())
	
	response, err := h.authService.Login(req)
	if err != nil {
		log.Printf("用户登录失败: %s, 错误: %v", req.Username, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	
	log.Printf("用户登录成功: %s", req.Username)
	c.JSON(http.StatusOK, response)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	// JWT是无状态的，客户端删除token即可
	log.Printf("用户登出: %s", c.GetString("username"))
	c.JSON(http.StatusOK, gin.H{"message": "登出成功"})
}

func (h *AuthHandler) GetCurrentUser(c *gin.Context) {
	userID := c.GetString("user_id")
	user := h.authService.GetUserByID(userID)
	if user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	
	c.JSON(http.StatusOK, user)
}

func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误: " + err.Error()})
		return
	}

	// 验证新密码强度
	if err := h.validationService.ValidatePassword(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Message})
		return
	}

	// 清理输入数据
	req.OldPassword = h.validationService.SanitizeInput(req.OldPassword)
	req.NewPassword = h.validationService.SanitizeInput(req.NewPassword)
	
	userID := c.GetString("user_id")
	if err := h.authService.ChangePassword(userID, req.OldPassword, req.NewPassword); err != nil {
		log.Printf("用户 %s 密码修改失败: %v", userID, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	log.Printf("用户 %s 密码修改成功", userID)
	c.JSON(http.StatusOK, gin.H{"message": "密码修改成功"})
}

// JWT认证中间件
func AuthMiddleware(authService *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 检查Authorization头
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "缺少认证令牌"})
			c.Abort()
			return
		}
		
		// 提取Bearer token
		tokenParts := strings.SplitN(authHeader, " ", 2)
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的认证格式"})
			c.Abort()
			return
		}
		
		tokenString := tokenParts[1]
		
		// 验证token
		claims, err := authService.VerifyToken(tokenString)
		if err != nil {
			log.Printf("令牌验证失败: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的认证令牌"})
			c.Abort()
			return
		}
		
		// 将用户信息存储到上下文中
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		
		c.Next()
	}
}

// 可选的认证中间件（对于不需要强制登录的接口）
func OptionalAuthMiddleware(authService *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			tokenParts := strings.SplitN(authHeader, " ", 2)
			if len(tokenParts) == 2 && tokenParts[0] == "Bearer" {
				claims, err := authService.VerifyToken(tokenParts[1])
				if err == nil {
					c.Set("user_id", claims.UserID)
					c.Set("username", claims.Username)
					c.Set("authenticated", true)
				}
			}
		}
		c.Next()
	}
}
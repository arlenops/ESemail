package service

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// APIError API错误结构
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// ErrorCode 错误码常量
const (
	ErrCodeInternal          = "INTERNAL_ERROR"
	ErrCodeValidation        = "VALIDATION_ERROR"
	ErrCodeNotFound          = "NOT_FOUND"
	ErrCodeUnauthorized      = "UNAUTHORIZED"
	ErrCodeForbidden         = "FORBIDDEN"
	ErrCodeBadRequest        = "BAD_REQUEST"
	ErrCodeConflict          = "CONFLICT"
	ErrCodeRateLimited       = "RATE_LIMITED"
	ErrCodeServiceUnavailable = "SERVICE_UNAVAILABLE"
)

// ErrorHandlerService 统一错误处理服务
type ErrorHandlerService struct {
	logger Logger
}

// Logger 日志接口
type Logger interface {
	Printf(format string, v ...interface{})
	Errorf(format string, v ...interface{})
}

// DefaultLogger 默认日志实现
type DefaultLogger struct{}

func (l *DefaultLogger) Printf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

func (l *DefaultLogger) Errorf(format string, v ...interface{}) {
	log.Printf("ERROR: "+format, v...)
}

// NewErrorHandlerService 创建错误处理服务
func NewErrorHandlerService(logger Logger) *ErrorHandlerService {
	if logger == nil {
		logger = &DefaultLogger{}
	}
	return &ErrorHandlerService{
		logger: logger,
	}
}

// HandleError 统一错误处理
func (e *ErrorHandlerService) HandleError(c *gin.Context, err error, code string, userMessage string) {
	// 记录详细错误到日志
	e.logger.Errorf("API Error [%s]: %v", code, err)
	
	statusCode := e.getHTTPStatusCode(code)
	
	apiError := APIError{
		Code:    code,
		Message: userMessage,
	}
	
	// 在开发环境下可以包含详细信息
	if gin.Mode() == gin.DebugMode && err != nil {
		apiError.Details = err.Error()
	}
	
	c.JSON(statusCode, apiError)
}

// HandleValidationError 处理验证错误
func (e *ErrorHandlerService) HandleValidationError(c *gin.Context, err error) {
	e.HandleError(c, err, ErrCodeValidation, "输入数据验证失败")
}

// HandleNotFoundError 处理未找到错误
func (e *ErrorHandlerService) HandleNotFoundError(c *gin.Context, resource string) {
	message := fmt.Sprintf("%s不存在", resource)
	e.HandleError(c, nil, ErrCodeNotFound, message)
}

// HandleUnauthorizedError 处理未授权错误
func (e *ErrorHandlerService) HandleUnauthorizedError(c *gin.Context) {
	e.HandleError(c, nil, ErrCodeUnauthorized, "未授权访问")
}

// HandleForbiddenError 处理禁止访问错误
func (e *ErrorHandlerService) HandleForbiddenError(c *gin.Context) {
	e.HandleError(c, nil, ErrCodeForbidden, "禁止访问")
}

// HandleConflictError 处理冲突错误
func (e *ErrorHandlerService) HandleConflictError(c *gin.Context, err error, message string) {
	e.HandleError(c, err, ErrCodeConflict, message)
}

// HandleInternalError 处理内部错误
func (e *ErrorHandlerService) HandleInternalError(c *gin.Context, err error) {
	e.HandleError(c, err, ErrCodeInternal, "服务器内部错误")
}

// SuccessResponse 成功响应
func (e *ErrorHandlerService) SuccessResponse(c *gin.Context, data interface{}) {
	if data == nil {
		c.JSON(http.StatusOK, gin.H{"success": true})
	} else {
		c.JSON(http.StatusOK, data)
	}
}

// SuccessResponseWithMessage 带消息的成功响应
func (e *ErrorHandlerService) SuccessResponseWithMessage(c *gin.Context, message string, data interface{}) {
	response := gin.H{
		"success": true,
		"message": message,
	}
	
	if data != nil {
		response["data"] = data
	}
	
	c.JSON(http.StatusOK, response)
}

// getHTTPStatusCode 根据错误码获取HTTP状态码
func (e *ErrorHandlerService) getHTTPStatusCode(code string) int {
	switch code {
	case ErrCodeValidation:
		return http.StatusBadRequest
	case ErrCodeNotFound:
		return http.StatusNotFound
	case ErrCodeUnauthorized:
		return http.StatusUnauthorized
	case ErrCodeForbidden:
		return http.StatusForbidden
	case ErrCodeBadRequest:
		return http.StatusBadRequest
	case ErrCodeConflict:
		return http.StatusConflict
	case ErrCodeRateLimited:
		return http.StatusTooManyRequests
	case ErrCodeServiceUnavailable:
		return http.StatusServiceUnavailable
	case ErrCodeInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// RecoveryHandler 统一的panic恢复处理
func (e *ErrorHandlerService) RecoveryHandler() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			e.logger.Errorf("Panic recovered: %s", err)
			e.HandleInternalError(c, fmt.Errorf("panic: %s", err))
		} else if err, ok := recovered.(error); ok {
			e.logger.Errorf("Panic recovered: %v", err)
			e.HandleInternalError(c, err)
		} else {
			e.logger.Errorf("Panic recovered: %v", recovered)
			e.HandleInternalError(c, fmt.Errorf("unknown panic: %v", recovered))
		}
		c.AbortWithStatus(http.StatusInternalServerError)
	})
}

// ValidationFunc 验证函数类型
type ValidationFunc func() error

// Validate 执行验证并处理错误
func (e *ErrorHandlerService) Validate(c *gin.Context, validations ...ValidationFunc) bool {
	for _, validate := range validations {
		if err := validate(); err != nil {
			e.HandleValidationError(c, err)
			return false
		}
	}
	return true
}

// WithContext 为错误添加上下文信息
func (e *ErrorHandlerService) WithContext(c *gin.Context, err error, context string) error {
	if err == nil {
		return nil
	}
	
	userAgent := c.GetHeader("User-Agent")
	clientIP := c.ClientIP()
	method := c.Request.Method
	path := c.Request.URL.Path
	
	contextualError := fmt.Errorf("%s [%s %s from %s, UA: %s]: %w", 
		context, method, path, clientIP, userAgent, err)
	
	return contextualError
}
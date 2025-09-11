package errors

import (
	"encoding/json"
	"fmt"
)

// ErrorCode 错误代码类型
type ErrorCode string

// 预定义错误代码
const (
	// 通用错误
	ErrCodeUnknown           ErrorCode = "UNKNOWN"
	ErrCodeInternalError     ErrorCode = "INTERNAL_ERROR"
	ErrCodeInvalidInput      ErrorCode = "INVALID_INPUT"
	ErrCodeNotFound          ErrorCode = "NOT_FOUND"
	ErrCodeAlreadyExists     ErrorCode = "ALREADY_EXISTS"
	ErrCodeUnauthorized      ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden         ErrorCode = "FORBIDDEN"

	// 用户相关错误
	ErrCodeUserNotFound      ErrorCode = "USER_NOT_FOUND"
	ErrCodeUserExists        ErrorCode = "USER_EXISTS"
	ErrCodeUserInactive      ErrorCode = "USER_INACTIVE"
	ErrCodeInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"
	ErrCodeWeakPassword      ErrorCode = "WEAK_PASSWORD"

	// 域名相关错误
	ErrCodeDomainNotFound    ErrorCode = "DOMAIN_NOT_FOUND"
	ErrCodeDomainExists      ErrorCode = "DOMAIN_EXISTS"
	ErrCodeInvalidDomain     ErrorCode = "INVALID_DOMAIN"
	ErrCodeDomainNotManaged  ErrorCode = "DOMAIN_NOT_MANAGED"

	// 邮件相关错误
	ErrCodeMailNotFound      ErrorCode = "MAIL_NOT_FOUND"
	ErrCodeInvalidEmail      ErrorCode = "INVALID_EMAIL"
	ErrCodeMailDeliveryFailed ErrorCode = "MAIL_DELIVERY_FAILED"
	ErrCodeQuotaExceeded     ErrorCode = "QUOTA_EXCEEDED"
	ErrCodeAttachmentTooLarge ErrorCode = "ATTACHMENT_TOO_LARGE"

	// SMTP/IMAP相关错误
	ErrCodeSMTPAuthFailed    ErrorCode = "SMTP_AUTH_FAILED"
	ErrCodeIMAPAuthFailed    ErrorCode = "IMAP_AUTH_FAILED"
	ErrCodeConnectionFailed  ErrorCode = "CONNECTION_FAILED"

	// DNS相关错误
	ErrCodeDNSLookupFailed   ErrorCode = "DNS_LOOKUP_FAILED"
	ErrCodeNoMXRecord        ErrorCode = "NO_MX_RECORD"

	// 证书相关错误
	ErrCodeCertNotFound      ErrorCode = "CERT_NOT_FOUND"
	ErrCodeCertExpired       ErrorCode = "CERT_EXPIRED"
	ErrCodeCertInvalid       ErrorCode = "CERT_INVALID"
)

// ServiceError 业务错误结构
type ServiceError struct {
	Code       ErrorCode   `json:"code"`
	Message    string      `json:"message"`
	Details    interface{} `json:"details,omitempty"`
	HTTPStatus int         `json:"-"`
	Internal   error       `json:"-"`
}

// Error 实现error接口
func (e *ServiceError) Error() string {
	if e.Internal != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Internal)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// JSON 返回JSON格式的错误信息
func (e *ServiceError) JSON() []byte {
	data, _ := json.Marshal(e)
	return data
}

// WithDetails 添加错误详情
func (e *ServiceError) WithDetails(details interface{}) *ServiceError {
	e.Details = details
	return e
}

// WithInternal 添加内部错误
func (e *ServiceError) WithInternal(err error) *ServiceError {
	e.Internal = err
	return e
}

// WithHTTPStatus 设置HTTP状态码
func (e *ServiceError) WithHTTPStatus(status int) *ServiceError {
	e.HTTPStatus = status
	return e
}

// 错误构造函数

// New 创建新的业务错误
func New(code ErrorCode, message string) *ServiceError {
	return &ServiceError{
		Code:       code,
		Message:    message,
		HTTPStatus: 500, // 默认为500
	}
}

// NewWithInternal 创建包含内部错误的业务错误
func NewWithInternal(code ErrorCode, message string, internal error) *ServiceError {
	return &ServiceError{
		Code:       code,
		Message:    message,
		Internal:   internal,
		HTTPStatus: 500,
	}
}

// 常用错误快速构造函数

// NotFound 创建未找到错误
func NotFound(resource string) *ServiceError {
	return &ServiceError{
		Code:       ErrCodeNotFound,
		Message:    fmt.Sprintf("%s未找到", resource),
		HTTPStatus: 404,
	}
}

// AlreadyExists 创建已存在错误
func AlreadyExists(resource string) *ServiceError {
	return &ServiceError{
		Code:       ErrCodeAlreadyExists,
		Message:    fmt.Sprintf("%s已存在", resource),
		HTTPStatus: 409,
	}
}

// InvalidInput 创建输入无效错误
func InvalidInput(field string, reason string) *ServiceError {
	message := fmt.Sprintf("输入无效: %s", field)
	if reason != "" {
		message += " - " + reason
	}
	return &ServiceError{
		Code:       ErrCodeInvalidInput,
		Message:    message,
		HTTPStatus: 400,
		Details: map[string]string{
			"field":  field,
			"reason": reason,
		},
	}
}

// Unauthorized 创建未授权错误
func Unauthorized(message string) *ServiceError {
	if message == "" {
		message = "未授权访问"
	}
	return &ServiceError{
		Code:       ErrCodeUnauthorized,
		Message:    message,
		HTTPStatus: 401,
	}
}

// Forbidden 创建禁止访问错误
func Forbidden(message string) *ServiceError {
	if message == "" {
		message = "禁止访问"
	}
	return &ServiceError{
		Code:       ErrCodeForbidden,
		Message:    message,
		HTTPStatus: 403,
	}
}

// InternalError 创建内部错误
func InternalError(message string, internal error) *ServiceError {
	if message == "" {
		message = "内部服务器错误"
	}
	return &ServiceError{
		Code:       ErrCodeInternalError,
		Message:    message,
		Internal:   internal,
		HTTPStatus: 500,
	}
}

// 领域特定错误

// UserNotFound 用户未找到
func UserNotFound() *ServiceError {
	return &ServiceError{
		Code:       ErrCodeUserNotFound,
		Message:    "用户不存在",
		HTTPStatus: 404,
	}
}

// UserExists 用户已存在
func UserExists(email string) *ServiceError {
	return &ServiceError{
		Code:       ErrCodeUserExists,
		Message:    "用户已存在",
		HTTPStatus: 409,
		Details:    map[string]string{"email": email},
	}
}

// InvalidCredentials 无效凭据
func InvalidCredentials() *ServiceError {
	return &ServiceError{
		Code:       ErrCodeInvalidCredentials,
		Message:    "用户名或密码错误",
		HTTPStatus: 401,
	}
}

// UserInactive 用户已停用
func UserInactive() *ServiceError {
	return &ServiceError{
		Code:       ErrCodeUserInactive,
		Message:    "用户账户已停用",
		HTTPStatus: 403,
	}
}

// DomainNotFound 域名未找到
func DomainNotFound(domain string) *ServiceError {
	return &ServiceError{
		Code:       ErrCodeDomainNotFound,
		Message:    "域名不存在",
		HTTPStatus: 404,
		Details:    map[string]string{"domain": domain},
	}
}

// DomainExists 域名已存在
func DomainExists(domain string) *ServiceError {
	return &ServiceError{
		Code:       ErrCodeDomainExists,
		Message:    "域名已存在",
		HTTPStatus: 409,
		Details:    map[string]string{"domain": domain},
	}
}

// InvalidDomain 无效域名
func InvalidDomain(domain string, reason string) *ServiceError {
	return &ServiceError{
		Code:       ErrCodeInvalidDomain,
		Message:    "域名格式无效",
		HTTPStatus: 400,
		Details: map[string]string{
			"domain": domain,
			"reason": reason,
		},
	}
}

// MailDeliveryFailed 邮件投递失败
func MailDeliveryFailed(recipient string, reason string) *ServiceError {
	return &ServiceError{
		Code:       ErrCodeMailDeliveryFailed,
		Message:    "邮件投递失败",
		HTTPStatus: 500,
		Details: map[string]string{
			"recipient": recipient,
			"reason":    reason,
		},
	}
}

// QuotaExceeded 配额超限
func QuotaExceeded(user string) *ServiceError {
	return &ServiceError{
		Code:       ErrCodeQuotaExceeded,
		Message:    "存储配额已超限",
		HTTPStatus: 413,
		Details:    map[string]string{"user": user},
	}
}

// 错误检查函数

// IsServiceError 检查是否为ServiceError
func IsServiceError(err error) bool {
	_, ok := err.(*ServiceError)
	return ok
}

// GetServiceError 获取ServiceError，如果不是则创建一个通用错误
func GetServiceError(err error) *ServiceError {
	if serviceErr, ok := err.(*ServiceError); ok {
		return serviceErr
	}
	return InternalError("", err)
}

// HasCode 检查错误是否包含特定代码
func HasCode(err error, code ErrorCode) bool {
	if serviceErr, ok := err.(*ServiceError); ok {
		return serviceErr.Code == code
	}
	return false
}

// HTTPStatusFromError 从错误获取HTTP状态码
func HTTPStatusFromError(err error) int {
	if serviceErr, ok := err.(*ServiceError); ok {
		if serviceErr.HTTPStatus > 0 {
			return serviceErr.HTTPStatus
		}
	}
	return 500 // 默认为500
}

// 错误包装函数

// Wrap 包装现有错误为ServiceError
func Wrap(err error, code ErrorCode, message string) *ServiceError {
	return NewWithInternal(code, message, err)
}

// WrapWithDetails 包装错误并添加详情
func WrapWithDetails(err error, code ErrorCode, message string, details interface{}) *ServiceError {
	return NewWithInternal(code, message, err).WithDetails(details)
}
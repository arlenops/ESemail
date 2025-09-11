package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Level 日志级别
type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
)

// String 返回日志级别字符串
func (l Level) String() string {
	switch l {
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return "INFO"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	case FatalLevel:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Field 日志字段
type Field struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

// NewField 创建新字段
func NewField(key string, value interface{}) Field {
	return Field{Key: key, Value: value}
}

// String 字符串字段
func String(key, value string) Field {
	return Field{Key: key, Value: value}
}

// Int 整数字段
func Int(key string, value int) Field {
	return Field{Key: key, Value: value}
}

// Bool 布尔字段
func Bool(key string, value bool) Field {
	return Field{Key: key, Value: value}
}

// Error 错误字段
func Error(err error) Field {
	if err == nil {
		return Field{Key: "error", Value: nil}
	}
	return Field{Key: "error", Value: err.Error()}
}

// Duration 时长字段
func Duration(key string, value time.Duration) Field {
	return Field{Key: key, Value: value.String()}
}

// LogEntry 日志条目
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Caller    string                 `json:"caller,omitempty"`
	Stack     string                 `json:"stack,omitempty"`
}

// Logger 日志记录器
type Logger struct {
	level      Level
	output     io.Writer
	formatter  Formatter
	sanitizer  *Sanitizer
	enableJSON bool
	enableCaller bool
	enableStack  bool
}

// Config 日志配置
type Config struct {
	Level        Level
	Output       io.Writer
	EnableJSON   bool
	EnableCaller bool
	EnableStack  bool
	LogFile      string
}

// NewLogger 创建新的日志记录器
func NewLogger(config Config) (*Logger, error) {
	logger := &Logger{
		level:        config.Level,
		output:       config.Output,
		enableJSON:   config.EnableJSON,
		enableCaller: config.EnableCaller,
		enableStack:  config.EnableStack,
		sanitizer:    NewSanitizer(),
	}

	// 如果指定了日志文件，创建文件输出
	if config.LogFile != "" {
		if err := os.MkdirAll(filepath.Dir(config.LogFile), 0755); err != nil {
			return nil, fmt.Errorf("创建日志目录失败: %v", err)
		}
		
		file, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("打开日志文件失败: %v", err)
		}
		logger.output = file
	}

	// 设置默认输出
	if logger.output == nil {
		logger.output = os.Stdout
	}

	// 设置格式化器
	if config.EnableJSON {
		logger.formatter = &JSONFormatter{}
	} else {
		logger.formatter = &TextFormatter{}
	}

	return logger, nil
}

// NewDefaultLogger 创建默认日志记录器
func NewDefaultLogger() *Logger {
	logger, _ := NewLogger(Config{
		Level:        InfoLevel,
		Output:       os.Stdout,
		EnableJSON:   true,
		EnableCaller: true,
	})
	return logger
}

// SetLevel 设置日志级别
func (l *Logger) SetLevel(level Level) {
	l.level = level
}

// log 记录日志
func (l *Logger) log(level Level, msg string, fields ...Field) {
	if level < l.level {
		return
	}

	entry := &LogEntry{
		Timestamp: time.Now(),
		Level:     level.String(),
		Message:   msg,
		Fields:    make(map[string]interface{}),
	}

	// 添加字段
	for _, field := range fields {
		entry.Fields[field.Key] = l.sanitizer.SanitizeValue(field.Value)
	}

	// 添加调用者信息
	if l.enableCaller {
		if caller := getCaller(); caller != "" {
			entry.Caller = caller
		}
	}

	// 添加堆栈信息（仅错误级别）
	if l.enableStack && level >= ErrorLevel {
		entry.Stack = getStack()
	}

	// 格式化并输出
	formatted := l.formatter.Format(entry)
	fmt.Fprintln(l.output, formatted)
}

// Debug 记录调试信息
func (l *Logger) Debug(msg string, fields ...Field) {
	l.log(DebugLevel, msg, fields...)
}

// Info 记录信息
func (l *Logger) Info(msg string, fields ...Field) {
	l.log(InfoLevel, msg, fields...)
}

// Warn 记录警告
func (l *Logger) Warn(msg string, fields ...Field) {
	l.log(WarnLevel, msg, fields...)
}

// Error 记录错误
func (l *Logger) Error(msg string, fields ...Field) {
	l.log(ErrorLevel, msg, fields...)
}

// Fatal 记录致命错误并退出
func (l *Logger) Fatal(msg string, fields ...Field) {
	l.log(FatalLevel, msg, fields...)
	os.Exit(1)
}

// Formatter 格式化器接口
type Formatter interface {
	Format(entry *LogEntry) string
}

// JSONFormatter JSON格式化器
type JSONFormatter struct{}

// Format 格式化为JSON
func (f *JSONFormatter) Format(entry *LogEntry) string {
	data, _ := json.Marshal(entry)
	return string(data)
}

// TextFormatter 文本格式化器
type TextFormatter struct{}

// Format 格式化为可读文本
func (f *TextFormatter) Format(entry *LogEntry) string {
	var parts []string
	
	// 时间戳
	parts = append(parts, entry.Timestamp.Format("2006-01-02 15:04:05"))
	
	// 级别
	parts = append(parts, fmt.Sprintf("[%s]", entry.Level))
	
	// 调用者
	if entry.Caller != "" {
		parts = append(parts, fmt.Sprintf("<%s>", entry.Caller))
	}
	
	// 消息
	parts = append(parts, entry.Message)
	
	// 字段
	if len(entry.Fields) > 0 {
		var fieldParts []string
		for key, value := range entry.Fields {
			fieldParts = append(fieldParts, fmt.Sprintf("%s=%v", key, value))
		}
		parts = append(parts, fmt.Sprintf("{%s}", strings.Join(fieldParts, ", ")))
	}
	
	result := strings.Join(parts, " ")
	
	// 堆栈信息
	if entry.Stack != "" {
		result += "\n" + entry.Stack
	}
	
	return result
}

// Sanitizer 敏感数据清理器
type Sanitizer struct {
	sensitiveKeys []string
	maskString    string
}

// NewSanitizer 创建数据清理器
func NewSanitizer() *Sanitizer {
	return &Sanitizer{
		sensitiveKeys: []string{
			"password", "passwd", "pwd", "secret", "token", "key", "auth",
			"authorization", "credential", "private", "confidential",
		},
		maskString: "***",
	}
}

// SanitizeValue 清理敏感值
func (s *Sanitizer) SanitizeValue(value interface{}) interface{} {
	switch v := value.(type) {
	case string:
		return s.sanitizeString(v)
	case map[string]interface{}:
		return s.sanitizeMap(v)
	default:
		return value
	}
}

// sanitizeString 清理敏感字符串
func (s *Sanitizer) sanitizeString(value string) string {
	// 如果包含敏感关键词，则遮蔽
	lower := strings.ToLower(value)
	for _, key := range s.sensitiveKeys {
		if strings.Contains(lower, key) {
			return s.maskString
		}
	}
	return value
}

// sanitizeMap 清理敏感映射
func (s *Sanitizer) sanitizeMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for key, value := range m {
		if s.isSensitiveKey(key) {
			result[key] = s.maskString
		} else {
			result[key] = s.SanitizeValue(value)
		}
	}
	return result
}

// isSensitiveKey 检查是否为敏感键
func (s *Sanitizer) isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, sensitive := range s.sensitiveKeys {
		if strings.Contains(lower, sensitive) {
			return true
		}
	}
	return false
}

// getCaller 获取调用者信息
func getCaller() string {
	pc, file, line, ok := runtime.Caller(3)
	if !ok {
		return ""
	}
	
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return ""
	}
	
	return fmt.Sprintf("%s:%d:%s", filepath.Base(file), line, filepath.Base(fn.Name()))
}

// getStack 获取堆栈信息
func getStack() string {
	buf := make([]byte, 2048)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// 全局日志记录器
var defaultLogger = NewDefaultLogger()

// SetDefaultLogger 设置默认日志记录器
func SetDefaultLogger(logger *Logger) {
	defaultLogger = logger
}

// Debug 使用默认记录器记录调试信息
func Debug(msg string, fields ...Field) {
	defaultLogger.Debug(msg, fields...)
}

// Info 使用默认记录器记录信息
func Info(msg string, fields ...Field) {
	defaultLogger.Info(msg, fields...)
}

// Warn 使用默认记录器记录警告
func Warn(msg string, fields ...Field) {
	defaultLogger.Warn(msg, fields...)
}

// Error 使用默认记录器记录错误
func Error(msg string, fields ...Field) {
	defaultLogger.Error(msg, fields...)
}

// Fatal 使用默认记录器记录致命错误
func Fatal(msg string, fields ...Field) {
	defaultLogger.Fatal(msg, fields...)
}

// WithContext 创建带上下文的日志记录器（用于追踪请求）
type ContextLogger struct {
	*Logger
	contextFields []Field
}

// NewContextLogger 创建上下文日志记录器
func NewContextLogger(logger *Logger, fields ...Field) *ContextLogger {
	return &ContextLogger{
		Logger:        logger,
		contextFields: fields,
	}
}

// addContextFields 添加上下文字段
func (cl *ContextLogger) addContextFields(fields []Field) []Field {
	return append(cl.contextFields, fields...)
}

// Debug 记录调试信息（带上下文）
func (cl *ContextLogger) Debug(msg string, fields ...Field) {
	cl.Logger.Debug(msg, cl.addContextFields(fields)...)
}

// Info 记录信息（带上下文）
func (cl *ContextLogger) Info(msg string, fields ...Field) {
	cl.Logger.Info(msg, cl.addContextFields(fields)...)
}

// Warn 记录警告（带上下文）
func (cl *ContextLogger) Warn(msg string, fields ...Field) {
	cl.Logger.Warn(msg, cl.addContextFields(fields)...)
}

// Error 记录错误（带上下文）
func (cl *ContextLogger) Error(msg string, fields ...Field) {
	cl.Logger.Error(msg, cl.addContextFields(fields)...)
}

// Fatal 记录致命错误（带上下文）
func (cl *ContextLogger) Fatal(msg string, fields ...Field) {
	cl.Logger.Fatal(msg, cl.addContextFields(fields)...)
}
package api

import (
	"esemail/internal/service"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

type MailServerHandler struct {
	mailServer *service.MailServer
}

func NewMailServerHandler(mailServer *service.MailServer) *MailServerHandler {
	return &MailServerHandler{
		mailServer: mailServer,
	}
}

// GetMailServerStatus 获取邮件服务器状态
func (h *MailServerHandler) GetMailServerStatus(c *gin.Context) {
	status := h.mailServer.GetStatus()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    status,
	})
}

// SendEmail 发送邮件
func (h *MailServerHandler) SendEmail(c *gin.Context) {
	var req struct {
		From    string            `json:"from" binding:"required,email"`
		To      string            `json:"to" binding:"required,email"`
		Subject string            `json:"subject" binding:"required"`
		Body    string            `json:"body" binding:"required"`
		Headers map[string]string `json:"headers"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "参数格式错误: " + err.Error(),
		})
		return
	}

	// 使用邮件权威性认证服务准备邮件
	authService := h.mailServer.GetAuthService()
	if authService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "邮件认证服务未初始化",
		})
		return
	}

	// 认证并准备邮件
	authenticatedMail, err := authService.AuthenticateAndPrepareEmail(
		req.From, req.To, req.Subject, req.Body, req.Headers)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "邮件认证失败: " + err.Error(),
		})
		return
	}

	// 发送邮件
	if err := h.mailServer.SendAuthenticatedEmail(authenticatedMail); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "发送邮件失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"message":    "邮件发送成功",
		"auth_score": authenticatedMail.AuthScore,
		"dkim_signed": authenticatedMail.DKIMSigned,
	})
}

// GetMailHistory 获取邮件历史
func (h *MailServerHandler) GetMailHistory(c *gin.Context) {
	query := service.MailHistoryQuery{
		StartDate: time.Now().AddDate(0, 0, -30),
		EndDate:   time.Now(),
		Page:      1,
		PageSize:  50,
	}

	if startDate := c.Query("start_date"); startDate != "" {
		if parsed, err := time.Parse("2006-01-02", startDate); err == nil {
			query.StartDate = parsed
		}
	}

	if endDate := c.Query("end_date"); endDate != "" {
		if parsed, err := time.Parse("2006-01-02", endDate); err == nil {
			query.EndDate = parsed
		}
	}

	if page := c.Query("page"); page != "" {
		if p, err := strconv.Atoi(page); err == nil && p > 0 {
			query.Page = p
		}
	}

	if pageSize := c.Query("page_size"); pageSize != "" {
		if ps, err := strconv.Atoi(pageSize); err == nil && ps > 0 && ps <= 100 {
			query.PageSize = ps
		}
	}

	query.Direction = c.Query("direction")
	query.User = c.Query("user")
	query.Status = c.Query("status")

	// 使用邮件服务器的增强邮件服务
	mailService := &service.EnhancedMailService{}
	history, err := mailService.GetMailHistory(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "获取邮件历史失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    history,
	})
}

// GetMailDetail 获取邮件详情
func (h *MailServerHandler) GetMailDetail(c *gin.Context) {
	messageID := c.Param("id")
	if messageID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "邮件ID不能为空",
		})
		return
	}

	message, err := h.mailServer.GetUserMessages("", "INBOX", 1, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "获取邮件详情失败: " + err.Error(),
		})
		return
	}

	// 简化实现：查找指定ID的邮件
	var foundMessage *service.MailMessage
	for _, msg := range message {
		if msg.ID == messageID {
			foundMessage = msg
			break
		}
	}

	if foundMessage == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "邮件不存在",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    foundMessage,
	})
}

// DownloadEML 下载EML文件
func (h *MailServerHandler) DownloadEML(c *gin.Context) {
	messageID := c.Param("id")
	if messageID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "邮件ID不能为空",
		})
		return
	}

	// 这里需要实现从邮件存储中获取EML内容
	emlData := []byte("From: test@example.com\r\nTo: user@example.com\r\nSubject: Test Email\r\n\r\nThis is a test email.")

	c.Header("Content-Type", "message/rfc822")
	c.Header("Content-Disposition", "attachment; filename=\""+messageID+".eml\"")
	c.Data(http.StatusOK, "message/rfc822", emlData)
}

// GetUserMessages 获取用户邮件
func (h *MailServerHandler) GetUserMessages(c *gin.Context) {
	userID := c.Query("user_id")
	mailbox := c.DefaultQuery("mailbox", "INBOX")
	
	limit := 50
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	
	offset := 0
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	messages, err := h.mailServer.GetUserMessages(userID, mailbox, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "获取用户邮件失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    messages,
		"count":   len(messages),
	})
}

// SearchMessages 搜索邮件
func (h *MailServerHandler) SearchMessages(c *gin.Context) {
	query := &service.MessageSearchQuery{
		Limit: 100,
	}

	if from := c.Query("from"); from != "" {
		query.From = from
	}
	if to := c.Query("to"); to != "" {
		query.To = to
	}
	if subject := c.Query("subject"); subject != "" {
		query.Subject = subject
	}
	if body := c.Query("body"); body != "" {
		query.Body = body
	}
	if status := c.Query("status"); status != "" {
		query.Status = status
	}
	if direction := c.Query("direction"); direction != "" {
		query.Direction = direction
	}

	if startDate := c.Query("start_date"); startDate != "" {
		if parsed, err := time.Parse("2006-01-02", startDate); err == nil {
			query.StartDate = &parsed
		}
	}
	if endDate := c.Query("end_date"); endDate != "" {
		if parsed, err := time.Parse("2006-01-02", endDate); err == nil {
			query.EndDate = &parsed
		}
	}

	if limit := c.Query("limit"); limit != "" {
		if parsed, err := strconv.Atoi(limit); err == nil && parsed > 0 {
			query.Limit = parsed
		}
	}

	messages, err := h.mailServer.SearchMessages(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "搜索邮件失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    messages,
		"count":   len(messages),
	})
}

// GetDKIMRecord 获取DKIM DNS记录
func (h *MailServerHandler) GetDKIMRecord(c *gin.Context) {
	publicKey, err := h.mailServer.GetDKIMPublicKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "获取DKIM公钥失败: " + err.Error(),
		})
		return
	}

	// 获取DNS记录名称
	authService := h.mailServer.GetAuthService()
	if authService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "认证服务未初始化",
		})
		return
	}

	recordName, recordValue, err := authService.GetDKIMDNSRecord()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "获取DKIM DNS记录失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"record_name":  recordName,
			"record_value": recordValue,
			"record_type":  "TXT",
			"description":  "DKIM公钥记录，用于邮件签名验证",
		},
	})
}

// GetRecommendedDNSRecords 获取推荐的DNS记录
func (h *MailServerHandler) GetRecommendedDNSRecords(c *gin.Context) {
	records, err := h.mailServer.GetRecommendedDNSRecords()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "获取DNS记录失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    records,
	})
}
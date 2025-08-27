package api

import (
	"esemail/internal/service"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

type MailHandler struct {
	mailService *service.MailService
}

func NewMailHandler(mailService *service.MailService) *MailHandler {
	return &MailHandler{
		mailService: mailService,
	}
}

func (h *MailHandler) GetMailHistory(c *gin.Context) {
	query := service.MailHistoryQuery{
		StartDate: time.Now().AddDate(0, 0, -30),
		EndDate:   time.Now(),
		Page:      1,
		PageSize:  50,
	}

	if startDate := c.Query("start_date"); startDate != "" {
		if t, err := time.Parse("2006-01-02", startDate); err == nil {
			query.StartDate = t
		}
	}

	if endDate := c.Query("end_date"); endDate != "" {
		if t, err := time.Parse("2006-01-02", endDate); err == nil {
			query.EndDate = t
		}
	}

	if direction := c.Query("direction"); direction != "" {
		query.Direction = direction
	}

	if user := c.Query("user"); user != "" {
		query.User = user
	}

	if status := c.Query("status"); status != "" {
		query.Status = status
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

	result, err := h.mailService.GetMailHistory(query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

func (h *MailHandler) GetMailDetail(c *gin.Context) {
	id := c.Param("id")

	record, err := h.mailService.GetMailDetail(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, record)
}

func (h *MailHandler) DownloadEML(c *gin.Context) {
	id := c.Param("id")

	data, filename, err := h.mailService.DownloadEML(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Disposition", "attachment; filename="+filename)
	c.Header("Content-Type", "message/rfc822")
	c.Data(http.StatusOK, "message/rfc822", data)
}

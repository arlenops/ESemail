package api

import (
	"esemail/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type SetupHandler struct {
	setupService *service.SetupService
}

func NewSetupHandler(setupService *service.SetupService) *SetupHandler {
	return &SetupHandler{
		setupService: setupService,
	}
}

func (h *SetupHandler) GetSetupStatus(c *gin.Context) {
	status := h.setupService.GetSetupStatus()
	c.JSON(http.StatusOK, status)
}

func (h *SetupHandler) ConfigureSystem(c *gin.Context) {
	var config service.SetupConfig

	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误: " + err.Error()})
		return
	}

	if err := h.setupService.ConfigureSystem(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "系统配置完成",
		"next_steps": []string{
			"配置域名DNS记录",
			"申请SSL证书",
			"测试邮件收发",
		},
	})
}

func (h *SetupHandler) GetDKIMRecord(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "域名参数不能为空"})
		return
	}

	publicKey, err := h.setupService.GetDKIMPublicKey(domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"domain":       domain,
		"selector":     "default",
		"record_name":  "default._domainkey." + domain,
		"record_type":  "TXT",
		"record_value": publicKey,
	})
}

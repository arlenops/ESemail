package api

import (
	"esemail/internal/service"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type SetupHandler struct {
    setupService    *service.SetupService
    workflowService *service.WorkflowService
}

func NewSetupHandler(setupService *service.SetupService, workflowService *service.WorkflowService) *SetupHandler {
    return &SetupHandler{
        setupService:    setupService,
        workflowService: workflowService,
    }
}

func (h *SetupHandler) GetSetupStatus(c *gin.Context) {
	status := h.setupService.GetSetupStatus()
	c.JSON(http.StatusOK, status)
}

func (h *SetupHandler) ConfigureSystem(c *gin.Context) {
	log.Printf("收到系统配置请求，来源IP: %s", c.ClientIP())
	
	var config service.SetupConfig

	if err := c.ShouldBindJSON(&config); err != nil {
		log.Printf("参数绑定失败: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误: " + err.Error()})
		return
	}

	log.Printf("解析配置参数成功: 域名=%s, 管理员=%s, 主机名=%s", 
		config.Domain, config.AdminEmail, config.Hostname)

    if err := h.setupService.ConfigureSystem(config); err != nil {
        log.Printf("系统配置失败: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    log.Printf("系统配置成功完成")
    // 初始化设置完成后，推进工作流到第1步（系统初始化）
    if h.workflowService != nil {
        if err := h.workflowService.CompleteStep(1); err != nil {
            c.Header("X-Workflow-Warning", "工作流步骤更新失败: "+err.Error())
        }
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

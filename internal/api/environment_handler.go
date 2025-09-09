package api

import (
	"esemail/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type EnvironmentHandler struct {
	environmentService *service.EnvironmentService
}

func NewEnvironmentHandler(environmentService *service.EnvironmentService) *EnvironmentHandler {
	return &EnvironmentHandler{
		environmentService: environmentService,
	}
}

func (h *EnvironmentHandler) CheckEnvironment(c *gin.Context) {
	status := h.environmentService.CheckEnvironment()
	c.JSON(http.StatusOK, status)
}

func (h *EnvironmentHandler) InstallDependency(c *gin.Context) {
	var req struct {
		Package string `json:"package" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误: " + err.Error()})
		return
	}
	
	if err := h.environmentService.InstallDependency(req.Package); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "安装失败: " + err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "依赖包安装成功",
		"package": req.Package,
	})
}

func (h *EnvironmentHandler) GetInstallScript(c *gin.Context) {
	script := h.environmentService.GetInstallScript()
	
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Content-Disposition", "attachment; filename=install-dependencies.sh")
	c.String(http.StatusOK, script)
}

func (h *EnvironmentHandler) GetEnvironmentStatus(c *gin.Context) {
	status := h.environmentService.CheckEnvironment()
	
	// 简化响应，只返回摘要信息
	c.JSON(http.StatusOK, gin.H{
		"ready":             status.Ready,
		"total_services":    status.Summary.TotalServices,
		"installed":         status.Summary.InstalledServices,
		"missing":           status.Summary.MissingServices,
		"required_missing":  status.Summary.RequiredMissing,
		"has_root":          status.SystemInfo.HasRoot,
		"last_check":        status.LastCheck,
	})
}
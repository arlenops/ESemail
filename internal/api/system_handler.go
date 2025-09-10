package api

import (
	"esemail/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type SystemHandler struct {
	systemService   *service.SystemService
	workflowService *service.WorkflowService
}

func NewSystemHandler(systemService *service.SystemService, workflowService *service.WorkflowService) *SystemHandler {
	return &SystemHandler{
		systemService:   systemService,
		workflowService: workflowService,
	}
}

func (h *SystemHandler) GetSystemStatus(c *gin.Context) {
	status := h.systemService.GetSystemStatus()
	c.JSON(http.StatusOK, status)
}

func (h *SystemHandler) InitializeSystem(c *gin.Context) {
	result := h.systemService.InitializeSystem()

	statusCode := http.StatusOK
	if !result.Success {
		statusCode = http.StatusInternalServerError
	} else {
		// 系统初始化成功后，自动完成工作流第1步
		if h.workflowService != nil {
			if err := h.workflowService.CompleteStep(1); err != nil {
				// 工作流步骤完成失败，但不影响系统初始化结果
				// 记录日志但继续
				c.Header("X-Workflow-Warning", "工作流步骤更新失败: "+err.Error())
			}
		}
	}

	c.JSON(statusCode, result)
}

func (h *SystemHandler) GetInitializationStatus(c *gin.Context) {
	status := h.systemService.GetInitializationStatus()
	c.JSON(http.StatusOK, status)
}

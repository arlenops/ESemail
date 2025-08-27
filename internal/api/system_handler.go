package api

import (
	"esemail/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type SystemHandler struct {
	systemService *service.SystemService
}

func NewSystemHandler(systemService *service.SystemService) *SystemHandler {
	return &SystemHandler{
		systemService: systemService,
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
	}

	c.JSON(statusCode, result)
}

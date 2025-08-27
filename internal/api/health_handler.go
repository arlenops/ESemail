package api

import (
	"esemail/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type HealthHandler struct {
	healthService *service.HealthService
}

func NewHealthHandler(healthService *service.HealthService) *HealthHandler {
	return &HealthHandler{
		healthService: healthService,
	}
}

func (h *HealthHandler) GetSystemHealth(c *gin.Context) {
	health := h.healthService.GetSystemHealth()
	c.JSON(http.StatusOK, health)
}

package api

import (
    "esemail/internal/service"
    "net/http"

    "github.com/gin-gonic/gin"
)

type ConfigHandler struct {
    settings *service.AppSettingsService
    cert     *service.CertService
}

func NewConfigHandler(settings *service.AppSettingsService, cert *service.CertService) *ConfigHandler {
    return &ConfigHandler{settings: settings, cert: cert}
}

// GetConfig 返回当前应用配置（API 管理的部分）
func (h *ConfigHandler) GetConfig(c *gin.Context) {
    data := h.settings.Get()
    c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}

// UpdateConfig 更新配置（允许部分字段）
func (h *ConfigHandler) UpdateConfig(c *gin.Context) {
    var req service.AppSettings
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
        return
    }

    updated, err := h.settings.Update(&req)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
        return
    }

    // 即时生效项：证书邮箱
    if req.Cert.Email != "" && h.cert != nil {
        _ = h.cert.SetEmail(req.Cert.Email)
    }

    c.JSON(http.StatusOK, gin.H{"success": true, "data": updated, "note": "部分设置需要重启服务生效（如域名/端口）"})
}


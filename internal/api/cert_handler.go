package api

import (
	"esemail/internal/service"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type CertHandler struct {
	certService *service.CertService
}

func NewCertHandler(certService *service.CertService) *CertHandler {
	return &CertHandler{
		certService: certService,
	}
}

func (h *CertHandler) ListCertificates(c *gin.Context) {
	certificates, err := h.certService.ListCertificates()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, certificates)
}

func (h *CertHandler) IssueCertificate(c *gin.Context) {
	var req service.IssueCertRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.certService.IssueCertificate(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 根据验证方式返回不同的响应
	if result.Success {
		// HTTP验证直接成功
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "证书申请成功",
		})
	} else {
		// DNS验证需要用户操作
		c.JSON(http.StatusOK, gin.H{
			"success":   false,
			"dns_name":  result.DNSName,
			"dns_value": result.DNSValue,
			"message":   "请添加DNS TXT记录后继续验证",
			"instructions": gin.H{
				"record_type": "TXT",
				"record_name": result.DNSName,
				"record_value": result.DNSValue,
				"example": fmt.Sprintf("添加 TXT 记录：\n名称: %s\n类型: TXT\n值: %s", result.DNSName, result.DNSValue),
				"note": "某些DNS服务商可能只需要输入记录名称的前缀部分，请根据您的DNS服务商要求调整",
			},
		})
	}
}

func (h *CertHandler) RenewCertificates(c *gin.Context) {
	if err := h.certService.RenewCertificates(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "证书续签成功"})
}

// ValidateDNS 验证DNS记录
func (h *CertHandler) ValidateDNS(c *gin.Context) {
	var req struct {
		DNSName  string `json:"dns_name" binding:"required"`
		DNSValue string `json:"dns_value" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.certService.ValidateDNS(req.DNSName, req.DNSValue)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

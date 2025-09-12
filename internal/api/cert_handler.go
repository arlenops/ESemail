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

// GetDNSChallenge 获取当前有效的DNS验证信息
func (h *CertHandler) GetDNSChallenge(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "域名参数不能为空"})
		return
	}

	challenge, err := h.certService.GetCurrentDNSChallenge(domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if challenge == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "未找到该域名的DNS验证信息"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"domain":     challenge.Domain,
		"dns_name":   challenge.DNSName,
		"dns_value":  challenge.DNSValue,
		"created_at": challenge.CreatedAt,
		"instructions": gin.H{
			"record_type": "TXT",
			"record_name": challenge.DNSName,
			"record_value": challenge.DNSValue,
			"example": fmt.Sprintf("添加 TXT 记录：\n名称: %s\n类型: TXT\n值: %s", challenge.DNSName, challenge.DNSValue),
		},
	})
}

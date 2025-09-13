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
	var req struct {
		Domain           string `json:"domain" binding:"required"`
		Email            string `json:"email" binding:"required,email"`
		ValidationMethod string `json:"validation_method"` // 新增验证方法字段
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 根据验证方法选择不同的申请流程
	var result *service.LegoCertResponse
	var err error

	switch req.ValidationMethod {
	case "http":
		result, err = h.certService.IssueHTTPCert(req.Domain, req.Email)
	case "dns":
		fallthrough
	default:
		// 默认使用DNS验证
		result, err = h.certService.IssueDNSCert(req.Domain, req.Email)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if result.Success && result.DNSName != "" {
		// DNS挑战需要用户操作
		c.JSON(http.StatusOK, gin.H{
			"success":   true,
			"dns_name":  result.DNSName,
			"dns_value": result.DNSValue,
			"message":   result.Message,
			"instructions": gin.H{
				"record_type":  "TXT",
				"record_name":  result.DNSName,
				"record_value": result.DNSValue,
				"example": fmt.Sprintf("添加 TXT 记录：\n名称: %s\n类型: TXT\n值: %s",
					result.DNSName, result.DNSValue),
				"note": "添加DNS记录后，请调用完成验证接口: POST /api/v1/certificates/validate-dns/" + req.Domain,
			},
		})
	} else if result.Success && result.Message != "" && req.ValidationMethod == "http" {
		// HTTP挑战需要用户操作
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": result.Message,
			"instructions": gin.H{
				"type": "http",
				"note": "请按照说明创建HTTP验证文件，然后调用完成验证接口: POST /api/v1/certificates/validate-http/" + req.Domain,
			},
		})
	} else if result.Success {
		// 证书申请成功
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": result.Message,
		})
	} else {
		// 申请失败
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   result.Error,
		})
	}
}

func (h *CertHandler) ValidateDNS(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "域名参数不能为空"})
		return
	}

	result, err := h.certService.CompleteDNSChallenge(domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if result.Success {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": result.Message,
		})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   result.Error,
		})
	}
}

func (h *CertHandler) ValidateHTTP(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "域名参数不能为空"})
		return
	}

	result, err := h.certService.CompleteHTTPChallenge(domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if result.Success {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": result.Message,
		})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   result.Error,
		})
	}
}

func (h *CertHandler) GetHTTPChallenge(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "域名参数不能为空"})
		return
	}

	challenge, err := h.certService.GetPendingHTTPChallenge(domain)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"domain":     challenge.Domain,
		"token":      challenge.Token,
		"path":       challenge.Path,
		"content":    challenge.Content,
		"created_at": challenge.CreatedAt,
		"instructions": gin.H{
			"file_path":    challenge.Path,
			"file_content": challenge.Content,
			"url":          fmt.Sprintf("http://%s%s", challenge.Domain, challenge.Path),
			"example":      fmt.Sprintf("创建文件：\n路径: %s\n内容: %s", challenge.Path, challenge.Content),
			"note":         "创建HTTP验证文件后，请调用完成验证接口: POST /api/v1/certificates/validate-http/" + domain,
		},
	})
}

func (h *CertHandler) GetDNSChallenge(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "域名参数不能为空"})
		return
	}

	challenge, err := h.certService.GetPendingChallenge(domain)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"domain":     challenge.Domain,
		"dns_name":   challenge.DNSName,
		"dns_value":  challenge.DNSValue,
		"token":      challenge.Token,
		"created_at": challenge.CreatedAt,
		"instructions": gin.H{
			"record_type": "TXT",
			"record_name": challenge.DNSName,
			"record_value": challenge.DNSValue,
			"example": fmt.Sprintf("添加 TXT 记录：\n名称: %s\n类型: TXT\n值: %s",
				challenge.DNSName, challenge.DNSValue),
			"note": "添加DNS记录后，请调用完成验证接口: POST /api/v1/certificates/validate-dns/" + domain,
		},
	})
}

func (h *CertHandler) RenewCertificates(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "证书续签功能暂未实现"})
}
package api

import (
	"esemail/internal/service"
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

	if err := h.certService.IssueCertificate(req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "证书签发成功"})
}

func (h *CertHandler) RenewCertificates(c *gin.Context) {
	if err := h.certService.RenewCertificates(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "证书续签成功"})
}

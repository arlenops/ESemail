package api

import (
	"esemail/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type DomainHandler struct {
	domainService *service.DomainService
}

func NewDomainHandler(domainService *service.DomainService) *DomainHandler {
	return &DomainHandler{
		domainService: domainService,
	}
}

func (h *DomainHandler) ListDomains(c *gin.Context) {
	domains, err := h.domainService.ListDomains()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, domains)
}

func (h *DomainHandler) AddDomain(c *gin.Context) {
	var req struct {
		Domain string `json:"domain" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.domainService.AddDomain(req.Domain); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "域名添加成功"})
}

func (h *DomainHandler) DeleteDomain(c *gin.Context) {
	domain := c.Param("domain")

	if err := h.domainService.DeleteDomain(domain); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "域名删除成功"})
}

func (h *DomainHandler) GetDNSRecords(c *gin.Context) {
	domain := c.Param("domain")

	records, err := h.domainService.GetDNSRecords(domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, records)
}

package api

import (
	"esemail/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type DNSHandler struct {
	dnsService *service.DNSService
}

func NewDNSHandler(dnsService *service.DNSService) *DNSHandler {
	return &DNSHandler{
		dnsService: dnsService,
	}
}

func (h *DNSHandler) CheckDomainDNS(c *gin.Context) {
	var req service.DNSCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误: " + err.Error()})
		return
	}
	
	// 验证域名格式
	if err := h.dnsService.ValidateDomain(req.Domain); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "域名验证失败: " + err.Error()})
		return
	}
	
	status := h.dnsService.CheckDomainDNS(req.Domain, req.ServerIP, req.MailServer)
	c.JSON(http.StatusOK, status)
}

func (h *DNSHandler) GetDNSSetupGuide(c *gin.Context) {
	domain := c.Query("domain")
	serverIP := c.Query("server_ip")
	mailServer := c.Query("mail_server")
	
	if domain == "" || serverIP == "" || mailServer == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少必需参数: domain, server_ip, mail_server"})
		return
	}
	
	// 验证域名格式
	if err := h.dnsService.ValidateDomain(domain); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "域名验证失败: " + err.Error()})
		return
	}
	
	guide := h.dnsService.GetDNSSetupGuide(domain, serverIP, mailServer)
	c.JSON(http.StatusOK, guide)
}

func (h *DNSHandler) QueryDNSRecord(c *gin.Context) {
	recordType := c.Query("type")
	domain := c.Query("domain")
	
	if recordType == "" || domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少必需参数: type, domain"})
		return
	}
	
	// 验证记录类型
	validTypes := map[string]bool{"A": true, "AAAA": true, "MX": true, "TXT": true, "CNAME": true, "NS": true}
	if !validTypes[recordType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不支持的DNS记录类型"})
		return
	}
	
	results, err := h.dnsService.QueryDNSRecord(recordType, domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"type":    recordType,
		"domain":  domain,
		"records": results,
	})
}
package api

import (
	"esemail/internal/service"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type DomainHandler struct {
	domainService   *service.DomainService
	workflowService *service.WorkflowService
}

func NewDomainHandler(domainService *service.DomainService, workflowService *service.WorkflowService) *DomainHandler {
	return &DomainHandler{
		domainService:   domainService,
		workflowService: workflowService,
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

	// 域名添加成功后，自动完成工作流第2步
	if h.workflowService != nil {
		if err := h.workflowService.CompleteStep(2); err != nil {
			// 工作流步骤完成失败，但不影响域名添加结果
			c.Header("X-Workflow-Warning", "工作流步骤更新失败: "+err.Error())
		}
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

func (h *DomainHandler) CheckDNSRecords(c *gin.Context) {
	domain := c.Param("domain")

	records, err := h.domainService.CheckDNSRecords(domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"domain":     domain,
		"records":    records,
		"message":    "DNS检查完成",
		"checked_at": time.Now().Format("2006-01-02 15:04:05"),
		"note":       "这是真实的DNS查询结果，不是模拟数据",
	})
}

func (h *DomainHandler) TestDNSQuery(c *gin.Context) {
	testDomain := c.Query("test_domain")
	if testDomain == "" {
		testDomain = "google.com" // 默认测试域名
	}

	results := h.domainService.TestDNSQuery(testDomain)
	c.JSON(http.StatusOK, gin.H{
		"test_domain": testDomain,
		"results":     results,
		"message":     "DNS测试查询完成",
	})
}

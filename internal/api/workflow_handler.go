package api

import (
	"esemail/internal/service"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type WorkflowHandler struct {
	workflowService *service.WorkflowService
	systemService   *service.SystemService
	domainService   *service.DomainService
	userService     *service.UserService
	certService     *service.CertService
	mailServer      *service.MailServer
}

func NewWorkflowHandler(
	workflowService *service.WorkflowService,
	systemService *service.SystemService,
	domainService *service.DomainService,
	userService *service.UserService,
	certService *service.CertService,
	mailServer *service.MailServer,
) *WorkflowHandler {
	return &WorkflowHandler{
		workflowService: workflowService,
		systemService:   systemService,
		domainService:   domainService,
		userService:     userService,
		certService:     certService,
		mailServer:      mailServer,
	}
}

// GetWorkflowStatus 获取工作流状态
func (h *WorkflowHandler) GetWorkflowStatus(c *gin.Context) {
	state := h.workflowService.GetCurrentState()
	steps := h.workflowService.GetWorkflowSteps()
	currentStep := h.workflowService.GetCurrentStep()

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"state":        state,
		"steps":        steps,
		"current_step": currentStep,
	})
}

// GetWorkflowSteps 获取所有步骤信息
func (h *WorkflowHandler) GetWorkflowSteps(c *gin.Context) {
	serviceSteps := h.workflowService.GetWorkflowSteps()
	state := h.workflowService.GetCurrentState()

	// 转换为包含运行时状态的步骤
	var steps []WorkflowStepWithState
	for _, step := range serviceSteps {
		stepWithState := WorkflowStepWithState{
			WorkflowStep: step,
			IsCompleted:  containsInt(state.CompletedSteps, step.ID),
			IsCurrent:    step.ID == state.CurrentStep,
			IsAccessible: step.ID <= state.CurrentStep,
		}
		steps = append(steps, stepWithState)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"steps":   steps,
	})
}

// CompleteStep 完成指定步骤
func (h *WorkflowHandler) CompleteStep(c *gin.Context) {
	stepIDStr := c.Param("id")
	stepID, err := strconv.Atoi(stepIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "无效的步骤ID",
		})
		return
	}

	// 验证步骤
	if err := h.workflowService.CompleteStep(stepID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// 返回更新后的状态
	state := h.workflowService.GetCurrentState()
	currentStep := h.workflowService.GetCurrentStep()

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"message":      "步骤完成",
		"state":        state,
		"current_step": currentStep,
	})
}

// CheckStepRequirements 检查步骤要求
func (h *WorkflowHandler) CheckStepRequirements(c *gin.Context) {
	stepIDStr := c.Param("id")
	stepID, err := strconv.Atoi(stepIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "无效的步骤ID",
		})
		return
	}

	// 检查步骤要求
	checkResults := h.checkStepRequirements(stepID)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"step_id": stepID,
		"checks":  checkResults,
	})
}

// checkStepRequirements 检查特定步骤的要求
func (h *WorkflowHandler) checkStepRequirements(stepID int) map[string]interface{} {
	results := make(map[string]interface{})

	switch stepID {
	case 1: // 系统初始化
		results["system_status"] = h.checkSystemStatus()
	case 2: // 域名配置
		results["domain_status"] = h.checkDomainStatus()
	case 3: // DNS验证
		results["dns_status"] = h.checkDNSStatus()
	case 4: // SSL证书
		results["ssl_status"] = h.checkSSLStatus()
	case 5: // 用户管理
		results["user_status"] = h.checkUserStatus()
	case 6: // 邮件服务
		results["mail_status"] = h.checkMailStatus()
	}

	return results
}

// checkSystemStatus 检查系统状态
func (h *WorkflowHandler) checkSystemStatus() map[string]interface{} {
	status := make(map[string]interface{})
	
	if h.systemService != nil {
		initStatus := h.systemService.GetInitializationStatus()
		status["initialized"] = initStatus["is_initialized"]
		status["details"] = initStatus
	} else {
		status["initialized"] = false
		status["error"] = "系统服务未初始化"
	}

	return status
}

// checkDomainStatus 检查域名状态
func (h *WorkflowHandler) checkDomainStatus() map[string]interface{} {
	status := make(map[string]interface{})
	
	if h.domainService != nil {
		domains, err := h.domainService.ListDomains()
		if err != nil {
			status["has_domains"] = false
			status["error"] = err.Error()
		} else {
			status["has_domains"] = len(domains) > 0
			status["domain_count"] = len(domains)
			status["domains"] = domains
		}
	} else {
		status["has_domains"] = false
		status["error"] = "域名服务未初始化"
	}

	return status
}

// checkDNSStatus 检查DNS状态
func (h *WorkflowHandler) checkDNSStatus() map[string]interface{} {
	status := make(map[string]interface{})
	
	if h.domainService != nil {
		domains, err := h.domainService.ListDomains()
		if err != nil {
			status["dns_valid"] = false
			status["error"] = err.Error()
			return status
		}

		allValid := true
		domainResults := make([]map[string]interface{}, 0)

		for _, domain := range domains {
			dnsRecords, err := h.domainService.CheckDNSRecords(domain.Domain)
			domainResult := map[string]interface{}{
				"domain": domain.Domain,
				"valid":  err == nil,
			}

			if err == nil {
				validRecords := 0
				totalRecords := 0
				for _, record := range dnsRecords {
					totalRecords++
					if record.Status == "valid" {
						validRecords++
					}
				}
				domainResult["valid_records"] = validRecords
				domainResult["total_records"] = totalRecords
				domainResult["records"] = dnsRecords

				if validRecords < totalRecords {
					allValid = false
				}
			} else {
				allValid = false
				domainResult["error"] = err.Error()
			}

			domainResults = append(domainResults, domainResult)
		}

		status["dns_valid"] = allValid
		status["domain_results"] = domainResults
	} else {
		status["dns_valid"] = false
		status["error"] = "域名服务未初始化"
	}

	return status
}

// checkSSLStatus 检查SSL状态
func (h *WorkflowHandler) checkSSLStatus() map[string]interface{} {
	status := make(map[string]interface{})
	
	if h.certService != nil {
		certs, err := h.certService.ListCertificates()
		if err != nil {
			status["has_ssl"] = false
			status["error"] = err.Error()
		} else {
			hasValidCert := false
			for _, cert := range certs {
				if cert.Status == "active" {
					hasValidCert = true
					break
				}
			}
			status["has_ssl"] = hasValidCert
			status["certificate_count"] = len(certs)
			status["certificates"] = certs
		}
	} else {
		status["has_ssl"] = false
		status["error"] = "证书服务未初始化"
	}

	return status
}

// checkUserStatus 检查用户状态
func (h *WorkflowHandler) checkUserStatus() map[string]interface{} {
	status := make(map[string]interface{})
	
	if h.userService != nil {
		users, err := h.userService.ListUsers()
		if err != nil {
			status["has_users"] = false
			status["error"] = err.Error()
		} else {
			activeUsers := 0
			for _, user := range users {
				if user.Active {
					activeUsers++
				}
			}
			status["has_users"] = len(users) > 0
			status["has_active_users"] = activeUsers > 0
			status["user_count"] = len(users)
			status["active_user_count"] = activeUsers
		}
	} else {
		status["has_users"] = false
		status["error"] = "用户服务未初始化"
	}

	return status
}

// checkMailStatus 检查邮件服务状态
func (h *WorkflowHandler) checkMailStatus() map[string]interface{} {
	status := make(map[string]interface{})
	
	if h.mailServer != nil {
		status["service_running"] = h.mailServer.IsRunning()
		
		// 检查DKIM配置
		_, err := h.mailServer.GetDKIMPublicKey()
		status["dkim_configured"] = err == nil
		
		if err != nil {
			status["dkim_error"] = err.Error()
		}

		// 获取服务器状态
		serverStatus := h.mailServer.GetStatus()
		status["server_status"] = serverStatus
	} else {
		status["service_running"] = false
		status["dkim_configured"] = false
		status["error"] = "邮件服务未初始化"
	}

	return status
}

// ResetWorkflow 重置工作流（仅用于开发/测试）
func (h *WorkflowHandler) ResetWorkflow(c *gin.Context) {
	if err := h.workflowService.ResetWorkflow(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "工作流已重置",
	})
}

// 辅助函数
func containsInt(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// WorkflowStepWithState 扩展WorkflowStep结构以包含运行时状态
type WorkflowStepWithState struct {
	service.WorkflowStep
	IsCompleted  bool `json:"is_completed"`
	IsCurrent    bool `json:"is_current"`
	IsAccessible bool `json:"is_accessible"`
}
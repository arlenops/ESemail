package middleware

import (
	"esemail/internal/service"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// WorkflowMiddleware 工作流程控制中间件
func WorkflowMiddleware(workflowService *service.WorkflowService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取请求路径
		path := c.Request.URL.Path
		
		// 始终允许的路径（不受工作流控制）
		allowedPaths := []string{
			"/",
			"/login",
			"/api/v1/auth/login",
			"/api/v1/auth/logout", 
			"/api/v1/health",
			"/api/v1/workflow/",
			"/api/v1/csrf-token",
			"/static/",
		}
		
		// 检查是否是始终允许的路径
		for _, allowedPath := range allowedPaths {
			if strings.HasPrefix(path, allowedPath) {
				c.Next()
				return
			}
		}
		
		// 检查功能是否已解锁
		if !workflowService.IsFeatureUnlocked(path) {
			// 获取当前步骤信息
			currentStep := workflowService.GetCurrentStep()
			state := workflowService.GetCurrentState()
			
			c.JSON(http.StatusLocked, gin.H{
				"success":        false,
				"error":          "功能未解锁",
				"message":        "请按照设置向导完成配置后再使用此功能",
				"current_step":   currentStep,
				"workflow_state": state,
				"redirect_url":   "/workflow",
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// WorkflowRedirectMiddleware 工作流重定向中间件（用于页面）
func WorkflowRedirectMiddleware(workflowService *service.WorkflowService) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		
		// 只对页面请求进行重定向，不对API请求
		if strings.HasPrefix(path, "/api/") {
			c.Next()
			return
		}
		
		// 排除静态资源和特殊页面
		excludePaths := []string{
			"/workflow", 
			"/login", 
			"/static/",
			"/test", // 添加测试页面
		}
		
		for _, excludePath := range excludePaths {
			if strings.HasPrefix(path, excludePath) {
				c.Next()
				return
			}
		}
		
		// 获取工作流状态
		state := workflowService.GetCurrentState()
		
		// 如果设置未完成，重定向到工作流页面
		if !state.IsSetupComplete {
			// 避免无限重定向
			if path != "/workflow" {
				c.Redirect(http.StatusTemporaryRedirect, "/workflow")
				c.Abort()
				return
			}
		}
		
		c.Next()
	}
}
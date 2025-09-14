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
			"/api/v1/system/", // 系统初始化相关
			"/api/v1/setup/",  // 系统设置相关
			"/api/v1/environment/", // 环境检查
			"/static/",
			"/test", // 临时测试页面
		}
		
		// 检查是否是始终允许的路径
		for _, allowedPath := range allowedPaths {
			if strings.HasPrefix(path, allowedPath) {
				c.Next()
				return
			}
		}
		
		// 获取工作流状态
		state := workflowService.GetCurrentState()
		
		// 根据步骤进度控制API访问 - 更新的步骤顺序
		if strings.HasPrefix(path, "/api/v1/domains") {
			// 域名管理需要系统初始化完成
			if state.CurrentStep < 2 {
				c.JSON(http.StatusLocked, gin.H{
					"success": false,
					"error":   "功能未解锁",
					"message": "请先完成系统初始化",
					"required_step": "系统初始化",
				})
				c.Abort()
				return
			}
        } else if strings.HasPrefix(path, "/api/v1/certificates") {
            // 放宽：有域名或已到步骤3即可访问
            // 由于中间件无法访问domainService，这里以工作流进度为准：到达步骤2（完成域名添加）即可
            if state.CurrentStep < 3 && state.CurrentStep < 2 {
                c.JSON(http.StatusLocked, gin.H{
                    "success": false,
                    "error":   "功能未解锁",
                    "message": "请先添加域名",
                    "required_step": "域名配置",
                })
                c.Abort()
                return
            }
        } else if strings.HasPrefix(path, "/api/v1/users") {
            // 放宽：到达步骤2（有域名）即可访问
            if state.CurrentStep < 2 {
                c.JSON(http.StatusLocked, gin.H{
                    "success": false,
                    "error":   "功能未解锁",
                    "message": "请先添加域名",
                    "required_step": "域名配置",
                })
                c.Abort()
                return
            }
        } else if strings.HasPrefix(path, "/api/v1/mail") {
            // 邮件服务需要用户管理完成（步骤6）
            if state.CurrentStep < 6 {
                c.JSON(http.StatusLocked, gin.H{
                    "success": false,
                    "error":   "功能未解锁",
                    "message": "请先完成用户管理和SSL证书配置",
                    "required_step": "用户管理",
                })
                c.Abort()
                return
            }
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

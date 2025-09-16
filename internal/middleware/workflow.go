package middleware

import (
    "esemail/internal/service"
    "net/http"
    "strings"

    "github.com/gin-gonic/gin"
)

// WorkflowMiddleware 工作流程控制中间件
// 取消工作流门禁：放开所有功能
func WorkflowMiddleware(_ *service.WorkflowService) gin.HandlerFunc {
    return func(c *gin.Context) { c.Next() }
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

package api

import (
    "esemail/internal/config"
    "esemail/internal/middleware"
    "esemail/internal/service"
    "fmt"
    "html/template"
    "net/http"
    "os"
    "path/filepath"

    "github.com/gin-gonic/gin"
)

// findResourcePath 查找资源文件路径，支持多种部署结构
func findResourcePath(resourceType string) string {
	// 可能的路径列表
	possiblePaths := []string{
		filepath.Join("web", resourceType),           // 相对路径 (开发环境)
		filepath.Join("src", "web", resourceType),   // src子目录
		filepath.Join("..", "web", resourceType),    // 上级目录
	}

	// 获取当前可执行文件目录
	executable, err := os.Executable()
	if err == nil {
		execDir := filepath.Dir(executable)
		possiblePaths = append(possiblePaths, []string{
			filepath.Join(execDir, "web", resourceType),
			filepath.Join(execDir, "src", "web", resourceType),
			filepath.Join(execDir, "..", "web", resourceType),
		}...)
	}

	// 检查每个可能的路径
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

func SetupRouter(
    cfg *config.Config,
    healthService *service.HealthService,
    systemService *service.SystemService,
    domainService *service.DomainService,
    userService *service.UserService,
    mailServer *service.MailServer,
    certService *service.CertService,
    authService *service.AuthService,
    validationService *service.ValidationService,
) *gin.Engine {
	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	// 添加基础中间件
	r.Use(middleware.RequestLogMiddleware())
	r.Use(middleware.SecurityHeadersMiddleware())
	r.Use(middleware.RequestValidationMiddleware(validationService))
	r.Use(middleware.RateLimitMiddleware())

	// CSRF保护配置
	csrfConfig := middleware.DefaultCSRFConfig()
	csrfConfig.TrustedOrigins = []string{"https://mail.caiji.wiki"}
	r.Use(middleware.CSRFMiddleware(csrfConfig))

	// 全局错误恢复
	r.Use(gin.Recovery())

	// 自动检测模板和静态文件路径
	templatesPath := findResourcePath("templates")
	staticPath := findResourcePath("static")

	if templatesPath != "" {
		fmt.Printf("找到模板路径: %s\n", templatesPath)
		tmpl := template.Must(template.ParseGlob(filepath.Join(templatesPath, "*")))
		r.SetHTMLTemplate(tmpl)
	} else {
		fmt.Printf("警告: 未找到模板路径\n")
	}
	if staticPath != "" {
		fmt.Printf("找到静态文件路径: %s\n", staticPath)
		r.Static("/static", staticPath)
	} else {
		fmt.Printf("警告: 未找到静态文件路径\n")
	}

	// 主页 - 直接跳转到管理面板
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"title": "ESemail 邮局管理面板",
		})
	})

	// 登录页面
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title": "ESemail 登录",
		})
	})

	api := r.Group("/api/v1")
	{
		// 公开接口（无需认证）
		auth := api.Group("/auth")
		{
			authHandler := NewAuthHandler(authService, validationService)
			auth.POST("/login", authHandler.Login)
			auth.POST("/logout", authHandler.Logout)
		}

		// 健康检查（无需认证）
		api.GET("/health", NewHealthHandler(healthService).GetSystemHealth)

		// CSRF令牌获取
		api.GET("/csrf-token", middleware.GetCSRFTokenHandler(csrfConfig))

		// 系统状态（无需认证）
		system := api.Group("/system")
		{
			systemHandler := NewSystemHandler(systemService)
			system.GET("/status", systemHandler.GetSystemStatus)
		}

		// 需要认证的接口组
		authenticated := api.Group("/")
		authenticated.Use(AuthMiddleware(authService))
		{
			// 用户信息
			authHandler := NewAuthHandler(authService, validationService)
			authenticated.GET("/auth/me", authHandler.GetCurrentUser)
			authenticated.POST("/auth/change-password", authHandler.ChangePassword)

			// 域名管理
			domains := authenticated.Group("/domains")
			{
				domainHandler := NewDomainHandler(domainService, certService)
				domains.GET("", domainHandler.ListDomains)
				domains.POST("", domainHandler.AddDomain)
				domains.DELETE("/:domain", domainHandler.DeleteDomain)
				domains.GET("/:domain/dns", domainHandler.GetDNSRecords)
				domains.POST("/:domain/ssl/request", domainHandler.RequestSSLCertificate)
			}

			// 用户管理
			users := authenticated.Group("/users")
			{
				uh := NewUserHandler(userService)
				users.GET("", uh.ListUsers)
				users.POST("", uh.CreateUser)
				users.PUT("/:id", uh.UpdateUser)
				users.DELETE("/:id", uh.DeleteUser)
				users.POST("/:id/reset-password", uh.ResetPassword)
			}

			// 邮件服务
			mail := authenticated.Group("/mail")
			{
				mailServerHandler := NewMailServerHandler(mailServer)
				mail.GET("/status", mailServerHandler.GetMailServerStatus)
				mail.POST("/send", mailServerHandler.SendEmail)
				mail.GET("/history", mailServerHandler.GetMailHistory)
				mail.GET("/history/:id", mailServerHandler.GetMailDetail)
				mail.GET("/dkim-record", mailServerHandler.GetDKIMRecord)
				mail.GET("/dns-records", mailServerHandler.GetRecommendedDNSRecords)
			}

			// 证书管理
			certs := authenticated.Group("/certificates")
			{
				certHandler := NewCertHandler(certService)
				certs.GET("", certHandler.ListCertificates)
				certs.POST("/issue", certHandler.IssueCertificate)
				certs.POST("/validate-dns/:domain", certHandler.ValidateDNS)
				certs.GET("/dns-challenge/:domain", certHandler.GetDNSChallenge)
				certs.POST("/renew", certHandler.RenewCertificates)
				certs.DELETE("/:domain", certHandler.DeleteCertificate)
			}
		}
	}

	return r
}
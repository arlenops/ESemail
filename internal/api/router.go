package api

import (
	"esemail/internal/config"
	"esemail/internal/middleware"
	"esemail/internal/service"
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
	setupService *service.SetupService,
	authService *service.AuthService,
	validationService *service.ValidationService,
	environmentService *service.EnvironmentService,
	dnsService *service.DNSService,
) *gin.Engine {
	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	// 添加安全中间件
	r.Use(middleware.RequestLogMiddleware())
	r.Use(middleware.SecurityHeadersMiddleware())
	r.Use(middleware.RequestValidationMiddleware(validationService))
	r.Use(middleware.RateLimitMiddleware())
	
	// CSRF保护配置
	csrfConfig := middleware.DefaultCSRFConfig()
	// 清空TrustedOrigins以允许所有来源（生产环境需要配置具体域名）
	csrfConfig.TrustedOrigins = []string{}
	r.Use(middleware.CSRFMiddleware(csrfConfig))
	
	// 全局错误恢复
	r.Use(gin.Recovery())

	// 自动检测模板和静态文件路径
	templatesPath := findResourcePath("templates")
	staticPath := findResourcePath("static")
	
	if templatesPath != "" {
		r.LoadHTMLGlob(filepath.Join(templatesPath, "*"))
	}
	if staticPath != "" {
		r.Static("/static", staticPath)
	}

	r.GET("/", func(c *gin.Context) {
		// 检查系统是否已设置
		setupService := service.NewSetupService()
		status := setupService.GetSetupStatus()

		if !status.IsSetup {
			c.HTML(http.StatusOK, "setup.html", gin.H{
				"title": "ESemail 系统配置",
			})
			return
		}

		// 检查系统是否已初始化
		initStatus := systemService.GetInitializationStatus()
		
		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"title":           "ESemail 邮局管理面板",
			"is_initialized":  initStatus["is_initialized"],
			"init_status":     initStatus,
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

		// 系统设置相关（无需认证，用于初始化）
		setup := api.Group("/setup")
		{
			setup.GET("/status", NewSetupHandler(setupService).GetSetupStatus)
			setup.POST("/configure", NewSetupHandler(setupService).ConfigureSystem)
			setup.GET("/dkim", NewSetupHandler(setupService).GetDKIMRecord)
		}

		// 系统初始化（无需认证）
		system := api.Group("/system")
		{
			system.GET("/status", NewSystemHandler(systemService).GetSystemStatus)
			system.GET("/init-status", NewSystemHandler(systemService).GetInitializationStatus)
			system.POST("/init", NewSystemHandler(systemService).InitializeSystem)
		}

		// 环境检查（无需认证）
		environment := api.Group("/environment")
		{
			environmentHandler := NewEnvironmentHandler(environmentService)
			environment.GET("/check", environmentHandler.CheckEnvironment)
			environment.GET("/status", environmentHandler.GetEnvironmentStatus)
			environment.GET("/install-script", environmentHandler.GetInstallScript)
		}

		// DNS检查（无需认证）
		dns := api.Group("/dns")
		{
			dnsHandler := NewDNSHandler(dnsService)
			dns.POST("/check", dnsHandler.CheckDomainDNS)
			dns.GET("/setup-guide", dnsHandler.GetDNSSetupGuide)
			dns.GET("/query", dnsHandler.QueryDNSRecord)
		}

		// 需要认证的接口组
		authenticated := api.Group("/")
		authenticated.Use(AuthMiddleware(authService))
		{
			// 用户信息
			authHandler := NewAuthHandler(authService, validationService)
			authenticated.GET("/auth/me", authHandler.GetCurrentUser)
			authenticated.POST("/auth/change-password", authHandler.ChangePassword)

			// 其他需要认证的系统管理接口可以放这里

			// 域名管理
			domains := authenticated.Group("/domains")
			{
				domains.GET("", NewDomainHandler(domainService).ListDomains)
				domains.POST("", NewDomainHandler(domainService).AddDomain)
				domains.DELETE("/:domain", NewDomainHandler(domainService).DeleteDomain)
				domains.GET("/:domain/dns", NewDomainHandler(domainService).GetDNSRecords)
			}

			// 用户管理
			users := authenticated.Group("/users")
			{
				users.GET("", NewUserHandler(userService).ListUsers)
				users.POST("", NewUserHandler(userService).CreateUser)
				users.PUT("/:id", NewUserHandler(userService).UpdateUser)
				users.DELETE("/:id", NewUserHandler(userService).DeleteUser)
				users.POST("/:id/reset-password", NewUserHandler(userService).ResetPassword)
			}

			// 邮件服务和历史
			mail := authenticated.Group("/mail")
			{
				mailServerHandler := NewMailServerHandler(mailServer)
				mail.GET("/status", mailServerHandler.GetMailServerStatus)
				mail.POST("/send", mailServerHandler.SendEmail)
				mail.GET("/history", mailServerHandler.GetMailHistory)
				mail.GET("/history/:id", mailServerHandler.GetMailDetail)
				mail.GET("/history/:id/download", mailServerHandler.DownloadEML)
				mail.GET("/user-messages", mailServerHandler.GetUserMessages)
				mail.GET("/search", mailServerHandler.SearchMessages)
			}

			// 证书管理
			certs := authenticated.Group("/certificates")
			{
				certs.GET("", NewCertHandler(certService).ListCertificates)
				certs.POST("/issue", NewCertHandler(certService).IssueCertificate)
				certs.POST("/renew", NewCertHandler(certService).RenewCertificates)
			}
		}
	}

	return r
}

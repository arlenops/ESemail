package api

import (
	"esemail/internal/config"
	"esemail/internal/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

func SetupRouter(
	cfg *config.Config,
	healthService *service.HealthService,
	systemService *service.SystemService,
	domainService *service.DomainService,
	userService *service.UserService,
	mailService *service.MailService,
	certService *service.CertService,
	setupService *service.SetupService,
) *gin.Engine {
	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()

	r.LoadHTMLGlob("web/templates/*")
	r.Static("/static", "web/static")

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

		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"title": "ESemail 邮局管理面板",
		})
	})

	api := r.Group("/api/v1")
	{
		api.GET("/health", NewHealthHandler(healthService).GetSystemHealth)
		api.GET("/system/status", NewSystemHandler(systemService).GetSystemStatus)
		api.POST("/system/init", NewSystemHandler(systemService).InitializeSystem)

		// 系统设置相关
		setup := api.Group("/setup")
		{
			setup.GET("/status", NewSetupHandler(setupService).GetSetupStatus)
			setup.POST("/configure", NewSetupHandler(setupService).ConfigureSystem)
			setup.GET("/dkim", NewSetupHandler(setupService).GetDKIMRecord)
		}

		domains := api.Group("/domains")
		{
			domains.GET("", NewDomainHandler(domainService).ListDomains)
			domains.POST("", NewDomainHandler(domainService).AddDomain)
			domains.DELETE("/:domain", NewDomainHandler(domainService).DeleteDomain)
			domains.GET("/:domain/dns", NewDomainHandler(domainService).GetDNSRecords)
		}

		users := api.Group("/users")
		{
			users.GET("", NewUserHandler(userService).ListUsers)
			users.POST("", NewUserHandler(userService).CreateUser)
			users.PUT("/:id", NewUserHandler(userService).UpdateUser)
			users.DELETE("/:id", NewUserHandler(userService).DeleteUser)
			users.POST("/:id/reset-password", NewUserHandler(userService).ResetPassword)
		}

		mail := api.Group("/mail")
		{
			mail.GET("/history", NewMailHandler(mailService).GetMailHistory)
			mail.GET("/history/:id", NewMailHandler(mailService).GetMailDetail)
			mail.GET("/history/:id/download", NewMailHandler(mailService).DownloadEML)
		}

		certs := api.Group("/certificates")
		{
			certs.GET("", NewCertHandler(certService).ListCertificates)
			certs.POST("/issue", NewCertHandler(certService).IssueCertificate)
			certs.POST("/renew", NewCertHandler(certService).RenewCertificates)
		}
	}

	return r
}

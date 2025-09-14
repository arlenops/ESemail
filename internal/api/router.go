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
    "sync"
    "time"

	"github.com/gin-gonic/gin"
)

// WorkflowStepWithState 扩展WorkflowStep结构以包含运行时状态
type WorkflowStepWithState struct {
	service.WorkflowStep
	IsCompleted  bool `json:"is_completed"`
	IsCurrent    bool `json:"is_current"`
	IsAccessible bool `json:"is_accessible"`
}

// containsInt 检查slice中是否包含指定的int值
func containsInt(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

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
    workflowService *service.WorkflowService,
    settingsService *service.AppSettingsService,
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
	
	// 工作流程控制中间件
	// r.Use(middleware.WorkflowRedirectMiddleware(workflowService)) // 临时禁用重定向
	r.Use(middleware.WorkflowMiddleware(workflowService))
	
	// 全局错误恢复
	r.Use(gin.Recovery())

	// 自动检测模板和静态文件路径
	templatesPath := findResourcePath("templates")
	staticPath := findResourcePath("static")
	
	// 添加调试日志
	if templatesPath != "" {
		fmt.Printf("找到模板路径: %s\n", templatesPath)
		// 定义自定义模板函数
		funcMap := template.FuncMap{
			"mul": func(a, b int) int { return a * b },
			"len": func(v interface{}) int {
				switch s := v.(type) {
				case []int:
					return len(s)
				case []interface{}:
					return len(s)
				default:
					return 0
				}
			},
		}
		
		// 创建自定义模板并设置函数映射
		tmpl := template.Must(template.New("").Funcs(funcMap).ParseGlob(filepath.Join(templatesPath, "*")))
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

		// 获取工作流状态
		state := workflowService.GetCurrentState()

		// 检查系统是否已初始化
		initStatus := systemService.GetInitializationStatus()

        // 计算功能解锁状态 - 更新的步骤顺序（对证书/用户管理更宽松：有域名即可解锁）
            hasDomains := false
            if domains, err := domainService.ListDomains(); err == nil && len(domains) > 0 {
                hasDomains = true
            }
            // 兼容：初始化完成但工作流未及时持久化时，仍立即解锁
            systemSetup := setupService.IsSystemSetup()
            unlockStatus := map[string]bool{
                // 使用Setup完成标志作为系统初始化的快速判断
                "system_init":    systemSetup,
                // 域名管理解锁：系统初始化已完成 或 工作流到达第2步
                "domain_config":  (systemSetup || containsInt(state.CompletedSteps, 1) || state.CurrentStep >= 2),
                // 证书管理：存在域名即可解锁（或已到步骤3）
                "ssl_config":     hasDomains || containsInt(state.CompletedSteps, 2) || state.CurrentStep >= 3,
                // 用户管理：存在域名即可解锁（或已到步骤4）
                "user_mgmt":      hasDomains || containsInt(state.CompletedSteps, 2) || state.CurrentStep >= 4,
                "dns_verified":   containsInt(state.CompletedSteps, 4) || state.CurrentStep >= 5, // DNS验证在步骤5
                "mail_service":   containsInt(state.CompletedSteps, 5) || state.CurrentStep >= 6, // 邮件服务在步骤6，需要用户管理完成
                "setup_complete": state.IsSetupComplete,
            }

		c.HTML(http.StatusOK, "dashboard.html", gin.H{
			"title":           "ESemail 邮局管理面板",
			"is_initialized":  initStatus["is_initialized"],
			"init_status":     initStatus,
			"workflow_state":  state,
			"unlock_status":   unlockStatus,
		})
	})

	// 登录页面
	r.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title": "ESemail 登录",
		})
	})

	// 工作流引导页面
	r.GET("/workflow", func(c *gin.Context) {
		fmt.Printf("访问 /workflow 路由\n")
		
		state := workflowService.GetCurrentState()
		serviceSteps := workflowService.GetWorkflowSteps()
		currentStep := workflowService.GetCurrentStep()

		fmt.Printf("工作流状态: %+v\n", state)
		fmt.Printf("步骤数量: %d\n", len(serviceSteps))

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
			fmt.Printf("步骤 %d: %s - 完成:%v, 当前:%v, 可访问:%v\n", 
				step.ID, step.Title, stepWithState.IsCompleted, stepWithState.IsCurrent, stepWithState.IsAccessible)
		}

		data := gin.H{
			"title":        "ESemail 设置向导",
			"state":        state,
			"steps":        steps,
			"current_step": currentStep,
		}
		
		fmt.Printf("模板数据: %+v\n", data)
		fmt.Printf("准备渲染 workflow_simple.html 模板\n")
		
		c.HTML(http.StatusOK, "workflow_simple.html", data)
	})

	// 简单测试页面
	r.GET("/test", func(c *gin.Context) {
		c.HTML(http.StatusOK, "test.html", gin.H{
			"title": "测试页面",
			"state": &service.WorkflowState{
				CurrentStep:      1,
				CompletedSteps:   []int{},
				IsSetupComplete:  false,
				UnlockedFeatures: []string{},
			},
			"steps": []WorkflowStepWithState{
				{
					WorkflowStep: service.WorkflowStep{
						ID:          1,
						Title:       "测试步骤",
						Description: "这是一个测试步骤",
					},
					IsCompleted:  false,
					IsCurrent:    true,
					IsAccessible: true,
				},
			},
			"current_step": &service.WorkflowStep{
				ID:          1,
				Title:       "测试步骤",
				Description: "这是一个测试步骤",
			},
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
            sh := NewSetupHandler(setupService, workflowService)
            setup.GET("/status", sh.GetSetupStatus)
            setup.POST("/configure", sh.ConfigureSystem)
            setup.GET("/dkim", sh.GetDKIMRecord)
        }

		// 系统初始化（无需认证）
		system := api.Group("/system")
		{
			systemHandler := NewSystemHandler(systemService, workflowService)
			system.GET("/status", systemHandler.GetSystemStatus)
			system.GET("/init-status", systemHandler.GetInitializationStatus)
			system.POST("/init", systemHandler.InitializeSystem)
		}

		// 环境检查（无需认证）
		environment := api.Group("/environment")
		{
			environmentHandler := NewEnvironmentHandler(environmentService)
			environment.GET("/check", environmentHandler.CheckEnvironment)
			environment.GET("/status", environmentHandler.GetEnvironmentStatus)
			environment.GET("/install-script", environmentHandler.GetInstallScript)
		}

		// 工作流控制（无需认证，用于设置向导）
		workflow := api.Group("/workflow")
		{
			workflowHandler := NewWorkflowHandler(workflowService, systemService, domainService, userService, certService, mailServer)
			workflow.GET("/status", workflowHandler.GetWorkflowStatus)
			workflow.GET("/steps", workflowHandler.GetWorkflowSteps)
			workflow.POST("/complete/:id", workflowHandler.CompleteStep)
			workflow.GET("/check/:id", workflowHandler.CheckStepRequirements)
			workflow.POST("/reset", workflowHandler.ResetWorkflow) // 仅用于开发测试

			// 获取功能解锁状态
            // 5分钟缓存，避免高频调用；当工作流状态/域名/用户变更时立即失效
            var unlockCache = struct {
                mu           sync.RWMutex
                data         gin.H
                at           time.Time
                stateUpdated time.Time
                domainCount  int
                activeUsers  int
            }{}

            workflow.GET("/unlock-status", func(c *gin.Context) {
                // 获取当前状态，用于与缓存对比
                state := workflowService.GetCurrentState()
                // 当前域名/用户计数（用于缓存失效）
                domains, _ := domainService.ListDomains()
                users, _ := userService.ListUsers()
                curDomainCount := len(domains)
                curActiveUsers := 0
                for _, u := range users { if u.Active { curActiveUsers++ } }

                // 尝试返回缓存：缓存时间在5分钟内，且缓存对应的状态更新时间不早于当前状态
                unlockCache.mu.RLock()
                if !unlockCache.at.IsZero() && time.Since(unlockCache.at) < 5*time.Minute && unlockCache.data != nil &&
                   !state.LastUpdated.After(unlockCache.stateUpdated) &&
                   unlockCache.domainCount == curDomainCount && unlockCache.activeUsers == curActiveUsers {
                    c.Header("Cache-Control", "public, max-age=300")
                    c.Header("X-Cache", "HIT")
                    c.JSON(http.StatusOK, unlockCache.data)
                    unlockCache.mu.RUnlock()
                    return
                }
                unlockCache.mu.RUnlock()

                // 计算最新状态（仅基于工作流与域名/用户，避免重度系统调用导致阻塞）
                systemInit := setupService.IsSystemSetup() || containsInt(state.CompletedSteps, 1) || state.CurrentStep >= 2
                hasDomains := curDomainCount > 0
                hasUsers := curActiveUsers > 0
                unlockStatus := map[string]bool{
                    "system_init":    systemInit,
                    "domain_config":  (systemInit || containsInt(state.CompletedSteps, 1) || state.CurrentStep >= 2),
                    "ssl_config":     hasDomains || containsInt(state.CompletedSteps, 2) || state.CurrentStep >= 3,
                    "user_mgmt":      hasDomains || containsInt(state.CompletedSteps, 2) || state.CurrentStep >= 4,
                    "dns_verified":   containsInt(state.CompletedSteps, 4) || state.CurrentStep >= 5,
                    "mail_service":   hasUsers || containsInt(state.CompletedSteps, 4) || state.CurrentStep >= 6,
                    "setup_complete": state.IsSetupComplete,
                }

                resp := gin.H{
                    "success": true,
                    "unlock_status": unlockStatus,
                    "workflow_state": state,
                }

                // 写入缓存
                unlockCache.mu.Lock()
                unlockCache.data = resp
                unlockCache.at = time.Now()
                unlockCache.stateUpdated = state.LastUpdated
                unlockCache.domainCount = curDomainCount
                unlockCache.activeUsers = curActiveUsers
                unlockCache.mu.Unlock()

                c.Header("Cache-Control", "public, max-age=300")
                c.Header("X-Cache", "MISS")
                c.JSON(http.StatusOK, resp)
            })
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
            domainHandler := NewDomainHandler(domainService, workflowService, certService)
            domains.GET("", domainHandler.ListDomains)
            domains.POST("", domainHandler.AddDomain)
            domains.DELETE("/:domain", domainHandler.DeleteDomain)
            domains.GET("/:domain/dns", domainHandler.GetDNSRecords)
            domains.POST("/:domain/dns/check", domainHandler.CheckDNSRecords)
            domains.POST("/:domain/dns/verify", domainHandler.VerifyDNSRecords) // 专业DNS验证
            domains.POST("/:domain/ssl/request", domainHandler.RequestSSLCertificate) // SSL证书申请
            domains.GET("/test-dns", domainHandler.TestDNSQuery)
        }

			// 用户管理
            users := authenticated.Group("/users")
            {
                uh := NewUserHandler(userService, workflowService)
                users.GET("", uh.ListUsers)
                users.POST("", uh.CreateUser)
                users.PUT("/:id", uh.UpdateUser)
                users.DELETE("/:id", uh.DeleteUser)
                users.POST("/:id/reset-password", uh.ResetPassword)
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
				mail.GET("/dkim-record", mailServerHandler.GetDKIMRecord)
				mail.GET("/dns-records", mailServerHandler.GetRecommendedDNSRecords)
			}

        // 证书管理
        certs := authenticated.Group("/certificates")
        {
            certHandler := NewCertHandler(certService)
            certHandler.workflowService = workflowService
            certs.GET("", certHandler.ListCertificates)
            certs.POST("/issue", certHandler.IssueCertificate)
            certs.POST("/validate-dns/:domain", certHandler.ValidateDNS)
            certs.GET("/dns-challenge/:domain", certHandler.GetDNSChallenge)
            certs.POST("/renew", certHandler.RenewCertificates)
            certs.GET("/settings", certHandler.GetSettings)
            certs.POST("/settings", certHandler.UpdateSettings)
            certs.GET("/pending", certHandler.GetPendingChallenges)
        }

        // 应用配置（API管理）
        cfgAPI := authenticated.Group("/config")
        {
            confHandler := NewConfigHandler(settingsService, certService)
            cfgAPI.GET("", confHandler.GetConfig)
            cfgAPI.POST("", confHandler.UpdateConfig)
        }
		}
	}

	return r
}

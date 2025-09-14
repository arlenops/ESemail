package main

import (
    "esemail/internal/api"
    "esemail/internal/config"
    "esemail/internal/service"
    "esemail/internal/storage"
    "log"
    "time"
)

func main() {
    cfg, err := config.Load()
    if err != nil {
        log.Fatalf("配置加载失败: %v", err)
    }

    // 初始化存储 - 使用相对路径避免权限问题
    dataDir := "./data"
    if cfg.Storage.DataDir != "" {
        dataDir = cfg.Storage.DataDir
    }
    jsonStorage := storage.NewJSONStorage(dataDir)
    if err := jsonStorage.Initialize(); err != nil {
        log.Fatalf("存储初始化失败: %v", err)
    }

    // 加载API管理的应用配置，并覆盖关键项（轻量化：不依赖config.yaml）
    settingsService := service.NewAppSettingsService(dataDir)
    if settings, err := settingsService.Load(); err == nil && settings != nil {
        if settings.Mail.Domain != "" { cfg.Mail.Domain = settings.Mail.Domain }
        if settings.Cert.Email != "" { cfg.Cert.Email = settings.Cert.Email }
        if settings.Cert.Server != "" { cfg.Cert.Server = settings.Cert.Server }
        if settings.Cert.CertPath != "" { cfg.Cert.CertPath = settings.Cert.CertPath }
    }

    // 初始化服务
    validationService := service.NewValidationService()
    authService := service.NewAuthService()
    healthService := service.NewHealthService()
    systemService := service.NewSystemService()
    domainService := service.NewDomainServiceWithConfig(dataDir)
    userService := service.NewUserService()
    certService, err := service.NewCertService(&cfg.Cert)
    if err != nil {
        log.Fatalf("证书服务初始化失败: %v", err)
    }
    setupService := service.NewSetupService()
    environmentService := service.NewEnvironmentService()
    dnsService := service.NewDNSService()
	
    // 初始化工作流服务
    workflowService := service.NewWorkflowService(dataDir)
    // 证书安装完成后，推进工作流到步骤3（SSL/TLS证书配置）
    certService.SetOnInstalled(func(domain string) {
        if err := workflowService.CompleteStep(3); err != nil {
            log.Printf("WARN: 完成工作流步骤3失败: %v", err)
        } else {
            log.Printf("INFO: 证书安装完成，已推进工作流到步骤3")
        }
    })
	
	// 初始化邮件服务器
	mailServerConfig := &service.MailServerConfig{
		Domain:         cfg.Mail.Domain,
		DataDir:        dataDir,
		SMTPPort:       cfg.Mail.SMTPPort,
		SMTPSPort:      cfg.Mail.SMTPSPort,
		IMAPPort:       cfg.Mail.IMAPPort,
		IMAPSPort:      cfg.Mail.IMAPSPort,
		MaxMessageSize: cfg.Mail.MaxMessageSize,
		MaxRecipients:  cfg.Mail.MaxRecipients,
		TLSCertFile:    cfg.Mail.TLSCertFile,
		TLSKeyFile:     cfg.Mail.TLSKeyFile,
		EnableTLS:      cfg.Mail.EnableTLS,
	}
	
	mailServer, err := service.NewMailServer(mailServerConfig, userService, domainService)
	if err != nil {
		log.Fatalf("创建邮件服务器失败: %v", err)
	}
	
	// 启动邮件服务器
	if err := mailServer.Start(); err != nil {
		log.Printf("启动邮件服务器失败: %v", err)
	} else {
		log.Println("邮件服务器启动成功")
	}
	
	// 为工作流服务设置服务引用
	workflowService.SetServiceReferences(
		systemService,
		domainService,
		userService,
		certService,
		mailServer,
	)
	
    router := api.SetupRouter(
        cfg, 
        healthService, 
        systemService, 
        domainService, 
        userService, 
        mailServer, 
        certService, 
        setupService, 
        authService,
        validationService,
        environmentService,
        dnsService,
        workflowService,
        settingsService,
    )

    // 启动健康检查定时器（每5分钟），用于周期性检查
    go func() {
        ticker := time.NewTicker(5 * time.Minute)
        defer ticker.Stop()
        for range ticker.C {
            st := systemService.GetSystemStatus()
            log.Printf("HEALTH: initialized=%v services=%v", st.Initialized, st.ServicesStatus)
        }
    }()

    log.Printf("ESemail 控制面启动在端口 :%s", cfg.Server.Port)
	if err := router.Run(":" + cfg.Server.Port); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

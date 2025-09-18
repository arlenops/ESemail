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

    // 初始化存储 - 使用固定绝对路径
    dataDir := "/opt/esemail/data"
    jsonStorage := storage.NewJSONStorage(dataDir)
    if err := jsonStorage.Initialize(); err != nil {
        log.Fatalf("存储初始化失败: %v", err)
    }

    // 初始化核心服务
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

    router := api.SetupRouter(
        cfg,
        healthService,
        systemService,
        domainService,
        userService,
        mailServer,
        certService,
        authService,
        validationService,
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
package main

import (
	"esemail/internal/api"
	"esemail/internal/config"
	"esemail/internal/service"
	"esemail/internal/storage"
	"log"
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

	// 初始化服务
	validationService := service.NewValidationService()
	authService := service.NewAuthService()
	healthService := service.NewHealthService()
	systemService := service.NewSystemService()
	domainService := service.NewDomainService()
	userService := service.NewUserService()
	certService := service.NewCertService()
	setupService := service.NewSetupService()
	environmentService := service.NewEnvironmentService()
	dnsService := service.NewDNSService()
	
	// 初始化邮件服务器
	mailServerConfig := &service.MailServerConfig{
		Domain:         "localhost", // 默认域名，应该从配置中获取
		DataDir:        "./data",
		SMTPPort:       "2525",  // 非特权端口
		SMTPSPort:      "4465",  // 非特权端口
		IMAPPort:       "1143",  // 非特权端口 
		IMAPSPort:      "9993",  // 非特权端口
		MaxMessageSize: 25 * 1024 * 1024, // 25MB
		MaxRecipients:  100,
		TLSCertFile:    "./certs/server.crt",
		TLSKeyFile:     "./certs/server.key",
		EnableTLS:      false, // 初始时禁用TLS，避免证书问题
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
		setupService, 
		authService,
		validationService,
		environmentService,
		dnsService,
	)

	log.Printf("ESemail 控制面启动在端口 :%s", cfg.Server.Port)
	if err := router.Run(":" + cfg.Server.Port); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

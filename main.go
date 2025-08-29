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

	// 初始化存储
	jsonStorage := storage.NewJSONStorage("/var/lib/esemail/data")
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
	mailService := service.NewMailService()
	certService := service.NewCertService()
	setupService := service.NewSetupService()

	router := api.SetupRouter(
		cfg, 
		healthService, 
		systemService, 
		domainService, 
		userService, 
		mailService, 
		certService, 
		setupService, 
		authService,
		validationService,
	)

	log.Printf("ESemail 控制面启动在端口 :%s", cfg.Server.Port)
	if err := router.Run(":" + cfg.Server.Port); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

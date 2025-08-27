package main

import (
	"esemail/internal/api"
	"esemail/internal/config"
	"esemail/internal/service"
	"log"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("配置加载失败: %v", err)
	}

	healthService := service.NewHealthService()
	systemService := service.NewSystemService()
	domainService := service.NewDomainService()
	userService := service.NewUserService()
	mailService := service.NewMailService()
	certService := service.NewCertService()
	setupService := service.NewSetupService()

	router := api.SetupRouter(cfg, healthService, systemService, domainService, userService, mailService, certService, setupService)

	log.Printf("ESemail 控制面启动在端口 :%s", cfg.Server.Port)
	if err := router.Run(":" + cfg.Server.Port); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

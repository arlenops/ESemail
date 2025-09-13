package service

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// WorkflowService 工作流程控制服务
type WorkflowService struct {
	mutex         sync.RWMutex
	currentState  *WorkflowState
	stateFile     string
	systemService *SystemService
	domainService *DomainService
	userService   *UserService
	certService   *CertService
	mailServer    *MailServer
}

// WorkflowState 工作流状态
type WorkflowState struct {
	CurrentStep      int                    `json:"current_step"`
	CompletedSteps   []int                  `json:"completed_steps"`
	StepDetails      map[string]interface{} `json:"step_details"`
	LastUpdated      time.Time              `json:"last_updated"`
	IsSetupComplete  bool                   `json:"is_setup_complete"`
	UnlockedFeatures []string               `json:"unlocked_features"`
}

// WorkflowStep 工作流步骤定义
type WorkflowStep struct {
	ID           int      `json:"id"`
	Name         string   `json:"name"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Requirements []string `json:"requirements"`
	APIEndpoints []string `json:"api_endpoints"`
	IsRequired   bool     `json:"is_required"`
	EstimateTime string   `json:"estimate_time"`
}

// WorkflowSteps 定义所有工作流步骤 - 优化版本
var WorkflowSteps = []WorkflowStep{
	{
		ID:           1,
		Name:         "system_init",
		Title:        "系统初始化",
		Description:  "配置基础系统设置，创建管理员账户，初始化数据存储。这是使用邮件系统的第一步，确保系统基础功能正常。",
		Requirements: []string{"服务器基础环境", "网络连接", "管理员权限"},
		APIEndpoints: []string{"/api/v1/system/*", "/api/v1/auth/login"},
		IsRequired:   true,
		EstimateTime: "2-3分钟",
	},
	{
		ID:           2,
		Name:         "domain_config",
		Title:        "域名配置",
		Description:  "添加您的邮件域名。添加域名后即可开始配置邮件用户和SSL证书，无需等待DNS验证完成。",
		Requirements: []string{"拥有域名管理权限", "系统初始化完成"},
		APIEndpoints: []string{"/api/v1/domains"},
		IsRequired:   true,
		EstimateTime: "3-5分钟",
	},
	{
		ID:           3,
		Name:         "ssl_certificate",
		Title:        "SSL/TLS证书配置",
		Description:  "为您的域名配置SSL证书，启用邮件服务的加密传输。支持自动申请Let's Encrypt证书或上传自有证书。",
		Requirements: []string{"域名已添加", "可选：域名DNS解析正常（自动申请证书时需要）"},
		APIEndpoints: []string{"/api/v1/certificates/*"},
		IsRequired:   true,
		EstimateTime: "3-10分钟",
	},
	{
		ID:           4,
		Name:         "user_management",
		Title:        "邮件用户管理",
		Description:  "创建第一个邮件用户账户。用户创建后即可开始收发邮件，建议先创建管理员邮箱用于测试。",
		Requirements: []string{"域名已添加", "至少创建1个邮件用户"},
		APIEndpoints: []string{"/api/v1/users"},
		IsRequired:   true,
		EstimateTime: "2-3分钟",
	},
	{
		ID:           5,
		Name:         "dns_verification",
		Title:        "DNS记录配置与验证",
		Description:  "配置必要的DNS记录（MX、SPF、DKIM、DMARC）以确保邮件正常收发和提高送达率。此步骤可与其他步骤并行进行。",
		Requirements: []string{"域名已添加", "DNS记录已配置", "DNS传播完成（通常需要1-48小时）"},
		APIEndpoints: []string{"/api/v1/dns/*", "/api/v1/domains/*/dns"},
		IsRequired:   true,
		EstimateTime: "10-30分钟（不含DNS传播时间）",
	},
	{
		ID:           6,
		Name:         "mail_service",
		Title:        "邮件服务启用",
		Description:  "启动SMTP/IMAP服务，进行邮件发送测试。完成此步骤后，您的邮件系统即可正式投入使用。",
		Requirements: []string{"用户已创建", "SSL证书已配置", "建议：DNS记录已验证"},
		APIEndpoints: []string{"/api/v1/mail/*"},
		IsRequired:   true,
		EstimateTime: "5-10分钟",
	},
}

// NewWorkflowService 创建工作流服务
func NewWorkflowService(dataDir string) *WorkflowService {
	stateFile := filepath.Join(dataDir, "workflow_state.json")
	
	ws := &WorkflowService{
		stateFile: stateFile,
		currentState: &WorkflowState{
			CurrentStep:      1,
			CompletedSteps:   []int{},
			StepDetails:      make(map[string]interface{}),
			LastUpdated:      time.Now(),
			IsSetupComplete:  false,
			UnlockedFeatures: []string{},
		},
	}
	
	// 尝试加载现有状态
	ws.loadState()
	
	return ws
}

// loadState 加载工作流状态
func (ws *WorkflowService) loadState() error {
	ws.mutex.Lock()
	defer ws.mutex.Unlock()
	
	if _, err := os.Stat(ws.stateFile); os.IsNotExist(err) {
		return ws.saveState()
	}
	
	data, err := ioutil.ReadFile(ws.stateFile)
	if err != nil {
		return err
	}
	
	return json.Unmarshal(data, ws.currentState)
}

// saveState 保存工作流状态
func (ws *WorkflowService) saveState() error {
	ws.currentState.LastUpdated = time.Now()
	
	data, err := json.MarshalIndent(ws.currentState, "", "  ")
	if err != nil {
		return err
	}
	
	// 确保目录存在
	dir := filepath.Dir(ws.stateFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	
	return ioutil.WriteFile(ws.stateFile, data, 0644)
}

// GetCurrentState 获取当前状态
func (ws *WorkflowService) GetCurrentState() *WorkflowState {
	ws.mutex.RLock()
	defer ws.mutex.RUnlock()
	
	// 返回状态副本
	state := *ws.currentState
	return &state
}

// GetWorkflowSteps 获取所有工作流步骤
func (ws *WorkflowService) GetWorkflowSteps() []WorkflowStep {
	return WorkflowSteps
}

// GetCurrentStep 获取当前步骤信息
func (ws *WorkflowService) GetCurrentStep() *WorkflowStep {
	ws.mutex.RLock()
	currentStepID := ws.currentState.CurrentStep
	ws.mutex.RUnlock()
	
	for _, step := range WorkflowSteps {
		if step.ID == currentStepID {
			return &step
		}
	}
	
	return nil
}

// CompleteStep 完成指定步骤
func (ws *WorkflowService) CompleteStep(stepID int) error {
	ws.mutex.Lock()
	defer ws.mutex.Unlock()
	
	// 验证步骤顺序
	if stepID != ws.currentState.CurrentStep {
		return fmt.Errorf("必须按顺序完成步骤，当前步骤: %d", ws.currentState.CurrentStep)
	}
	
	// 验证步骤要求
	if err := ws.validateStepRequirements(stepID); err != nil {
		return fmt.Errorf("步骤%d要求未满足: %v", stepID, err)
	}
	
	// 标记步骤完成
	ws.currentState.CompletedSteps = append(ws.currentState.CompletedSteps, stepID)
	
	// 解锁该步骤的功能
	ws.unlockStepFeatures(stepID)
	
	// 移动到下一步
	if stepID < len(WorkflowSteps) {
		ws.currentState.CurrentStep = stepID + 1
	} else {
		// 所有步骤完成
		ws.currentState.IsSetupComplete = true
		ws.unlockAllFeatures()
	}
	
	return ws.saveState()
}

// validateStepRequirements 验证步骤要求
func (ws *WorkflowService) validateStepRequirements(stepID int) error {
	switch stepID {
	case 1: // 系统初始化
		return ws.validateSystemInit()
	case 2: // 域名配置
		return ws.validateDomainConfig()
	case 3: // SSL证书配置
		return ws.validateSSLCertificate()
	case 4: // 用户管理
		return ws.validateUserManagement()
	case 5: // DNS验证
		return ws.validateDNSVerification()
	case 6: // 邮件服务
		return ws.validateMailService()
	default:
		return fmt.Errorf("未知步骤: %d", stepID)
	}
}

// validateSystemInit 验证系统初始化
func (ws *WorkflowService) validateSystemInit() error {
	if ws.systemService == nil {
		return fmt.Errorf("系统服务未初始化")
	}
	
	status := ws.systemService.GetInitializationStatus()
	if !status["is_initialized"].(bool) {
		return fmt.Errorf("系统未初始化")
	}
	
	return nil
}

// validateDomainConfig 验证域名配置
func (ws *WorkflowService) validateDomainConfig() error {
	if ws.domainService == nil {
		return fmt.Errorf("域名服务未初始化")
	}
	
	// 检查是否至少有一个域名
	domains, err := ws.domainService.ListDomains()
	if err != nil {
		return fmt.Errorf("获取域名列表失败: %v", err)
	}
	
	if len(domains) == 0 {
		return fmt.Errorf("至少需要添加一个域名")
	}
	
	// 检查MX记录
	for _, domain := range domains {
		if !domain.Active {
			return fmt.Errorf("域名 %s 未激活", domain.Domain)
		}
	}
	
	return nil
}

// validateDNSVerification 验证DNS解析
func (ws *WorkflowService) validateDNSVerification() error {
	if ws.domainService == nil {
		return fmt.Errorf("域名服务未初始化")
	}
	
	domains, err := ws.domainService.ListDomains()
	if err != nil {
		return err
	}
	
	for _, domain := range domains {
		// 检查必要的DNS记录
		dnsRecords, err := ws.domainService.CheckDNSRecords(domain.Domain)
		if err != nil {
			return fmt.Errorf("域名 %s DNS检查失败: %v", domain.Domain, err)
		}
		
		// 验证关键记录是否通过
		requiredRecords := []string{"MX", "SPF", "DKIM"}
		for _, recordType := range requiredRecords {
			found := false
			for _, record := range dnsRecords {
				if record.Type == recordType && record.Status == "valid" {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("域名 %s 缺少有效的 %s 记录", domain.Domain, recordType)
			}
		}
	}
	
	return nil
}

// validateSSLCertificate 验证SSL证书 - 更灵活的验证
func (ws *WorkflowService) validateSSLCertificate() error {
	if ws.certService == nil {
		return fmt.Errorf("证书服务未初始化")
	}

	// 检查是否有域名配置
	if ws.domainService == nil {
		return fmt.Errorf("域名服务未初始化")
	}

	domains, err := ws.domainService.ListDomains()
	if err != nil {
		return fmt.Errorf("获取域名列表失败: %v", err)
	}

	if len(domains) == 0 {
		return fmt.Errorf("请先添加域名")
	}

	// SSL证书可以通过多种方式配置，不强制要求DNS验证完成
	certs, err := ws.certService.ListCertificates()
	if err != nil {
		return fmt.Errorf("获取证书列表失败: %v", err)
	}

	// 检查是否有有效证书（允许各种状态的证书）
	if len(certs) == 0 {
		return fmt.Errorf("请为域名配置SSL证书")
	}

	return nil
}

// validateUserManagement 验证用户管理 - 只需要域名配置完成
func (ws *WorkflowService) validateUserManagement() error {
	if ws.userService == nil {
		return fmt.Errorf("用户服务未初始化")
	}

	// 检查是否有域名配置
	if ws.domainService == nil {
		return fmt.Errorf("域名服务未初始化")
	}

	domains, err := ws.domainService.ListDomains()
	if err != nil {
		return fmt.Errorf("获取域名列表失败: %v", err)
	}

	if len(domains) == 0 {
		return fmt.Errorf("请先添加域名")
	}

	users, err := ws.userService.ListUsers()
	if err != nil {
		return fmt.Errorf("获取用户列表失败: %v", err)
	}

	if len(users) == 0 {
		return fmt.Errorf("至少需要创建一个邮件用户")
	}

	// 检查用户是否激活
	hasActiveUser := false
	for _, user := range users {
		if user.Active {
			hasActiveUser = true
			break
		}
	}

	if !hasActiveUser {
		return fmt.Errorf("至少需要一个激活的邮件用户")
	}

	return nil
}

// validateMailService 验证邮件服务
func (ws *WorkflowService) validateMailService() error {
    // 优先使用系统级 Postfix/Dovecot 服务状态作为判定依据
    if ws.systemService == nil {
        return fmt.Errorf("系统服务未初始化")
    }

    status := ws.systemService.GetInitializationStatus()
    services, ok := status["services"].(map[string]string)
    if !ok {
        return fmt.Errorf("无法获取系统服务状态")
    }

    postfix := services["postfix"]
    dovecot := services["dovecot"]
    opendkim := services["opendkim"]

    isActive := func(s string) bool { return s == "active" || s == "running" }

    if !isActive(postfix) || !isActive(dovecot) || !isActive(opendkim) {
        return fmt.Errorf("邮件相关服务未全部就绪 (postfix=%s, dovecot=%s, opendkim=%s)", postfix, dovecot, opendkim)
    }

    return nil
}

// unlockStepFeatures 解锁步骤相关功能
func (ws *WorkflowService) unlockStepFeatures(stepID int) {
	step := WorkflowSteps[stepID-1]
	for _, endpoint := range step.APIEndpoints {
		if !containsString(ws.currentState.UnlockedFeatures, endpoint) {
			ws.currentState.UnlockedFeatures = append(ws.currentState.UnlockedFeatures, endpoint)
		}
	}
}

// unlockAllFeatures 解锁所有功能
func (ws *WorkflowService) unlockAllFeatures() {
	ws.currentState.UnlockedFeatures = []string{"*"}
}

// IsFeatureUnlocked 检查功能是否已解锁
func (ws *WorkflowService) IsFeatureUnlocked(endpoint string) bool {
	ws.mutex.RLock()
	defer ws.mutex.RUnlock()
	
	// 如果设置完成，解锁所有功能
	if ws.currentState.IsSetupComplete {
		return true
	}
	
	// 检查通配符
	if containsString(ws.currentState.UnlockedFeatures, "*") {
		return true
	}
	
	// 检查具体端点
	for _, unlockedEndpoint := range ws.currentState.UnlockedFeatures {
		if matchEndpoint(endpoint, unlockedEndpoint) {
			return true
		}
	}
	
	return false
}

// ResetWorkflow 重置工作流（仅用于测试）
func (ws *WorkflowService) ResetWorkflow() error {
	ws.mutex.Lock()
	defer ws.mutex.Unlock()
	
	ws.currentState = &WorkflowState{
		CurrentStep:      1,
		CompletedSteps:   []int{},
		StepDetails:      make(map[string]interface{}),
		LastUpdated:      time.Now(),
		IsSetupComplete:  false,
		UnlockedFeatures: []string{},
	}
	
	return ws.saveState()
}

// SetServiceReferences 设置服务引用
func (ws *WorkflowService) SetServiceReferences(
	systemService *SystemService,
	domainService *DomainService,
	userService *UserService,
	certService *CertService,
	mailServer *MailServer,
) {
	ws.mutex.Lock()
	defer ws.mutex.Unlock()
	
	ws.systemService = systemService
	ws.domainService = domainService
	ws.userService = userService
	ws.certService = certService
	ws.mailServer = mailServer
}

// 辅助函数
func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func matchEndpoint(endpoint, pattern string) bool {
	if pattern == "*" {
		return true
	}
	
	// 简单的通配符匹配
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(endpoint, prefix)
	}
	
	return endpoint == pattern
}

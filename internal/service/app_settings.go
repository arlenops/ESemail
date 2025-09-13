package service

import (
    "encoding/json"
    "os"
    "path/filepath"
    "sync"
)

// AppSettings 可通过API管理的运行时配置
type AppSettings struct {
    Mail struct {
        Domain     string `json:"domain"`
        AdminEmail string `json:"admin_email"`
    } `json:"mail"`
    Cert struct {
        Email    string `json:"email"`
        Server   string `json:"server"`
        CertPath string `json:"cert_path"`
    } `json:"cert"`
}

// AppSettingsService 负责加载/保存设置
type AppSettingsService struct {
    filePath string
    mu       sync.RWMutex
    data     *AppSettings
}

func NewAppSettingsService(dataDir string) *AppSettingsService {
    path := filepath.Join(dataDir, "config", "app.json")
    return &AppSettingsService{filePath: path}
}

func (s *AppSettingsService) Load() (*AppSettings, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    // 默认值
    s.data = &AppSettings{}

    if _, err := os.Stat(s.filePath); os.IsNotExist(err) {
        // 创建目录
        if err := os.MkdirAll(filepath.Dir(s.filePath), 0755); err != nil {
            return s.data, nil
        }
        // 初次写入空默认
        _ = s.saveLocked()
        return s.data, nil
    }

    b, err := os.ReadFile(s.filePath)
    if err != nil {
        return s.data, nil
    }
    _ = json.Unmarshal(b, s.data)
    return s.data, nil
}

func (s *AppSettingsService) saveLocked() error {
    b, _ := json.MarshalIndent(s.data, "", "  ")
    return os.WriteFile(s.filePath, b, 0644)
}

func (s *AppSettingsService) Save(newData *AppSettings) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.data = newData
    return s.saveLocked()
}

func (s *AppSettingsService) Get() *AppSettings {
    s.mu.RLock()
    defer s.mu.RUnlock()
    // 返回拷贝
    out := *s.data
    return &out
}

// Update 合并更新（仅非空字段覆盖）
func (s *AppSettingsService) Update(patch *AppSettings) (*AppSettings, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.data == nil {
        s.data = &AppSettings{}
    }
    if patch.Mail.Domain != "" {
        s.data.Mail.Domain = patch.Mail.Domain
    }
    if patch.Mail.AdminEmail != "" {
        s.data.Mail.AdminEmail = patch.Mail.AdminEmail
    }
    if patch.Cert.Email != "" {
        s.data.Cert.Email = patch.Cert.Email
    }
    if patch.Cert.Server != "" {
        s.data.Cert.Server = patch.Cert.Server
    }
    if patch.Cert.CertPath != "" {
        s.data.Cert.CertPath = patch.Cert.CertPath
    }
    if err := s.saveLocked(); err != nil {
        return nil, err
    }
    out := *s.data
    return &out, nil
}


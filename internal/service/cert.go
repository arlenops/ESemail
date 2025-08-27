package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type CertService struct{}

type Certificate struct {
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Issuer    string    `json:"issuer"`
	AutoRenew bool      `json:"auto_renew"`
}

type IssueCertRequest struct {
	Domain      string `json:"domain" binding:"required"`
	Type        string `json:"type"`
	DNSProvider string `json:"dns_provider"`
	APIKey      string `json:"api_key"`
	APISecret   string `json:"api_secret"`
}

func NewCertService() *CertService {
	return &CertService{}
}

func (s *CertService) ListCertificates() ([]Certificate, error) {
	var certificates []Certificate

	acmeHome := "/root/.acme.sh"
	if _, err := os.Stat(acmeHome); os.IsNotExist(err) {
		return certificates, nil
	}

	entries, err := os.ReadDir(acmeHome)
	if err != nil {
		return nil, fmt.Errorf("读取证书目录失败: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			domain := entry.Name()
			cert := s.getCertificateInfo(domain)
			if cert != nil {
				certificates = append(certificates, *cert)
			}
		}
	}

	return certificates, nil
}

func (s *CertService) IssueCertificate(req IssueCertRequest) error {
	if err := s.setupDNSProvider(req.DNSProvider, req.APIKey, req.APISecret); err != nil {
		return fmt.Errorf("配置DNS提供商失败: %v", err)
	}

	var cmd *exec.Cmd
	if req.Type == "wildcard" {
		cmd = exec.Command("/root/.acme.sh/acme.sh", "--issue", "--dns", "dns_"+req.DNSProvider,
			"-d", req.Domain, "-d", "*."+req.Domain)
	} else {
		cmd = exec.Command("/root/.acme.sh/acme.sh", "--issue", "--dns", "dns_"+req.DNSProvider,
			"-d", req.Domain)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("证书签发失败: %v\n输出: %s", err, string(output))
	}

	if err := s.installCertificate(req.Domain); err != nil {
		return fmt.Errorf("证书安装失败: %v", err)
	}

	return nil
}

func (s *CertService) RenewCertificates() error {
	cmd := exec.Command("/root/.acme.sh/acme.sh", "--cron")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("证书续签失败: %v\n输出: %s", err, string(output))
	}

	return nil
}

func (s *CertService) getCertificateInfo(domain string) *Certificate {
	certPath := fmt.Sprintf("/etc/ssl/mail/%s/fullchain.pem", domain)

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil
	}

	cert := &Certificate{
		Domain:    domain,
		Type:      "single",
		Status:    "valid",
		AutoRenew: true,
		Issuer:    "Let's Encrypt",
	}

	if strings.Contains(domain, "*") {
		cert.Type = "wildcard"
	}

	cmd := exec.Command("openssl", "x509", "-in", certPath, "-text", "-noout")
	output, err := cmd.Output()
	if err == nil {
		s.parseCertificateOutput(cert, string(output))
	}

	return cert
}

func (s *CertService) parseCertificateOutput(cert *Certificate, output string) {
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "Not Before:") {
			dateStr := strings.TrimPrefix(line, "Not Before:")
			dateStr = strings.TrimSpace(dateStr)
			if t, err := time.Parse("Jan 2 15:04:05 2006 MST", dateStr); err == nil {
				cert.IssuedAt = t
			}
		}

		if strings.Contains(line, "Not After:") {
			dateStr := strings.TrimPrefix(line, "Not After:")
			dateStr = strings.TrimSpace(dateStr)
			if t, err := time.Parse("Jan 2 15:04:05 2006 MST", dateStr); err == nil {
				cert.ExpiresAt = t
				if t.Before(time.Now()) {
					cert.Status = "expired"
				} else if t.Before(time.Now().AddDate(0, 0, 30)) {
					cert.Status = "expiring"
				}
			}
		}
	}
}

func (s *CertService) setupDNSProvider(provider, apiKey, apiSecret string) error {
	switch provider {
	case "cf":
		os.Setenv("CF_Key", apiKey)
		os.Setenv("CF_Email", apiSecret)
	case "ali":
		os.Setenv("Ali_Key", apiKey)
		os.Setenv("Ali_Secret", apiSecret)
	case "dp":
		os.Setenv("DP_Id", apiKey)
		os.Setenv("DP_Key", apiSecret)
	default:
		return fmt.Errorf("不支持的DNS提供商: %s", provider)
	}

	return nil
}

func (s *CertService) installCertificate(domain string) error {
	certDir := fmt.Sprintf("/etc/ssl/mail/%s", domain)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %v", err)
	}

	cmd := exec.Command("/root/.acme.sh/acme.sh", "--install-cert", "-d", domain,
		"--key-file", filepath.Join(certDir, "privkey.pem"),
		"--fullchain-file", filepath.Join(certDir, "fullchain.pem"),
		"--reloadcmd", "systemctl reload postfix dovecot")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("安装证书失败: %v\n输出: %s", err, string(output))
	}

	return nil
}

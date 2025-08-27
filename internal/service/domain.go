package service

import (
	"fmt"
	"os/exec"
	"strings"
)

type DomainService struct{}

type Domain struct {
	Name       string            `json:"name"`
	Active     bool              `json:"active"`
	DNSRecords map[string]string `json:"dns_records"`
	DKIMKey    string            `json:"dkim_key"`
	Status     string            `json:"status"`
}

type DNSRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Status   string `json:"status"`
	Required bool   `json:"required"`
}

func NewDomainService() *DomainService {
	return &DomainService{}
}

func (s *DomainService) ListDomains() ([]Domain, error) {
	domains := []Domain{
		{
			Name:   "example.com",
			Active: true,
			Status: "active",
			DNSRecords: map[string]string{
				"MX":    "10 mail.example.com",
				"SPF":   "v=spf1 mx ~all",
				"DMARC": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
			},
		},
	}
	return domains, nil
}

func (s *DomainService) AddDomain(domain string) error {
	return nil
}

func (s *DomainService) DeleteDomain(domain string) error {
	return nil
}

func (s *DomainService) GetDNSRecords(domain string) ([]DNSRecord, error) {
	records := []DNSRecord{
		{Type: "MX", Name: domain, Value: fmt.Sprintf("10 mail.%s", domain), Required: true, Status: s.checkDNSRecord("MX", domain)},
		{Type: "TXT", Name: domain, Value: "v=spf1 mx ~all", Required: true, Status: s.checkDNSRecord("TXT", domain)},
		{Type: "TXT", Name: fmt.Sprintf("_dmarc.%s", domain), Value: fmt.Sprintf("v=DMARC1; p=none; rua=mailto:dmarc@%s", domain), Required: true, Status: s.checkDNSRecord("TXT", fmt.Sprintf("_dmarc.%s", domain))},
		{Type: "TXT", Name: fmt.Sprintf("default._domainkey.%s", domain), Value: s.getDKIMRecord(domain), Required: true, Status: s.checkDNSRecord("TXT", fmt.Sprintf("default._domainkey.%s", domain))},
	}
	return records, nil
}

func (s *DomainService) checkDNSRecord(recordType, domain string) string {
	var cmd *exec.Cmd
	switch recordType {
	case "MX":
		cmd = exec.Command("dig", "+short", "MX", domain)
	case "TXT":
		cmd = exec.Command("dig", "+short", "TXT", domain)
	default:
		return "unknown"
	}

	output, err := cmd.Output()
	if err != nil {
		return "error"
	}

	if len(strings.TrimSpace(string(output))) > 0 {
		return "found"
	}
	return "missing"
}

func (s *DomainService) getDKIMRecord(domain string) string {
	return "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
}

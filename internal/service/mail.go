package service

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type MailService struct{}

type MailRecord struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	From      string            `json:"from"`
	To        []string          `json:"to"`
	Subject   string            `json:"subject"`
	Status    string            `json:"status"`
	Direction string            `json:"direction"`
	Size      int64             `json:"size"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      string            `json:"body,omitempty"`
}

type MailHistoryQuery struct {
	StartDate time.Time `json:"start_date"`
	EndDate   time.Time `json:"end_date"`
	Direction string    `json:"direction"`
	User      string    `json:"user"`
	Status    string    `json:"status"`
	Page      int       `json:"page"`
	PageSize  int       `json:"page_size"`
}

type MailHistoryResponse struct {
	Records    []MailRecord `json:"records"`
	Total      int          `json:"total"`
	Page       int          `json:"page"`
	PageSize   int          `json:"page_size"`
	TotalPages int          `json:"total_pages"`
}

func NewMailService() *MailService {
	return &MailService{}
}

func (s *MailService) GetMailHistory(query MailHistoryQuery) (*MailHistoryResponse, error) {
	records, err := s.parseMailLogs(query)
	if err != nil {
		return nil, err
	}

	total := len(records)
	totalPages := (total + query.PageSize - 1) / query.PageSize

	start := (query.Page - 1) * query.PageSize
	end := start + query.PageSize
	if end > total {
		end = total
	}

	var pagedRecords []MailRecord
	if start < total {
		pagedRecords = records[start:end]
	}

	return &MailHistoryResponse{
		Records:    pagedRecords,
		Total:      total,
		Page:       query.Page,
		PageSize:   query.PageSize,
		TotalPages: totalPages,
	}, nil
}

func (s *MailService) GetMailDetail(id string) (*MailRecord, error) {
	record, err := s.findMailRecord(id)
	if err != nil {
		return nil, err
	}

	record.Headers, record.Body, err = s.parseEMLFile(record)
	if err != nil {
		return nil, fmt.Errorf("解析邮件文件失败: %v", err)
	}

	return record, nil
}

func (s *MailService) DownloadEML(id string) ([]byte, string, error) {
	record, err := s.findMailRecord(id)
	if err != nil {
		return nil, "", err
	}

	emlPath := s.getEMLPath(record)
	data, err := os.ReadFile(emlPath)
	if err != nil {
		return nil, "", fmt.Errorf("读取邮件文件失败: %v", err)
	}

	filename := fmt.Sprintf("mail_%s_%s.eml", record.ID, record.Timestamp.Format("20060102_150405"))
	return data, filename, nil
}

func (s *MailService) parseMailLogs(query MailHistoryQuery) ([]MailRecord, error) {
	var records []MailRecord

	logFiles := []string{"/var/log/mail.log", "/var/log/mail.info"}

	for _, logFile := range logFiles {
		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			continue
		}

		fileRecords, err := s.parseLogFile(logFile, query)
		if err != nil {
			continue
		}
		records = append(records, fileRecords...)
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.After(records[j].Timestamp)
	})

	return records, nil
}

func (s *MailService) parseLogFile(logFile string, query MailHistoryQuery) ([]MailRecord, error) {
	file, err := os.Open(logFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var records []MailRecord
	scanner := bufio.NewScanner(file)

	postfixRegex := regexp.MustCompile(`(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).+postfix/(\w+)\[(\d+)\]: (.+)`)
	queueRegex := regexp.MustCompile(`([A-F0-9]+): (.+)`)

	for scanner.Scan() {
		line := scanner.Text()

		matches := postfixRegex.FindStringSubmatch(line)
		if len(matches) < 5 {
			continue
		}

		timestamp, _ := time.Parse("Jan 2 15:04:05", matches[1])
		timestamp = timestamp.AddDate(time.Now().Year(), 0, 0)

		if timestamp.Before(query.StartDate) || timestamp.After(query.EndDate) {
			continue
		}

		component := matches[2]
		message := matches[4]

		queueMatches := queueRegex.FindStringSubmatch(message)
		if len(queueMatches) < 3 {
			continue
		}

		queueID := queueMatches[1]
		details := queueMatches[2]

		record := MailRecord{
			ID:        queueID,
			Timestamp: timestamp,
			Status:    s.extractStatus(component, details),
			Direction: s.extractDirection(component, details),
		}

		if from := s.extractFrom(details); from != "" {
			record.From = from
		}
		if to := s.extractTo(details); len(to) > 0 {
			record.To = to
		}
		if subject := s.extractSubject(details); subject != "" {
			record.Subject = subject
		}

		if s.matchesQuery(record, query) {
			records = append(records, record)
		}
	}

	return records, nil
}

func (s *MailService) extractStatus(component, details string) string {
	if strings.Contains(details, "sent") {
		return "sent"
	}
	if strings.Contains(details, "bounced") {
		return "bounced"
	}
	if strings.Contains(details, "deferred") {
		return "deferred"
	}
	if strings.Contains(details, "rejected") {
		return "rejected"
	}
	return "queued"
}

func (s *MailService) extractDirection(component, details string) string {
	if component == "smtp" || strings.Contains(details, "relay=") {
		return "outbound"
	}
	return "inbound"
}

func (s *MailService) extractFrom(details string) string {
	fromRegex := regexp.MustCompile(`from=<([^>]*)>`)
	matches := fromRegex.FindStringSubmatch(details)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (s *MailService) extractTo(details string) []string {
	toRegex := regexp.MustCompile(`to=<([^>]*)>`)
	matches := toRegex.FindAllStringSubmatch(details, -1)
	var recipients []string
	for _, match := range matches {
		if len(match) > 1 {
			recipients = append(recipients, match[1])
		}
	}
	return recipients
}

func (s *MailService) extractSubject(details string) string {
	return ""
}

func (s *MailService) matchesQuery(record MailRecord, query MailHistoryQuery) bool {
	if query.Direction != "" && record.Direction != query.Direction {
		return false
	}
	if query.User != "" && record.From != query.User && !s.containsUser(record.To, query.User) {
		return false
	}
	if query.Status != "" && record.Status != query.Status {
		return false
	}
	return true
}

func (s *MailService) containsUser(recipients []string, user string) bool {
	for _, recipient := range recipients {
		if recipient == user {
			return true
		}
	}
	return false
}

func (s *MailService) findMailRecord(id string) (*MailRecord, error) {
	query := MailHistoryQuery{
		StartDate: time.Now().AddDate(0, -1, 0),
		EndDate:   time.Now(),
		Page:      1,
		PageSize:  1000,
	}

	records, err := s.parseMailLogs(query)
	if err != nil {
		return nil, err
	}

	for _, record := range records {
		if record.ID == id {
			return &record, nil
		}
	}

	return nil, fmt.Errorf("邮件记录未找到")
}

func (s *MailService) getEMLPath(record *MailRecord) string {
	return filepath.Join("/var/spool/postfix", "defer", record.ID)
}

func (s *MailService) parseEMLFile(record *MailRecord) (map[string]string, string, error) {
	emlPath := s.getEMLPath(record)

	data, err := os.ReadFile(emlPath)
	if err != nil {
		return nil, "", err
	}

	content := string(data)
	headers := make(map[string]string)

	lines := strings.Split(content, "\n")
	headerEnd := 0

	for i, line := range lines {
		if line == "" {
			headerEnd = i
			break
		}

		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	body := strings.Join(lines[headerEnd+1:], "\n")

	if subject, exists := headers["Subject"]; exists {
		record.Subject = subject
	}

	return headers, body, nil
}

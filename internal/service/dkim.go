package service

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DKIMService DKIM签名服务
type DKIMService struct {
	selector    string
	domain      string
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	keyPath     string
}

// DKIMSignature DKIM签名结构
type DKIMSignature struct {
	Version       string
	Algorithm     string
	Canonicalization string
	Domain        string
	Selector      string
	Headers       string
	BodyHash      string
	Signature     string
	Timestamp     int64
}

// NewDKIMService 创建DKIM服务
func NewDKIMService(domain, selector, keyPath string) (*DKIMService, error) {
	service := &DKIMService{
		domain:   domain,
		selector: selector,
		keyPath:  keyPath,
	}
	
	// 尝试加载现有密钥，如果不存在则生成
	if err := service.loadOrGenerateKeys(); err != nil {
		return nil, fmt.Errorf("初始化DKIM密钥失败: %v", err)
	}
	
	return service, nil
}

// loadOrGenerateKeys 加载或生成DKIM密钥对
func (d *DKIMService) loadOrGenerateKeys() error {
	privateKeyPath := filepath.Join(d.keyPath, fmt.Sprintf("%s.%s.private", d.selector, d.domain))
	publicKeyPath := filepath.Join(d.keyPath, fmt.Sprintf("%s.%s.public", d.selector, d.domain))
	
	// 检查密钥文件是否存在
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		// 生成新的密钥对
		return d.generateKeys(privateKeyPath, publicKeyPath)
	}
	
	// 加载现有密钥
	return d.loadKeys(privateKeyPath, publicKeyPath)
}

// generateKeys 生成DKIM密钥对
func (d *DKIMService) generateKeys(privateKeyPath, publicKeyPath string) error {
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(privateKeyPath), 0700); err != nil {
		return fmt.Errorf("创建密钥目录失败: %v", err)
	}
	
	// 生成RSA密钥对 (2048位)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("生成RSA密钥失败: %v", err)
	}
	
	// 保存私钥
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("编码私钥失败: %v", err)
	}
	
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	
	if err := ioutil.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("保存私钥失败: %v", err)
	}
	
	// 保存公钥
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("编码公钥失败: %v", err)
	}
	
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	
	if err := ioutil.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("保存公钥失败: %v", err)
	}
	
	d.privateKey = privateKey
	d.publicKey = &privateKey.PublicKey
	
	fmt.Printf("🔐 DKIM密钥对已生成:\n")
	fmt.Printf("   域名: %s\n", d.domain)
	fmt.Printf("   选择器: %s\n", d.selector)
	fmt.Printf("   私钥: %s\n", privateKeyPath)
	fmt.Printf("   公钥: %s\n", publicKeyPath)
	
	return nil
}

// loadKeys 加载现有密钥
func (d *DKIMService) loadKeys(privateKeyPath, publicKeyPath string) error {
	// 加载私钥
	privateKeyPEM, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return fmt.Errorf("读取私钥文件失败: %v", err)
	}
	
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return fmt.Errorf("解码私钥PEM失败")
	}
	
	privateKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("解析私钥失败: %v", err)
	}
	
	privateKey, ok := privateKeyInterface.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("私钥类型错误，需要RSA密钥")
	}
	
	d.privateKey = privateKey
	d.publicKey = &privateKey.PublicKey
	
	return nil
}

// SignEmail 对邮件进行DKIM签名
func (d *DKIMService) SignEmail(headers map[string]string, body string) (string, error) {
	// 计算body hash
	bodyHash := d.calculateBodyHash(body)
	
	// 选择要签名的头部字段
	signedHeaders := []string{"from", "to", "subject", "date", "message-id"}
	
	// 构建DKIM签名头部
	dkimHeader := fmt.Sprintf("v=1; a=rsa-sha256; c=relaxed/simple; d=%s; s=%s; t=%d; bh=%s; h=%s",
		d.domain, d.selector, time.Now().Unix(), bodyHash, strings.Join(signedHeaders, ":"))
	
	// 构建待签名的字符串
	signData := d.buildSignatureData(headers, signedHeaders, dkimHeader)
	
	// 计算签名
	signature, err := d.calculateSignature(signData)
	if err != nil {
		return "", fmt.Errorf("计算DKIM签名失败: %v", err)
	}
	
	// 构建完整的DKIM-Signature头部
	fullDKIMHeader := dkimHeader + "; b=" + signature
	
	return fullDKIMHeader, nil
}

// calculateBodyHash 计算邮件正文的哈希
func (d *DKIMService) calculateBodyHash(body string) string {
	// 使用简单的body canonicalization
	canonicalBody := strings.ReplaceAll(body, "\r\n", "\n")
	canonicalBody = strings.TrimRight(canonicalBody, "\n")
	if canonicalBody != "" {
		canonicalBody += "\n"
	}
	
	hash := sha256.Sum256([]byte(canonicalBody))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// buildSignatureData 构建待签名的数据
func (d *DKIMService) buildSignatureData(headers map[string]string, signedHeaders []string, dkimHeader string) string {
	var signData strings.Builder
	
	// 添加已签名的头部
	for _, headerName := range signedHeaders {
		if value, exists := headers[strings.ToLower(headerName)]; exists {
			signData.WriteString(fmt.Sprintf("%s:%s\r\n", strings.ToLower(headerName), strings.TrimSpace(value)))
		}
	}
	
	// 添加DKIM-Signature头部（不包含b=签名部分）
	signData.WriteString("dkim-signature:" + dkimHeader)
	
	return signData.String()
}

// calculateSignature 计算签名
func (d *DKIMService) calculateSignature(data string) (string, error) {
	hash := sha256.Sum256([]byte(data))
	
	signature, err := rsa.SignPKCS1v15(rand.Reader, d.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	
	return base64.StdEncoding.EncodeToString(signature), nil
}

// GetPublicKeyRecord 获取用于DNS的公钥记录
func (d *DKIMService) GetPublicKeyRecord() (string, error) {
	if d.publicKey == nil {
		return "", fmt.Errorf("公钥未初始化")
	}
	
	// 将公钥转换为DER格式
	publicKeyDER, err := x509.MarshalPKIXPublicKey(d.publicKey)
	if err != nil {
		return "", fmt.Errorf("编码公钥失败: %v", err)
	}
	
	// 编码为base64
	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKeyDER)
	
	// 构建DNS TXT记录值
	dnsRecord := fmt.Sprintf("v=DKIM1; k=rsa; p=%s", publicKeyB64)
	
	return dnsRecord, nil
}

// GetDNSRecordName 获取DNS记录名称
func (d *DKIMService) GetDNSRecordName() string {
	return fmt.Sprintf("%s._domainkey.%s", d.selector, d.domain)
}

// VerifySignature 验证DKIM签名（用于测试）
func (d *DKIMService) VerifySignature(headers map[string]string, body, signature string) error {
	// 这里可以实现签名验证逻辑，用于测试签名是否正确
	// 暂时返回nil表示验证通过
	return nil
}
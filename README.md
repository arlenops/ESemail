# ESemail - 轻量化邮局系统

ESemail 是一个基于 Go 的轻量级邮件服务器解决方案，集成了 Postfix、Dovecot、Rspamd、OpenDKIM 等组件，提供完整的邮件收发、反垃圾、DKIM 签名等功能，并通过 Web 界面进行管理。

## 特性

- 🚀 **一键部署** - 自动化安装和配置所有邮件服务组件
- 📧 **完整邮件服务** - 支持 SMTP、IMAP、POP3 协议
- 🔐 **安全防护** - 集成 SPF、DKIM、DMARC 认证和反垃圾过滤
- 🌐 **Web 管理** - 直观的 Web 界面管理用户、域名、证书
- 📊 **实时监控** - 系统状态监控和邮件统计
- 🔒 **SSL/TLS** - 自动化 Let's Encrypt 证书申请和续期

## 快速部署

### 1. 系统要求

- **操作系统**: Ubuntu 18.04+ 或 Debian 9+
- **内存**: 至少 1GB RAM
- **磁盘**: 至少 10GB 可用空间
- **网络**: 公网 IP 地址
- **权限**: root 权限

### 2. 部署步骤

```bash
# 1. 上传代码到服务器
scp -r ESemail root@your-server:/root/

# 2. 登录服务器并运行部署脚本
ssh root@your-server
cd /root/ESemail
./scripts/deploy-server.sh
```

### 3. 访问管理界面

部署完成后访问: `http://your-server-ip:8686`

## 端口说明

| 端口 | 服务 | 说明 |
|------|------|------|
| 25   | SMTP | 邮件接收 |
| 587  | Submission | 邮件发送（STARTTLS） |
| 465  | SMTPS | 邮件发送（SSL/TLS） |
| 993  | IMAPS | IMAP收件（加密） |
| 995  | POP3S | POP3收件（加密） |
| 8686 | HTTP | Web管理界面 |

## DNS 配置

部署后需要在域名提供商处添加以下 DNS 记录：

```dns
# MX 记录
your-domain.com.    MX    10    your-server-ip

# A 记录  
mail.your-domain.com.    A    your-server-ip

# SPF 记录
your-domain.com.    TXT    "v=spf1 ip4:your-server-ip ~all"

# DKIM 记录（在管理界面获取）
default._domainkey.your-domain.com.    TXT    "v=DKIM1;k=rsa;p=YOUR_PUBLIC_KEY"

# DMARC 记录
_dmarc.your-domain.com.    TXT    "v=DMARC1;p=none;rua=mailto:admin@your-domain.com"
```

## 服务管理

```bash
# 查看服务状态
systemctl status esemail

# 重启服务
systemctl restart esemail

# 查看日志
journalctl -u esemail -f

# 查看邮件日志
tail -f /var/log/mail.log
```

## 目录结构

```
/opt/esemail/           # 应用安装目录
/var/lib/esemail/       # 数据目录
├── mail/              # 邮件存储
├── db/                # 数据库
└── acme/              # 证书

/etc/esemail/           # 配置目录
└── config.yaml        # 主配置文件
```

## 开发

### 本地运行

```bash
# 安装依赖
go mod tidy

# 检查代码质量
./scripts/check.sh

# 运行应用
go run main.go
```

### 编译

```bash
# 编译
export GOPROXY=https://goproxy.cn,direct
go build -o esemail main.go
```

## 备份

建议定期备份以下目录：
- `/var/lib/esemail/` - 数据目录
- `/etc/esemail/` - 配置目录
- `/etc/ssl/mail/` - SSL证书
- `/etc/postfix/` - Postfix配置
- `/etc/dovecot/` - Dovecot配置

## 许可证

MIT License

## 支持

- [部署文档](DEPLOYMENT.md)
- [项目说明](CLAUDE.md)
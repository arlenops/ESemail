# ESemail 云服务器部署指南

## 快速部署

### 1. 上传代码到服务器

```bash
# 将项目代码上传到云服务器
scp -r /path/to/ESemail root@your-server:/root/

# 或者在服务器上
git clone <your-repo> /root/ESemail
```

### 2. 运行部署脚本

```bash
# 登录服务器
ssh root@your-server

# 进入项目目录
cd /root/ESemail

# 运行部署脚本
./scripts/deploy-server.sh
```

### 3. 访问管理界面

部署完成后，在浏览器中访问：
- `http://your-server-ip:8686`

## 系统要求

- **操作系统**: Ubuntu 18.04+ 或 Debian 9+
- **内存**: 至少 1GB RAM
- **磁盘**: 至少 10GB 可用空间
- **权限**: root 权限

## 端口说明

| 端口 | 服务 | 说明 |
|------|------|------|
| 25   | SMTP | 邮件接收 |
| 587  | Submission | 邮件发送（STARTTLS） |
| 465  | SMTPS | 邮件发送（SSL/TLS） |
| 993  | IMAPS | IMAP收件（加密） |
| 995  | POP3S | POP3收件（加密） |
| 8686 | HTTP | Web管理界面 |

## 部署后配置

### 1. 初始化系统
1. 访问 `http://your-server-ip:8686`
2. 按照向导完成初始配置
3. 设置域名、管理员信息等

### 2. 配置DNS记录

在你的域名提供商处添加以下DNS记录：

```
# MX记录
your-domain.com.    MX    10    your-server-ip

# A记录
mail.your-domain.com.    A    your-server-ip

# SPF记录
your-domain.com.    TXT    "v=spf1 ip4:your-server-ip ~all"

# DKIM记录（在管理界面获取）
default._domainkey.your-domain.com.    TXT    "v=DKIM1;k=rsa;p=YOUR_PUBLIC_KEY"

# DMARC记录
_dmarc.your-domain.com.    TXT    "v=DMARC1;p=none;rua=mailto:admin@your-domain.com"
```

### 3. SSL证书

在管理界面中配置acme.sh自动申请Let's Encrypt证书。

## 服务管理

### 查看服务状态
```bash
systemctl status esemail
systemctl status postfix
systemctl status dovecot
systemctl status rspamd
```

### 查看日志
```bash
# ESemail日志
journalctl -u esemail -f

# 邮件日志
tail -f /var/log/mail.log

# Rspamd日志
tail -f /var/log/rspamd/rspamd.log
```

### 重启服务
```bash
systemctl restart esemail
systemctl restart postfix
systemctl restart dovecot
```

## 故障排除

### 常见问题

1. **Web界面无法访问**
   ```bash
   # 检查服务状态
   systemctl status esemail
   
   # 检查端口
   netstat -tlnp | grep :8686
   
   # 检查防火墙
   ufw status
   ```

2. **邮件无法发送**
   ```bash
   # 检查Postfix
   systemctl status postfix
   postqueue -p
   
   # 检查日志
   tail -f /var/log/mail.log
   ```

3. **邮件无法接收**
   ```bash
   # 检查MX记录
   dig MX your-domain.com
   
   # 检查端口25
   telnet your-server-ip 25
   ```

### 重新部署

如果需要重新部署：

```bash
# 停止服务
systemctl stop esemail

# 重新运行部署脚本
./scripts/deploy-server.sh
```

## 安全建议

1. **更改默认密码**
2. **配置SSL证书**
3. **定期更新系统**
4. **设置合适的防火墙规则**
5. **配置反垃圾邮件策略**
6. **监控邮件队列和日志**

## 目录结构

```
/opt/esemail/           # 应用安装目录
├── esemail             # 主程序
└── src/               # 源代码

/var/lib/esemail/       # 数据目录
├── mail/              # 邮件存储
├── db/                # 数据库
└── acme/              # 证书

/etc/esemail/           # 配置目录
└── config.yaml        # 主配置文件

/var/log/esemail/       # 日志目录
```

## 备份

建议定期备份以下目录：
- `/var/lib/esemail/` - 数据目录
- `/etc/esemail/` - 配置目录
- `/etc/ssl/mail/` - SSL证书
- `/etc/postfix/` - Postfix配置
- `/etc/dovecot/` - Dovecot配置
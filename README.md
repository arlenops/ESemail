# ESemail 快速部署指南

## 🚀 一键部署（本地）

```bash
# 拉取最新代码并执行部署（无需本地配置文件）
chmod +x deploy.sh
./deploy.sh
```

## 🔧 问题修复

### ✅ 已修复的BUG：
1. **权限问题** - 使用相对路径，避免系统目录权限错误
2. **DKIM配置** - 完善密钥生成流程  
3. **安全验证** - 优化JSON请求检测
4. **403错误** - 修复 `/api/v1/system/init` 接口权限（**新修复**）

## 📝 管理命令

### 查看应用状态：
```bash
# 查看实时日志
tail -f /opt/ESemail/logs/app.log

# 查看进程状态
ps aux | grep esemail

# 检查端口
lsof -i:8686
```

### 停止应用：
```bash
cd /opt/ESemail
./stop.sh
```

### 重启应用：
```bash
cd /opt/ESemail
./stop.sh
./deploy.sh
```

## 🧪 API 测试与配置管理

### 系统状态
```bash
curl http://localhost:8686/api/v1/setup/status
curl http://localhost:8686/api/v1/system/status
```

### 系统初始化（返回 200 表示触发成功）
```bash
curl -X POST http://localhost:8686/api/v1/system/init
```

### 登录获取 Token
```bash
curl -s -X POST http://localhost:8686/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'
```

### 应用配置（前端/API 管理）
- 获取配置：
```bash
curl -H "Authorization: Bearer <TOKEN>" \
  http://localhost:8686/api/v1/config
```

- 更新配置（仅非空字段覆盖）：
```bash
curl -s -X POST http://localhost:8686/api/v1/config \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "mail": {"domain": "yourdomain.com", "admin_email": "admin@yourdomain.com"},
    "cert": {"email": "admin@yourdomain.com", "server": "letsencrypt", "cert_path": "/etc/ssl/mail"}
  }'
```

提示：配置会持久化到 `./data/config/app.json`，重启后仍生效。

## 🌐 访问方式

- 本地访问: http://localhost:8686

## 📁 目录结构（关键）

```
/opt/ESemail/
├── esemail          # 可执行文件
├── deploy.sh        # 部署脚本  
├── stop.sh         # 停止脚本
├── logs/           # 日志目录
│   └── app.log     # 应用日志
├── config/         # 系统生成的服务配置（postfix/dovecot/opendkim 等）
├── data/           # 数据文件（domains/users/workflow/app.json 等）
└── mail/           # 邮件存储
```

## ⚠️ 注意事项

1. 脚本会自动检测并停止占用8686端口的进程
2. 应用以后台方式运行，日志保存在 `logs/app.log`
3. 每次部署都会拉取最新代码，确保使用最新版本
4. 如果部署失败，会显示详细的错误日志

## 🔐 证书签发（DNS-01，本机验证）

1) 设置证书邮箱（前端/API）：
```bash
curl -s -X POST http://localhost:8686/api/v1/certificates/settings \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourdomain.com"}'
```

2) 发起挑战，获取 TXT 记录：
```bash
curl -s -X POST http://localhost:8686/api/v1/domains/mail.yourdomain.com/ssl/request \
  -H "Authorization: Bearer <TOKEN>"
```
响应包含 `dns_name` 与 `dns_value`。

3) 在 DNS 平台添加 TXT 记录：名称 = `dns_name`，值 = `dns_value`。

4) 完成验证并安装证书：
```bash
curl -s -X POST http://localhost:8686/api/v1/certificates/validate-dns/mail.yourdomain.com \
  -H "Authorization: Bearer <TOKEN>"
```
失败时返回 `debug.observed`（本机 dig 解析到的 TXT 值），用于快速排查。

可选调试：
- 挂起挑战列表：`GET /api/v1/certificates/pending`
- 查看某域名挑战：`GET /api/v1/certificates/dns-challenge/:domain`

依赖：请确保本机已安装 `dig`（Ubuntu/Debian: `apt install -y dnsutils`）。

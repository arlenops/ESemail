# ESemail 快速部署指南

## 🚀 一键部署（本地）

```bash
# 准备配置（首次使用）
cp config/config.example.yaml config/config.yaml
# 编辑 config/config.yaml，至少设置 cert.email 为有效邮箱

# 拉取最新代码并执行部署
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

## 🧪 API测试

### 测试系统状态：
```bash
curl http://localhost:8686/api/v1/setup/status
curl http://localhost:8686/api/v1/system/status
```

### 测试系统初始化（现在应该返回200）：
```bash
curl -X POST http://localhost:8686/api/v1/system/init
```

### 配置系统：
```bash
curl -X POST http://localhost:8686/api/v1/setup/configure \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "yourdomain.com",
    "admin_email": "admin@yourdomain.com",
    "hostname": "mail.yourdomain.com", 
    "admin_name": "Admin",
    "admin_pass": "your_password"
  }'
```

## 🌐 访问方式

- 本地访问: http://localhost:8686

## 📁 目录结构

```
/opt/ESemail/
├── esemail          # 可执行文件
├── deploy.sh        # 部署脚本  
├── stop.sh         # 停止脚本
├── logs/           # 日志目录
│   └── app.log     # 应用日志
├── config/         # 配置文件
├── data/           # 数据文件
└── mail/           # 邮件存储
```

## ⚠️ 注意事项

1. 脚本会自动检测并停止占用8686端口的进程
2. 应用以后台方式运行，日志保存在 `logs/app.log`
3. 每次部署都会拉取最新代码，确保使用最新版本
4. 如果部署失败，会显示详细的错误日志

## 🔐 证书邮箱配置

- 证书申请统一从配置项 `cert.email` 注入，不再从 API 参数传入。
- 请在配置文件或环境变量中设置有效邮箱，否则证书签发会被拒绝。

示例（config.yaml）：

```yaml
cert:
  email: "admin@yourdomain.com"
```

进阶（受限网络/本地验证）
- 使用系统解析器进行本地验证（不直连公共DNS）：
  - `export CERT_DNS_MODE=system`
- 跳过本地预校验，直接交给 ACME 验证（谨慎使用）：
  - `export CERT_SKIP_PRECHECK=true`
- 自定义解析器（逗号分隔）：
  - `export DNS_RESOLVERS="223.5.5.5:53,119.29.29.29:53"`

也可通过环境变量指定配置文件路径（deploy.sh 会自动识别 config/config.yaml）：

```bash
export ESEMAIL_CONFIG=$(pwd)/config/config.yaml
./esemail
```

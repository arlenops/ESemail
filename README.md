# ESemail 快速部署指南

## 🚀 一键部署

### 在远程服务器上执行：

```bash
# 1. 连接服务器
ssh root@103.233.255.199

# 2. 下载并运行部署脚本
curl -sSL https://raw.githubusercontent.com/arlenops/ESemail/main/deploy.sh | bash

# 或者手动下载后执行
wget https://raw.githubusercontent.com/arlenops/ESemail/main/deploy.sh
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

- **本地访问**: http://localhost:8686
- **远程访问**: http://103.233.255.199:8686

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
3. 每次部署都会完全重新下载代码，确保使用最新版本
4. 如果部署失败，会显示详细的错误日志
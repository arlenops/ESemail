# ESemail 远程服务器部署指南

## 修复内容
已修复以下致命BUG：
- ✅ 权限问题：改用相对路径避免权限错误
- ✅ DKIM密钥生成：完善配置文件生成
- ✅ 安全验证：优化JSON请求检测规则
- ✅ CSRF保护：调整setup接口保护策略

## 远程服务器部署步骤

### 1. 连接到服务器
```bash
ssh root@103.233.255.199
# 密码: pmzqBRIZ7012
```

### 2. 安装依赖
```bash
# 更新系统
apt update && apt upgrade -y

# 安装Go环境 (如果未安装)
wget https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# 安装Git (如果未安装)
apt install -y git curl
```

### 3. 克隆代码
```bash
# 如果已存在旧版本，先删除
rm -rf /opt/ESemail

# 克隆最新代码
cd /opt
git clone https://github.com/arlenops/ESemail.git
cd ESemail
```

### 4. 编译应用
```bash
# 下载依赖
go mod tidy

# 编译
go build -o esemail
```

### 5. 配置服务器环境
```bash
# 创建系统用户
useradd -r -s /bin/false esemail

# 设置权限
chown -R esemail:esemail /opt/ESemail
chmod +x /opt/ESemail/esemail
```

### 6. 创建systemd服务
```bash
cat > /etc/systemd/system/esemail.service << EOF
[Unit]
Description=ESemail Mail Server Control Panel
After=network.target

[Service]
Type=simple
User=esemail
Group=esemail
WorkingDirectory=/opt/ESemail
ExecStart=/opt/ESemail/esemail
Restart=always
RestartSec=5
Environment=EXAMPLES_PORT=8686

[Install]
WantedBy=multi-user.target
EOF
```

### 7. 启动服务
```bash
# 重载systemd配置
systemctl daemon-reload

# 启用并启动服务
systemctl enable esemail
systemctl start esemail

# 查看状态
systemctl status esemail
```

### 8. 配置防火墙
```bash
# 开放必要端口
ufw allow 8686/tcp  # 控制面板
ufw allow 25/tcp    # SMTP
ufw allow 465/tcp   # SMTPS
ufw allow 587/tcp   # Submission
ufw allow 993/tcp   # IMAPS
ufw allow 995/tcp   # POP3S
```

### 9. 验证部署
```bash
# 检查服务状态
curl http://localhost:8686/api/v1/setup/status

# 应该返回类似：
# {"is_setup":false,"step":1,"domain":"","admin_email":"","hostname":"","required_fields":["domain","admin_email","hostname","admin_name","admin_pass"]}
```

### 10. 初始化系统
```bash
# 通过API初始化系统
curl -X POST http://localhost:8686/api/v1/setup/configure \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "yourdomain.com",
    "admin_email": "admin@yourdomain.com", 
    "hostname": "mail.yourdomain.com",
    "admin_name": "Admin",
    "admin_pass": "your_secure_password"
  }'
```

## 访问控制面板
- 地址: `http://103.233.255.199:8686`
- 首次访问会显示系统配置向导
- 配置完成后可通过管理员账户登录

## 故障排查
```bash
# 查看日志
journalctl -u esemail -f

# 查看进程
ps aux | grep esemail

# 重启服务
systemctl restart esemail
```

## 注意事项
1. 确保服务器防火墙已正确配置
2. 如需HTTPS，请配置反向代理（nginx/apache）
3. 定期备份配置文件和邮件数据
4. 修改默认管理员密码

## 目录结构
```
/opt/ESemail/
├── config/          # 配置文件
├── data/            # 数据文件
├── mail/            # 邮件存储
├── logs/            # 日志文件
└── esemail          # 可执行文件
```
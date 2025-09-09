# 远程服务器紧急修复指令

## 当前问题
远程服务器仍在使用旧版本代码，尝试写入 `/etc/esemail/setup.conf` 导致权限错误。

## 立即执行以下命令

### 1. 连接到服务器并停止服务
```bash
ssh root@103.233.255.199
systemctl stop esemail
pkill -f esemail
```

### 2. 更新代码到最新版本
```bash
cd /opt/ESemail
git fetch origin
git reset --hard origin/main
git pull origin main
```

### 3. 重新编译
```bash
go mod tidy
go build -o esemail
```

### 4. 验证修复内容
```bash
# 检查setup.go文件是否已更新（应该看到 ./config/setup.conf）
grep -n "setup.conf" internal/service/setup.go

# 应该显示类似：
# 137:        return os.WriteFile("./config/setup.conf", []byte(configContent), 0644)
```

### 5. 清理旧配置文件
```bash
# 删除可能存在的旧配置
rm -rf /etc/esemail
rm -rf config/.setup_complete config/setup.conf
```

### 6. 重启服务
```bash
systemctl start esemail
systemctl status esemail
```

### 7. 测试修复结果
```bash
# 检查服务状态
curl http://localhost:8686/api/v1/setup/status

# 测试系统配置
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

## 如果问题仍然存在
```bash
# 检查当前分支和最新提交
cd /opt/ESemail
git branch -v
git log --oneline -5

# 最新提交应该是：
# 697f822 添加远程服务器部署指南
# dc92d6e 修复系统初始化致命BUG
```

## 验证修复成功的标志
1. `curl http://localhost:8686/api/v1/setup/status` 返回JSON而不是500错误
2. 系统配置API返回成功消息而非权限错误
3. 在项目目录下看到 `config/` 目录而不是尝试写入 `/etc/` 目录

## 如果Git更新失败
```bash
# 完全重新克隆
cd /opt
rm -rf ESemail
git clone https://github.com/arlenops/ESemail.git
cd ESemail
go mod tidy
go build -o esemail
chown -R esemail:esemail /opt/ESemail
systemctl restart esemail
```
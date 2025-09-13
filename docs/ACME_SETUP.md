# ACME.SH 安装和配置指南

## 🔧 快速安装

### 方式一：官方安装脚本（推荐）
```bash
# 安装acme.sh到 /root/.acme.sh/
curl https://get.acme.sh | sh

# 或使用wget
wget -O - https://get.acme.sh | sh

# 安装完成后重新加载bash配置
source ~/.bashrc
```

### 方式二：从GitHub安装
```bash
# 克隆仓库
git clone https://github.com/acmesh-official/acme.sh.git
cd ./acme.sh

# 安装
./acme.sh --install --home /root/.acme.sh --config-home /root/.acme.sh/data --cert-home /root/.acme.sh/certs

# 添加到PATH
echo 'export PATH="/root/.acme.sh:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

## 📋 验证安装

```bash
# 检查acme.sh版本
/root/.acme.sh/acme.sh --version

# 或者如果已添加到PATH
acme.sh --version
```

## 🎯 ESemail集成配置

### 1. 基础配置文件设置
在 `config/config.yaml` 中配置：

```yaml
cert:
  acme_path: "/root/.acme.sh"
  cert_path: "/etc/ssl/mail"
  webroot_path: "/var/www/html"
  email: "admin@yourdomain.com"  # 重要：请使用真实有效的邮箱地址
  server: "letsencrypt"
  auto_renew: true
  enable_http_challenge: true
  enable_dns_challenge: true
```

### 📧 邮箱地址配置说明

**重要**：ACME协议要求使用有效的邮箱地址进行证书申请。ESemail会按以下顺序选择邮箱：

1. **请求中指定的邮箱** - API调用时提供的email参数
2. **配置文件中的邮箱** - config.yaml中cert.email设置
3. **自动生成邮箱** - 基于申请域名生成admin@domain.com格式
4. **公共邮箱回退** - 使用admin@gmail.com等公共邮箱域名

**建议配置**：
```yaml
# 推荐配置：使用真实管理员邮箱
cert:
  email: "admin@yourdomain.com"  # 替换为您的真实邮箱
```

**支持的邮箱格式**：
- ✅ admin@yourdomain.com（推荐）
- ✅ webmaster@yourdomain.com
- ✅ admin@gmail.com（公共邮箱，可用作回退）
- ❌ admin@localhost（无效）
- ❌ admin@example.com（被ACME拒绝）
- ❌ test@test.local（无效TLD）

### 2. HTTP验证准备（推荐新手）
```bash
# 确保webroot目录存在
mkdir -p /var/www/html

# 确保端口80可用（停止可能占用的服务）
sudo systemctl stop apache2 nginx 2>/dev/null || true

# 检查端口80是否可用
sudo netstat -tlnp | grep :80
```

### 3. DNS验证准备（推荐生产环境）

#### Cloudflare配置
```bash
export CF_Key="your_cloudflare_global_api_key"
export CF_Email="your_cloudflare_email"
```

#### 阿里云DNS配置
```bash
export Ali_Key="your_aliyun_access_key"
export Ali_Secret="your_aliyun_access_secret"
```

#### AWS Route53配置
```bash
export AWS_ACCESS_KEY_ID="your_aws_access_key"
export AWS_SECRET_ACCESS_KEY="your_aws_secret_key"
```

#### DNSPod配置
```bash
export DP_Id="your_dnspod_api_id"
export DP_Key="your_dnspod_api_key"
```

## 🚀 使用示例

### HTTP验证申请证书
通过ESemail管理界面或API（邮箱从配置注入，不需在请求中提供）：
```http
POST /api/v1/certificates/issue
{
  "domain": "mail.yourdomain.com"
}
```

### DNS验证申请证书
```http
POST /api/v1/certificates/issue
{
  "domain": "*.yourdomain.com"
}
```

## 🔐 权限设置

```bash
# 确保acme.sh可执行
chmod +x /root/.acme.sh/acme.sh

# 创建证书目录并设置权限
mkdir -p /etc/ssl/mail
chown -R root:root /etc/ssl/mail
chmod 755 /etc/ssl/mail

# 创建webroot目录
mkdir -p /var/www/html
chown -R www-data:www-data /var/www/html
chmod 755 /var/www/html
```

## ⚠️ 故障排除

### 常见问题

#### 1. "executable file not found in $PATH"
```bash
# 检查acme.sh是否存在
ls -la /root/.acme.sh/acme.sh

# 如果不存在，重新安装
curl https://get.acme.sh | sh
```

#### 2. "Permission denied"
```bash
# 修复权限
chmod +x /root/.acme.sh/acme.sh
chown root:root /root/.acme.sh/acme.sh
```

#### 3. "Port 80 already in use"
```bash
# 查找占用端口80的进程
sudo lsof -i :80

# 停止冲突服务
sudo systemctl stop nginx apache2 httpd 2>/dev/null || true
```

#### 4. DNS验证失败
```bash
# 检查DNS记录是否生效
# 方式一：使用系统解析器进行本地验证（不直连公共DNS）
export CERT_DNS_MODE=system

# 方式二：自定义解析器（逗号分隔）
export DNS_RESOLVERS="223.5.5.5:53,119.29.29.29:53"

# 方式三（谨慎）：跳过本地预校验，直接交给ACME验证
export CERT_SKIP_PRECHECK=true

# 等待DNS传播（通常需要几分钟到几小时）
```

#### 5. 邮箱验证失败
```bash
# 错误: "contact email has invalid domain"
# 解决方案: 在config.yaml中配置有效邮箱（证书邮箱不再从API传入）
cert:
  email: "admin@yourdomain.com"  # 使用您的真实域名
# 或使用公共邮箱（不推荐但可用）
cert:
  email: "admin@gmail.com"
```

## 🔄 自动续签设置

```bash
# acme.sh默认会自动添加cron任务
crontab -l | grep acme

# 手动添加cron任务（如果没有）
echo '0 2 * * * /root/.acme.sh/acme.sh --cron --home /root/.acme.sh' | crontab -

# 通过ESemail API手动续签
curl -X POST http://localhost:8686/api/v1/certificates/renew
```

## 📝 日志和调试

```bash
# 查看acme.sh日志
tail -f /root/.acme.sh/acme.sh.log

# 启用调试模式申请证书
export DEBUG=1
/root/.acme.sh/acme.sh --issue -d yourdomain.com --webroot /var/www/html

# 查看ESemail日志
tail -f ./logs/app.log
```

## 🎖️ 最佳实践

1. **生产环境建议使用DNS验证**，更安全且支持通配符证书
2. **设置自动续签**，避免证书过期
3. **定期备份证书**，确保服务连续性
4. **监控证书状态**，及时处理异常
5. **使用Let's Encrypt**，免费且被广泛信任

## 📞 支持

如果遇到问题，请：
1. 查看 `/root/.acme.sh/acme.sh.log` 日志
2. 查看 ESemail 应用日志
3. 在项目GitHub提交Issue

---
**注意**：首次使用建议先在测试域名上验证配置正确性。

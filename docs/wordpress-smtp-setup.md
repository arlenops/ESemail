# WordPress WP Mail SMTP 集成教程

本教程将指导您如何将 WordPress 网站的 WP Mail SMTP 插件连接到 ESemail 服务器。

## 前提条件

1. 已成功部署并运行 ESemail 服务器
2. 已完成 ESemail 系统初始化
3. 已在 ESemail 中添加并管理您的域名
4. WordPress 网站已安装 WP Mail SMTP 插件

## 第一步：ESemail 服务器配置

### 1.1 确认 SMTP 服务状态

登录 ESemail 管理界面，前往 **邮件管理** → **服务状态**，确认：
- SMTP 服务运行状态为 "运行中"
- SMTP 端口已正确配置（默认：25, 465, 587）
- TLS 加密已启用

### 1.2 添加域名管理

在 **域名管理** 中添加您的 WordPress 网站域名：
1. 点击 "添加域名"
2. 输入您的域名（例如：example.com）
3. 等待域名验证完成

### 1.3 创建邮件用户

在 **用户管理** 中创建用于发送邮件的账户：
1. 点击 "添加用户"
2. 输入邮件地址（例如：noreply@example.com）
3. 设置密码（记住此密码，稍后配置时需要）
4. 确保用户状态为 "激活"

### 1.4 配置 DNS 记录

按照 ESemail 推荐的 DNS 配置，在您的域名服务商处添加以下记录：

```
# MX 记录
example.com    MX    10    mail.example.com

# A 记录
mail.example.com    A    您的服务器IP

# SPF 记录
example.com    TXT    v=spf1 mx a ip4:您的服务器IP -all

# DKIM 记录（从 ESemail 获取具体值）
default._domainkey.example.com    TXT    v=DKIM1; k=rsa; p=...

# DMARC 记录
_dmarc.example.com    TXT    v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com
```

## 第二步：WordPress WP Mail SMTP 配置

### 2.1 安装插件

如果尚未安装，请在 WordPress 后台安装 "WP Mail SMTP" 插件：
1. 进入 **插件** → **安装插件**
2. 搜索 "WP Mail SMTP"
3. 安装并激活插件

### 2.2 基本设置

进入 **WP Mail SMTP** → **设置**：

#### 邮件发送方式
- 选择 **"其他 SMTP"**

#### 发件人设置
- **发件人邮箱地址**：noreply@example.com（使用在 ESemail 中创建的邮件地址）
- **发件人姓名**：您的网站名称
- **强制使用发件人邮箱**：勾选
- **强制使用发件人姓名**：勾选

#### SMTP 设置
- **SMTP 主机**：您的 ESemail 服务器 IP 或域名（例如：mail.example.com）
- **加密**：选择 **SSL** 或 **TLS**
- **SMTP 端口**：
  - SSL: 465
  - TLS: 587
  - 无加密: 25
- **身份验证**：开启
- **SMTP 用户名**：noreply@example.com（完整邮箱地址）
- **SMTP 密码**：在 ESemail 中设置的密码

### 2.3 高级设置（可选）

#### 邮件日志
- 开启邮件日志记录，便于排查问题

#### 备份连接
- 可以配置备用 SMTP 服务器作为故障转移

## 第三步：测试配置

### 3.1 发送测试邮件

在 WP Mail SMTP 设置页面：
1. 切换到 **"邮件测试"** 标签
2. 输入您的邮箱地址
3. 点击 **"发送邮件"**
4. 检查是否收到测试邮件

### 3.2 查看邮件日志

如果测试失败，检查以下日志：

**WordPress 端：**
- WP Mail SMTP → 邮件日志
- WordPress 调试日志

**ESemail 端：**
- 邮件管理 → 邮件历史
- 服务器日志文件

## 常见问题排查

### 问题 1：连接被拒绝

**可能原因：**
- SMTP 端口被防火墙阻止
- 服务器 IP 不正确
- SMTP 服务未启动

**解决方案：**
```bash
# 检查端口是否开放
telnet 您的服务器IP 587

# 检查防火墙设置
sudo ufw status
sudo ufw allow 25,465,587,993,995/tcp
```

### 问题 2：身份验证失败

**可能原因：**
- 用户名或密码错误
- 用户账户被禁用
- 域名未正确配置

**解决方案：**
1. 确认 ESemail 中用户账户激活状态
2. 重置用户密码
3. 检查域名管理状态

### 问题 3：邮件发送成功但未收到

**可能原因：**
- SPF/DKIM/DMARC 配置不正确
- 邮件被标记为垃圾邮件
- DNS 记录未生效

**解决方案：**
1. 使用邮件头分析工具检查认证状态
2. 检查垃圾邮件文件夹
3. 等待 DNS 记录全球生效（最多 48 小时）

### 问题 4：TLS/SSL 证书错误

**解决方案：**
```php
// 在 WordPress wp-config.php 中临时禁用 SSL 验证（仅用于测试）
define('WP_MAIL_SMTP_SSL_VERIFY', false);
```

**生产环境建议：**
为服务器配置有效的 SSL 证书（Let's Encrypt）

## 性能优化建议

### 1. 邮件队列设置

在 ESemail 配置中调整队列参数：
```yaml
mail_queue:
  max_concurrent: 5        # 并发发送数
  process_interval: 1s     # 处理间隔
  retry_interval: 30s      # 重试间隔
  max_retries: 3          # 最大重试次数
```

### 2. WordPress 优化

安装邮件队列插件，避免大量邮件阻塞页面加载：
- WP Mail Queue
- Action Queue

### 3. 监控设置

定期检查：
- ESemail 邮件历史和发送状态
- WordPress 邮件日志
- 服务器性能指标

## 安全建议

1. **使用专用邮件账户**：为 WordPress 创建专门的邮件账户，不要使用管理员邮箱
2. **定期更换密码**：定期更新 SMTP 认证密码
3. **限制发送频率**：在 ESemail 中配置合理的发送限制
4. **监控异常活动**：定期检查邮件发送日志，发现异常及时处理

## 支持与帮助

如遇到问题，请：
1. 查看 ESemail 邮件管理界面的详细错误信息
2. 检查 WordPress 和 ESemail 的日志文件
3. 确认 DNS 记录配置正确
4. 测试基本的 SMTP 连接性

---

**注意：** 本教程基于 ESemail 的默认配置。如果您的服务器有特殊配置，请相应调整设置参数。
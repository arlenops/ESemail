# SMTP 功能验证脚本使用说明

本目录包含了用于验证 ESemail SMTP 功能的测试脚本，可以全面测试邮件服务器的连接性和发送功能。

## 📁 文件说明

- `test_smtp.py` - Python版本的完整SMTP测试脚本
- `test_smtp.sh` - Shell版本的快速SMTP测试脚本
- `smtp_config.conf` - 配置文件模板
- `README.md` - 本说明文件

## 🚀 快速开始

### 方法一：使用Python脚本 (推荐)

1. **安装依赖**：
   ```bash
   pip install colorama
   ```

2. **运行测试**：
   ```bash
   python3 test_smtp.py
   ```

### 方法二：使用Shell脚本

1. **确保依赖已安装**：
   ```bash
   # Ubuntu/Debian
   sudo apt-get install curl telnet openssl

   # CentOS/RHEL
   sudo yum install curl telnet openssl
   ```

2. **设置执行权限并运行**：
   ```bash
   chmod +x test_smtp.sh
   ./test_smtp.sh
   ```

## 🔧 配置说明

脚本中包含了以下测试服务器配置：

```
SMTP主机: mail.caiji.wiki
用户名: yiqiu@caiji.wiki
密码: 123456789
```

如需修改配置，请编辑脚本文件中的相应变量。

## 📋 测试项目

脚本将测试以下功能：

### 1. 基础连接测试
- DNS解析验证
- 端口连通性测试 (25, 587, 465)
- SMTP服务响应测试

### 2. 认证测试
- 用户名密码验证
- 各种加密方式的认证测试

### 3. 邮件发送测试
- **端口 465** (SMTPS/SSL) - 直接SSL连接
- **端口 587** (SMTP/STARTTLS) - TLS加密连接
- **端口 25** (SMTP) - 标准连接

### 4. 协议支持测试
- SSL/TLS 加密支持
- STARTTLS 功能测试
- 明文连接测试

## 📊 测试结果解读

### ✅ 成功示例
```
✓ DNS解析成功: mail.caiji.wiki -> 123.456.789.0
✓ 端口 465 连接成功
✓ SMTP服务响应正常: 220 mail.caiji.wiki ESMTP
✓ SMTP认证成功
✓ 测试邮件发送成功 (SSL)
```

### ❌ 失败示例及解决方法

**1. DNS解析失败**
```
✗ DNS解析失败: mail.caiji.wiki
```
- 检查域名是否正确
- 检查DNS服务器设置

**2. 端口连接失败**
```
✗ 端口 465 连接失败
```
- 检查服务器是否启动
- 检查防火墙设置：`sudo ufw allow 465/tcp`

**3. SMTP认证失败**
```
✗ SMTP认证失败: 535 Authentication failed
```
- 检查用户名和密码
- 确认用户账户已激活

**4. SSL证书问题**
```
✗ SSL连接失败: certificate verify failed
```
- 检查SSL证书是否正确安装
- 验证证书是否过期

## 🔍 故障排查

### 查看详细日志
Python脚本会输出详细的调试信息，包括：
- 每个连接步骤的状态
- 服务器响应内容
- 错误详细信息

### 手动测试SMTP连接
```bash
# 测试SSL连接 (465端口)
openssl s_client -connect mail.caiji.wiki:465

# 测试STARTTLS连接 (587端口)
telnet mail.caiji.wiki 587
# 然后输入: EHLO test
# 再输入: STARTTLS
```

### 检查服务器状态
```bash
# 检查端口是否开放
nmap -p 25,465,587 mail.caiji.wiki

# 检查DNS解析
nslookup mail.caiji.wiki
dig mail.caiji.wiki MX
```

## 📧 WordPress配置建议

根据测试结果，推荐的WordPress WP Mail SMTP配置：

### 如果465端口测试成功 (推荐)
```
SMTP主机: mail.caiji.wiki
端口: 465
加密: SSL
用户名: yiqiu@caiji.wiki
密码: 123456789
```

### 如果587端口测试成功
```
SMTP主机: mail.caiji.wiki
端口: 587
加密: TLS
用户名: yiqiu@caiji.wiki
密码: 123456789
```

## ⚠️ 安全提醒

1. **不要在生产环境中使用简单密码**
2. **定期更换邮件账户密码**
3. **确保使用加密连接 (SSL/TLS)**
4. **限制SMTP访问IP范围**

## 🆘 常见问题

**Q: 测试邮件没有收到怎么办？**
A: 检查垃圾邮件箱，确认邮件服务器日志，验证收件人地址正确。

**Q: 所有端口都无法连接？**
A: 检查服务器是否启动，防火墙配置，以及网络连通性。

**Q: 认证成功但发送失败？**
A: 检查用户配额，域名配置，以及邮件内容是否符合规范。

---

如有其他问题，请查看ESemail服务器日志或联系系统管理员。
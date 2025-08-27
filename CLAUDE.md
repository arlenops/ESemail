**项目名称与介绍**：项目名叫ESemail是个轻量化邮局系统
**目标**：部署在docker，不占用 80/443。支持 **SMTP / IMAP / POP3 / HTTP 控制面**，具备基础送达与反垃圾能力，保留历史记录浏览，证书通过 **acme.sh DNS-01** 自动化签发。

## 架构与端口

* **Postfix**：MTA（收发、队列、重试）
* **Rspamd**：反垃圾与策略中心（milter）
* **OpenDKIM**：出站签名（milter）
* **Dovecot**：IMAP / POP3 服务（Maildir 存储）
* **控制面（Gin）**：域/用户管理、DNS 引导、历史浏览、EML 下载

  * 默认监听 **:8686**，不占 80/443
* **acme.sh**：DNS-01 证书自动化（通配或多域）

**对外端口：**

| 服务         | 端口        | 说明             |
| ---------- | --------- | -------------- |
| SMTP 入站    | 25        | 外部来信           |
| Submission | 465 / 587 | 客户端发信          |
| IMAPS      | 993       | 客户端收取（加密）      |
| POP3S      | 995       | 客户端收取（加密）      |
| 控制面        | 8686 (可配) | 管理后台，不占 80/443 |

---

## 技术选型

| 模块   | 选型       | 理由               |
| ---- | -------- | ---------------- |
| MTA  | Postfix  | 成熟稳定，队列/重试丰富     |
| 反垃圾  | Rspamd   | 轻量高效，可策略化        |
| DKIM | OpenDKIM | 主流集成方式           |
| 存储   | Maildir  | 简单，无外部依赖         |
| 收件协议 | Dovecot  | IMAP/POP3 兼容性好   |
| 控制面  | Go + Gin | 轻量，端口可自定义        |
| 证书   | acme.sh  | DNS-01，不占 80/443 |

---

## 系统功能

### 系统部署
* 要求部署简单配置项都集成到web界面
* 提供开发环境下的镜像打包教程
* 提供还未打包时的测试教程

### 域与身份

* MX/SPF/DKIM/DMARC 引导与状态检测
* DKIM：生成 selector + 私钥，导出 TXT
* DMARC：建议 `p=none`（监测模式）

### 用户与邮箱

* 用户新增/禁用、密码重置、别名/转发
* 系统文件夹：INBOX/SENT/JUNK/TRASH/DRAFTS
* 历史记录：

  * 按日期/方向/用户浏览
  * 查看详情（头字段+状态）
  * 下载原始 EML 文件

### 系统健康监控

* **首页仪表盘**：实时显示所有邮件服务组件状态
  * Postfix（SMTP/Submission）运行状态与队列情况
  * Rspamd 服务状态与规则加载情况
  * OpenDKIM 运行状态与密钥验证
  * Dovecot（IMAP/POP3）服务状态
  * 磁盘使用率、内存占用等系统资源
  * 端口监听状态（25/465/587/993/995）

* **状态监测**：
  * 绿色：服务正常运行
  * 黄色：服务运行但有警告（如队列积压）
  * 红色：服务异常或停止
  * 自动刷新间隔：30秒

* **系统初始化**：
  * 首次访问控制面时，检测系统初始化状态
  * 如未初始化，显示引导页面和"一键初始化"按钮
  * 初始化流程包括：
    * 检查并安装所需软件包（Postfix/Rspamd/Dovecot/OpenDKIM）
    * 创建基础配置文件
    * 生成默认 DKIM 密钥
    * 启动所有邮件服务
    * 验证服务运行状态

### 收发闭环

* 入站：Postfix → Rspamd → Maildir → Dovecot
* 出站：客户端 → Submission (TLS) → OpenDKIM → Postfix 队列 → 外部 MX

---

## Rspamd 策略

* **评分与动作：**

  * `<=5` → 正常投递
  * `5~8` → 加头标记，投递到 JUNK
  * `8~15` → soft reject / greylist
  * `>15` → 拒收

* **推荐启用模块：**

  * SPF/DKIM/DMARC 校验
  * RBL/DNSBL（如 Spamhaus）
  * MIME/HTML 检查
  * URL reputation（轻量启用）
  * Greylisting（陌生来源）

* **出站防滥用：**

  * Submission 速率限制
  * PTR/HELO 合法性校验
  * SPF/DKIM 一致性保证

---

## TLS 证书

* 使用 **acme.sh + DNS-01**
* 步骤：

  1. 配置 DNS 提供商 API（如 Cloudflare/阿里云）
  2. 申请证书：

     ```bash
     acme.sh --issue --dns dns_cf -d example.com -d *.example.com
     ```
  3. 安装证书并 reload：

     ```bash
     acme.sh --install-cert -d example.com \
       --key-file /etc/ssl/mail/example.com/privkey.pem \
       --fullchain-file /etc/ssl/mail/example.com/fullchain.pem \
       --reloadcmd "systemctl reload postfix dovecot"
     ```
* 控制面 (:8686) 如需 HTTPS，可签 `admin.example.com` 单独证书加载

---

---

## 运维要点

* **日志**：使用系统自带 `/var/log/maillog` 或 `journalctl`
* **证书**：acme.sh 自动续签，失败可邮件提醒
* **备份**：备份 Maildir、Postfix/Dovecot/OpenDKIM/Rspamd 配置、证书目录
* **安全**：

  * 控制面端口仅对管理来源放行
  * 强密码策略 / 可选 TOTP
  * Submission 并发与速率限制

---


**验收点：**

* 客户端正常收发
* SPF/DKIM 通过，DMARC 生效
* Rspamd 拦截明显垃圾，误判率可控
* 控制面可正常管理与浏览历史
* 首页健康监控正确显示所有服务状态
* 系统初始化功能完整可用
* 不占用 80/443

---


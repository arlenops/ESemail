#!/bin/bash

set -e

echo "🚀 ESemail 云服务器一键部署脚本"
echo "================================"
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }

# 检查是否为root用户
if [[ $EUID -ne 0 ]]; then
   log_error "此脚本需要以root权限运行"
   echo "请使用: sudo $0"
   exit 1
fi

# 检查操作系统
if ! grep -q "Ubuntu\|Debian" /etc/os-release; then
    log_error "此脚本仅支持 Ubuntu/Debian 系统"
    exit 1
fi

log_success "系统检查通过: $(lsb_release -d | cut -f2)"

# 获取服务器IP
SERVER_IP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip || hostname -I | awk '{print $1}')
log_info "服务器IP: $SERVER_IP"

# 设置变量
ESEMAIL_USER="esemail"
ESEMAIL_HOME="/opt/esemail"
ESEMAIL_DATA="/var/lib/esemail"
ESEMAIL_CONFIG="/etc/esemail"

echo ""
echo "📋 部署配置:"
echo "   用户: $ESEMAIL_USER"
echo "   安装目录: $ESEMAIL_HOME"
echo "   数据目录: $ESEMAIL_DATA" 
echo "   配置目录: $ESEMAIL_CONFIG"
echo "   服务器IP: $SERVER_IP"
echo ""

read -p "是否继续部署？[y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# 更新系统
log_info "检查系统包更新..."
if [ ! -f "/tmp/.esemail_apt_updated" ]; then
    log_info "更新系统包..."
    apt-get update && touch /tmp/.esemail_apt_updated
    log_success "系统包列表更新完成"
else
    log_success "系统包列表已更新（跳过）"
fi

# 检查并升级系统（可选）
log_info "检查系统升级（可跳过）..."
read -p "是否升级系统软件包？这可能需要较长时间 [y/N]: " -t 10 -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    apt-get upgrade -y
    log_success "系统升级完成"
else
    log_info "跳过系统升级"
fi

# 安装基础依赖
log_info "检查基础依赖..."
missing_deps=()
required_deps=("curl" "wget" "git" "build-essential" "supervisor" "ca-certificates" "gnupg2" "software-properties-common" "apt-transport-https" "lsb-release" "ufw")

for dep in "${required_deps[@]}"; do
    if ! dpkg -l | grep -q "^ii  $dep "; then
        missing_deps+=("$dep")
    fi
done

if [ ${#missing_deps[@]} -gt 0 ]; then
    log_info "安装缺失的基础依赖: ${missing_deps[*]}"
    apt-get install -y "${missing_deps[@]}" || {
        log_error "基础依赖安装失败"
        exit 1
    }
    log_success "基础依赖安装完成"
else
    log_success "基础依赖已安装（跳过）"
fi

# 安装Go
log_info "检查Go安装..."
if command -v go >/dev/null 2>&1; then
    CURRENT_GO_VERSION=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+\.[0-9]+')
    REQUIRED_GO_VERSION="1.21.0"
    
    if [ "$(printf '%s\n' "$REQUIRED_GO_VERSION" "$CURRENT_GO_VERSION" | sort -V | head -n1)" = "$REQUIRED_GO_VERSION" ]; then
        log_success "Go已安装且版本满足要求: $(go version)"
    else
        log_warning "Go版本过低: $CURRENT_GO_VERSION，需要升级到 >= $REQUIRED_GO_VERSION"
    fi
else
    log_info "安装Go编程语言..."
    GO_VERSION="1.21.6"
    
    # 检查是否已下载
    if [ ! -f "/tmp/go.tar.gz" ]; then
        wget -q https://golang.google.cn/dl/go${GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz || {
            log_error "Go下载失败"
            exit 1
        }
    fi
    
    # 安装Go
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz || {
        log_error "Go解压失败"
        exit 1
    }
    
    # 设置Go环境变量
    if ! grep -q "/usr/local/go/bin" /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    
    export PATH=$PATH:/usr/local/go/bin
    rm -f /tmp/go.tar.gz
    
    log_success "Go安装完成: $(/usr/local/go/bin/go version)"
fi

# 安装邮件服务组件
log_info "检查邮件服务组件..."

# 检查需要安装的邮件组件
mail_components=("postfix" "dovecot-core" "dovecot-imapd" "dovecot-pop3d" "dovecot-lmtpd" "rspamd" "opendkim" "opendkim-tools" "redis-server")
missing_components=()

for component in "${mail_components[@]}"; do
    if ! dpkg -l | grep -q "^ii  $component "; then
        missing_components+=("$component")
    fi
done

if [ ${#missing_components[@]} -gt 0 ]; then
    log_info "安装缺失的邮件组件: ${missing_components[*]}"
    
    # 如果需要安装Postfix，预设配置
    if [[ " ${missing_components[*]} " =~ " postfix " ]]; then
        echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections
        echo "postfix postfix/mailname string $(hostname -f)" | debconf-set-selections
    fi
    
    # 安装缺失的组件
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing_components[@]}" || {
        log_error "邮件服务组件安装失败"
        exit 1
    }
    
    log_success "邮件服务组件安装完成"
else
    log_success "邮件服务组件已安装（跳过）"
fi

# 安装acme.sh
log_info "检查证书管理工具..."
if [ -d "/root/.acme.sh" ] && [ -f "/root/.acme.sh/acme.sh" ]; then
    log_success "acme.sh已安装（跳过）"
else
    log_info "安装证书管理工具..."
    curl -s https://get.acme.sh | sh -s email=admin@$(hostname -f) || {
        log_error "acme.sh安装失败"
        exit 1
    }
    log_success "acme.sh安装完成"
fi

# 创建系统用户
log_info "创建系统用户..."

# 创建esemail用户（如果不存在）
if ! id "$ESEMAIL_USER" &>/dev/null; then
    useradd -r -s /bin/bash -d "$ESEMAIL_HOME" -m "$ESEMAIL_USER" || {
        log_error "创建 $ESEMAIL_USER 用户失败"
        exit 1
    }
    log_success "创建 $ESEMAIL_USER 用户成功"
else
    log_success "$ESEMAIL_USER 用户已存在"
fi

# 创建vmail用户组和用户（如果不存在）
if ! getent group vmail >/dev/null 2>&1; then
    groupadd -g 5000 vmail || {
        log_error "创建 vmail 组失败"
        exit 1
    }
    log_success "创建 vmail 组成功"
else
    log_success "vmail 组已存在"
fi

if ! id "vmail" &>/dev/null; then
    useradd -u 5000 -g vmail -d "$ESEMAIL_DATA/mail" -s /usr/sbin/nologin vmail || {
        log_error "创建 vmail 用户失败"
        exit 1
    }
    log_success "创建 vmail 用户成功"
else
    log_success "vmail 用户已存在"
fi

log_success "系统用户创建完成"

# 创建目录结构
log_info "创建目录结构..."
mkdir -p "$ESEMAIL_HOME" || { log_error "创建 $ESEMAIL_HOME 目录失败"; exit 1; }
mkdir -p "$ESEMAIL_DATA"/{mail,db,acme} || { log_error "创建数据目录失败"; exit 1; }
mkdir -p "$ESEMAIL_CONFIG" || { log_error "创建配置目录失败"; exit 1; }
mkdir -p /etc/ssl/mail || { log_error "创建SSL目录失败"; exit 1; }
mkdir -p /etc/opendkim/keys || { log_error "创建OpenDKIM目录失败"; exit 1; }
mkdir -p /var/log/esemail || { log_error "创建日志目录失败"; exit 1; }
mkdir -p /var/spool/postfix/rspamd || { log_error "创建Postfix目录失败"; exit 1; }

# 设置权限（带错误检查）
chown -R "$ESEMAIL_USER:$ESEMAIL_USER" "$ESEMAIL_HOME" 2>/dev/null || {
    log_warning "设置 $ESEMAIL_HOME 权限失败，继续执行..."
}

chown -R vmail:vmail "$ESEMAIL_DATA/mail" 2>/dev/null || {
    log_warning "设置邮件目录权限失败，继续执行..."
}

# 检查opendkim用户是否存在（可能还没安装opendkim）
if id "opendkim" &>/dev/null; then
    chown -R opendkim:opendkim /etc/opendkim 2>/dev/null || {
        log_warning "设置OpenDKIM权限失败，继续执行..."
    }
else
    log_info "OpenDKIM用户不存在，稍后安装OpenDKIM后会自动设置权限"
fi

chmod 755 "$ESEMAIL_CONFIG" || { log_error "设置配置目录权限失败"; exit 1; }

log_success "目录结构创建完成"

# 下载并编译ESemail
log_info "检查ESemail应用..."

if [ -f "$ESEMAIL_HOME/esemail" ]; then
    log_success "ESemail应用已编译（跳过）"
else
    log_info "编译ESemail应用..."
    cd "$ESEMAIL_HOME"
    
    # 如果是从项目目录运行，复制源码
    if [[ -f "$(dirname "$0")/../go.mod" ]]; then
        log_info "从本地项目复制源码..."
        cp -r "$(dirname "$0")/.." "$ESEMAIL_HOME/src"
        cd "$ESEMAIL_HOME/src"
    else
        # 否则从git克隆（这里需要你提供git地址）
        log_warning "需要手动复制ESemail源码到 $ESEMAIL_HOME/src"
        exit 1
    fi
    
    # 编译
    export GOPROXY=https://goproxy.cn,direct
    export GO111MODULE=on
    /usr/local/go/bin/go mod tidy
    /usr/local/go/bin/go build -o "$ESEMAIL_HOME/esemail" main.go
    
    chown "$ESEMAIL_USER:$ESEMAIL_USER" "$ESEMAIL_HOME/esemail"
    chmod +x "$ESEMAIL_HOME/esemail"
    
    log_success "ESemail编译完成"
fi

# 创建配置文件
log_info "检查配置文件..."

if [ -f "$ESEMAIL_CONFIG/config.yaml" ]; then
    log_success "配置文件已存在（跳过）"
else
    log_info "创建配置文件..."
    
    cat > "$ESEMAIL_CONFIG/config.yaml" << EOF
server:
  port: "8686"
  mode: "release"

database:
  path: "$ESEMAIL_DATA/db"

mail:
  data_path: "$ESEMAIL_DATA/mail"
  log_path: "/var/log/esemail"
  domains: []

cert:
  acme_path: "$ESEMAIL_DATA/acme"
  cert_path: "/etc/ssl/mail"
  auto_renew: true
EOF
    
    chown "$ESEMAIL_USER:$ESEMAIL_USER" "$ESEMAIL_CONFIG/config.yaml"
    
    log_success "配置文件创建完成"
fi

# 配置基础的邮件服务
log_info "配置邮件服务..."

# 基础Postfix配置
cat >> /etc/postfix/main.cf << EOF

# ESemail Configuration
virtual_mailbox_domains = 
virtual_mailbox_maps = 
virtual_alias_maps = 
virtual_mailbox_base = $ESEMAIL_DATA/mail
virtual_minimum_uid = 5000
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000

# Milter configuration
smtpd_milters = unix:/var/spool/postfix/rspamd/rspamd-milter.sock,unix:/var/spool/postfix/opendkim/opendkim.sock
non_smtpd_milters = unix:/var/spool/postfix/rspamd/rspamd-milter.sock,unix:/var/spool/postfix/opendkim/opendkim.sock
milter_protocol = 6
milter_mail_macros = i {mail_addr} {client_addr} {client_name} {auth_authen}
milter_default_action = accept
EOF

# 基础Dovecot配置
cat > /etc/dovecot/conf.d/99-esemail.conf << EOF
# ESemail Dovecot Configuration
mail_location = maildir:$ESEMAIL_DATA/mail/%d/%n
first_valid_uid = 5000
last_valid_uid = 5000
first_valid_gid = 5000
last_valid_gid = 5000

userdb {
  driver = static
  args = uid=vmail gid=vmail home=$ESEMAIL_DATA/mail/%d/%n
}

passdb {
  driver = static
  args = password=changeme
}
EOF

log_success "邮件服务配置完成"

# 现在OpenDKIM已安装，设置其权限
log_info "设置OpenDKIM权限..."
if id "opendkim" &>/dev/null; then
    chown -R opendkim:opendkim /etc/opendkim 2>/dev/null || {
        log_warning "设置OpenDKIM权限失败，但继续执行..."
    }
    log_success "OpenDKIM权限设置完成"
else
    log_warning "OpenDKIM用户仍不存在，权限设置跳过"
fi

# 创建systemd服务
log_info "检查systemd服务..."

if [ -f "/etc/systemd/system/esemail.service" ]; then
    log_success "systemd服务已存在（跳过）"
else
    log_info "创建systemd服务..."
    
    cat > /etc/systemd/system/esemail.service << EOF
[Unit]
Description=ESemail Mail Server Control Panel
After=network.target postgresql.service mysql.service redis.service
Wants=network.target

[Service]
Type=simple
User=$ESEMAIL_USER
Group=$ESEMAIL_USER
WorkingDirectory=$ESEMAIL_HOME
Environment=ESEMAIL_CONFIG=$ESEMAIL_CONFIG/config.yaml
ExecStart=$ESEMAIL_HOME/esemail
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=esemail

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$ESEMAIL_DATA $ESEMAIL_CONFIG /var/log/esemail

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable esemail
    
    log_success "systemd服务创建完成"
fi

# 配置防火墙
log_info "配置防火墙..."
ufw --force enable
ufw allow 22/tcp      # SSH
ufw allow 25/tcp      # SMTP
ufw allow 587/tcp     # Submission
ufw allow 465/tcp     # SMTPS  
ufw allow 993/tcp     # IMAPS
ufw allow 995/tcp     # POP3S
ufw allow 8686/tcp    # Web控制面

log_success "防火墙配置完成"

# 启动服务
log_info "检查并启动服务..."

# 检查并启动基础服务
base_services=("redis-server" "rspamd" "opendkim" "postfix" "dovecot")
for service in "${base_services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        log_success "$service 已运行（跳过）"
    else
        log_info "启动 $service..."
        systemctl restart "$service" || {
            log_warning "启动 $service 失败，但继续执行..."
        }
    fi
done

# 检查并启动ESemail
if systemctl is-active --quiet "esemail"; then
    log_success "esemail 已运行（跳过）"
else
    log_info "启动 esemail..."
    systemctl start esemail || {
        log_warning "启动 esemail 失败，但继续执行..."
    }
fi

sleep 5

log_success "服务启动完成"

# 检查服务状态
log_info "检查服务状态..."

services=("redis-server" "rspamd" "opendkim" "postfix" "dovecot" "esemail")
all_running=true

for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        log_success "$service 运行正常"
    else
        log_error "$service 运行异常"
        all_running=false
    fi
done

# 检查Web服务
log_info "检查Web服务..."
for i in {1..10}; do
    if curl -s http://localhost:8686 >/dev/null 2>&1; then
        log_success "Web服务正常运行"
        break
    elif [ $i -eq 10 ]; then
        log_error "Web服务无响应"
        all_running=false
    else
        log_info "等待Web服务启动... ($i/10)"
        sleep 3
    fi
done

# 检查端口
log_info "检查端口监听..."
netstat -tlnp | grep -E ':(25|587|465|993|995|8686)\s'

echo ""
if [ "$all_running" = true ]; then
    log_success "🎉 ESemail部署成功！"
else
    log_warning "⚠️  部分服务存在问题，请检查日志"
fi

echo ""
echo "📋 部署信息："
echo "================================="
echo "🌐 Web管理界面: http://$SERVER_IP:8686"
echo "📊 API接口: http://$SERVER_IP:8686/api/v1/"
echo ""
echo "📧 邮件服务端口："
echo "   SMTP (接收): $SERVER_IP:25"
echo "   Submission: $SERVER_IP:587"
echo "   SMTPS: $SERVER_IP:465"
echo "   IMAPS: $SERVER_IP:993"
echo "   POP3S: $SERVER_IP:995"
echo ""
echo "📁 重要目录："
echo "   应用目录: $ESEMAIL_HOME"
echo "   配置目录: $ESEMAIL_CONFIG"
echo "   数据目录: $ESEMAIL_DATA"
echo "   日志: journalctl -u esemail -f"
echo ""
echo "🔧 服务管理："
echo "   查看状态: systemctl status esemail"
echo "   重启服务: systemctl restart esemail"
echo "   查看日志: journalctl -u esemail -f"
echo ""
echo "🎯 下一步："
echo "1. 在浏览器中访问: http://$SERVER_IP:8686"
echo "2. 完成系统初始化配置"
echo "3. 添加域名和DNS记录"
echo "4. 配置SSL证书"
echo "5. 测试邮件收发功能"
echo ""
echo "⚠️  安全提醒："
echo "- 请及时修改默认密码"
echo "- 配置合适的DNS记录（MX、SPF、DKIM、DMARC）"
echo "- 定期更新系统和应用"

log_success "部署脚本执行完成！"
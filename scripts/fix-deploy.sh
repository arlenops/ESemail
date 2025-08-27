#!/bin/bash

set -e

echo "🔧 修复 ESemail 部署问题"
echo "========================"

# 检查是否为root用户
if [[ $EUID -ne 0 ]]; then
   echo "❌ 此脚本需要以root权限运行"
   echo "请使用: sudo $0"
   exit 1
fi

# 创建vmail用户（如果不存在）
if ! id "vmail" &>/dev/null; then
    echo "🔧 创建vmail用户..."
    groupadd -g 5000 vmail
    useradd -u 5000 -g vmail -d /var/lib/esemail/mail -s /usr/sbin/nologin vmail
    echo "✅ vmail用户创建完成"
else
    echo "✅ vmail用户已存在"
fi

# 创建目录结构
echo "🔧 创建目录结构..."
mkdir -p /var/lib/esemail/{mail,db,acme}
mkdir -p /etc/ssl/mail
mkdir -p /etc/esemail
mkdir -p /etc/opendkim/keys
mkdir -p /var/log/esemail
mkdir -p /var/spool/postfix/rspamd

# 设置权限
chown -R vmail:vmail /var/lib/esemail/mail
chown -R opendkim:opendkim /etc/opendkim 2>/dev/null || echo "⚠️ opendkim用户不存在，稍后会创建"
chmod 755 /etc/esemail

echo "✅ 目录结构修复完成"

# 继续检查其他组件
echo "🔧 检查系统组件..."

# 检查Go是否安装
if command -v go >/dev/null 2>&1; then
    echo "✅ Go已安装: $(go version)"
else
    echo "❌ Go未安装，需要安装Go"
    exit 1
fi

# 检查邮件服务是否安装
services=("postfix" "dovecot" "rspamd" "opendkim")
missing_services=()

for service in "${services[@]}"; do
    if systemctl list-units --full -all | grep -q "$service.service"; then
        echo "✅ $service 已安装"
    else
        echo "❌ $service 未安装"
        missing_services+=("$service")
    fi
done

if [ ${#missing_services[@]} -gt 0 ]; then
    echo ""
    echo "❌ 以下服务需要安装: ${missing_services[*]}"
    echo "请重新运行完整的部署脚本: ./scripts/deploy-server.sh"
    exit 1
fi

# 检查ESemail是否编译
ESEMAIL_HOME="/opt/esemail"
if [ -f "$ESEMAIL_HOME/esemail" ]; then
    echo "✅ ESemail应用已编译"
else
    echo "🔧 编译ESemail应用..."
    
    # 确保目录存在
    mkdir -p "$ESEMAIL_HOME"
    
    # 复制源码（如果在当前目录）
    if [ -f "main.go" ]; then
        cp -r . "$ESEMAIL_HOME/src"
        cd "$ESEMAIL_HOME/src"
        
        # 编译
        export GOPROXY=https://goproxy.cn,direct
        export GO111MODULE=on
        go mod tidy
        go build -o "$ESEMAIL_HOME/esemail" main.go
        
        chown -R esemail:esemail "$ESEMAIL_HOME" 2>/dev/null || chown -R root:root "$ESEMAIL_HOME"
        chmod +x "$ESEMAIL_HOME/esemail"
        
        echo "✅ ESemail应用编译完成"
    else
        echo "❌ 找不到源代码，请在项目根目录运行此脚本"
        exit 1
    fi
fi

# 检查systemd服务
if [ -f "/etc/systemd/system/esemail.service" ]; then
    echo "✅ systemd服务已创建"
else
    echo "🔧 创建systemd服务..."
    
    cat > /etc/systemd/system/esemail.service << EOF
[Unit]
Description=ESemail Mail Server Control Panel
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$ESEMAIL_HOME
Environment=ESEMAIL_CONFIG=/etc/esemail/config.yaml
ExecStart=$ESEMAIL_HOME/esemail
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=esemail

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable esemail
    echo "✅ systemd服务创建完成"
fi

# 创建配置文件（如果不存在）
if [ ! -f "/etc/esemail/config.yaml" ]; then
    echo "🔧 创建配置文件..."
    
    cat > /etc/esemail/config.yaml << EOF
server:
  port: "8686"
  mode: "release"

database:
  path: "/var/lib/esemail/db"

mail:
  data_path: "/var/lib/esemail/mail"
  log_path: "/var/log/esemail"
  domains: []

cert:
  acme_path: "/var/lib/esemail/acme"
  cert_path: "/etc/ssl/mail"
  auto_renew: true
EOF

    echo "✅ 配置文件创建完成"
fi

# 启动服务
echo "🔧 启动ESemail服务..."
systemctl start esemail

sleep 3

# 检查服务状态
if systemctl is-active --quiet esemail; then
    echo "✅ ESemail服务启动成功"
    
    # 检查Web服务
    for i in {1..10}; do
        if curl -s http://localhost:8686 >/dev/null 2>&1; then
            echo "✅ Web服务正常运行: http://localhost:8686"
            break
        elif [ $i -eq 10 ]; then
            echo "❌ Web服务无响应"
        else
            echo "⏳ 等待Web服务启动... ($i/10)"
            sleep 2
        fi
    done
else
    echo "❌ ESemail服务启动失败"
    echo "查看日志: journalctl -u esemail -n 20"
    exit 1
fi

echo ""
echo "🎉 ESemail修复完成！"
echo "==================="
echo ""
echo "🌐 Web管理界面: http://$(curl -s ifconfig.me):8686"
echo "📊 服务状态: systemctl status esemail"
echo "📋 查看日志: journalctl -u esemail -f"
echo ""
echo "🎯 下一步："
echo "1. 访问Web管理界面进行系统初始化"
echo "2. 配置域名和DNS记录"
echo "3. 测试邮件收发功能"
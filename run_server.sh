#!/bin/bash

# 在远程服务器上运行ESemail的脚本
# 需要以root权限运行以绑定特权端口

set -e

echo "🚀 启动 ESemail 邮件服务器..."

# 检查是否有root权限
if [ "$EUID" -ne 0 ]; then
    echo "❌ 此脚本需要root权限运行"
    echo "请使用: sudo ./run_server.sh"
    exit 1
fi

# 停止可能运行的实例
echo "🔍 停止现有实例..."
pkill -f esemail || true
sleep 2

# 设置配置文件路径
export ESEMAIL_CONFIG="$(pwd)/config/config.yaml"
echo "⚙️  使用配置文件: $ESEMAIL_CONFIG"

# 检查SSL证书
CERT_FILE="/etc/ssl/mail/mail.caiji.wiki/fullchain.pem"
KEY_FILE="/etc/ssl/mail/mail.caiji.wiki/private.key"

if [ ! -f "$CERT_FILE" ]; then
    echo "❌ 证书文件不存在: $CERT_FILE"
    exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
    echo "❌ 私钥文件不存在: $KEY_FILE"
    exit 1
fi

echo "✅ SSL证书检查通过"

# 创建必要的目录
mkdir -p ./data/db ./mail ./logs ./backups

# 编译（如果需要）
if [ ! -f "./esemail" ] || [ "main.go" -nt "./esemail" ]; then
    echo "🔨 编译应用..."
    go build -o esemail
fi

# 启动服务
echo "🎯 启动邮件服务器..."
./esemail

echo "📊 邮件服务器应该在以下端口运行:"
echo "   - Web管理界面: http://localhost:8686"
echo "   - SMTP: 25"
echo "   - SMTP提交: 587"
echo "   - SMTPS (SSL): 465"
echo "   - IMAP: 143"
echo "   - IMAPS (SSL): 993"
#!/bin/bash

# ESemail 远程服务器强制更新脚本
# 确保远程服务器使用最新代码

set -e

SERVER_IP=${1:-"103.233.255.199"}
APP_PORT=${2:-"8686"}
APP_NAME="esemail"
DEPLOY_DIR="/opt/ESemail"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "🚀 ESemail 远程服务器强制更新"
echo "================================"
echo "请在远程服务器 $SERVER_IP 上执行以下命令："
echo ""

cat << 'EOF'
# 1. 停止所有现有进程
killall esemail 2>/dev/null || true
pkill -f esemail 2>/dev/null || true

# 2. 删除旧代码，重新克隆
cd /opt
rm -rf ESemail
git clone https://github.com/arlenops/ESemail.git

# 3. 编译新版本
cd ESemail
go mod tidy
go build -o esemail

# 4. 启动应用（后台运行，日志输出到文件）
mkdir -p logs
nohup ./esemail > logs/app.log 2>&1 &
echo $! > esemail.pid

# 5. 等待启动并测试
echo "等待应用启动..."
sleep 5

# 6. 测试接口是否修复
echo "测试系统初始化接口..."
curl -X POST http://localhost:8686/api/v1/system/init

# 7. 查看日志
echo "查看应用日志："
tail -20 logs/app.log

# 8. 显示管理命令
echo ""
echo "管理命令："
echo "查看日志: tail -f logs/app.log"
echo "停止应用: kill \$(cat esemail.pid)"
echo "重启应用: killall esemail; sleep 2; ./esemail &"

EOF

echo ""
echo "或者使用一键命令："
echo "curl -sSL https://raw.githubusercontent.com/arlenops/ESemail/main/remote_update.sh | bash"
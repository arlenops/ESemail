#!/bin/bash
# ESemail 远程服务器一键更新脚本

set -e

APP_NAME="esemail"
DEPLOY_DIR="/opt/ESemail"
REPO_URL="https://github.com/arlenops/ESemail.git"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "🔄 ESemail 远程服务器一键更新"
echo "==============================="

# 停止所有现有进程
log_info "停止现有进程..."
killall $APP_NAME 2>/dev/null || true
pkill -f $APP_NAME 2>/dev/null || true
sleep 2

# 检查端口是否释放
if lsof -Pi :8686 -sTCP:LISTEN -t >/dev/null 2>&1; then
    PID=$(lsof -Pi :8686 -sTCP:LISTEN -t)
    log_warn "强制杀死占用端口8686的进程 $PID"
    kill -9 $PID 2>/dev/null || true
fi

# 删除旧代码
log_info "删除旧代码..."
rm -rf $DEPLOY_DIR

# 重新克隆最新代码
log_info "克隆最新代码..."
cd /opt
git clone $REPO_URL
cd $DEPLOY_DIR

# 编译应用
log_info "编译应用..."
go mod tidy
go build -o $APP_NAME

# 创建日志目录
mkdir -p logs

# 启动应用
log_info "启动应用..."
nohup ./$APP_NAME > logs/app.log 2>&1 &
APP_PID=$!
echo $APP_PID > ${APP_NAME}.pid

# 等待启动
log_info "等待应用启动..."
sleep 5

# 检查进程是否运行
if ! kill -0 $APP_PID 2>/dev/null; then
    log_error "应用启动失败！查看日志："
    tail -20 logs/app.log
    exit 1
fi

log_success "应用已启动，PID: $APP_PID"

# 测试接口
log_info "测试关键接口..."

# 测试健康检查
if curl -s http://localhost:8686/api/v1/health > /dev/null; then
    log_success "✅ 健康检查接口正常"
else
    log_error "❌ 健康检查接口异常"
fi

# 测试系统初始化接口
RESPONSE=$(curl -s -X POST http://localhost:8686/api/v1/system/init)
if echo "$RESPONSE" | grep -q '"success"'; then
    log_success "✅ 系统初始化接口正常 (返回200)"
else
    log_error "❌ 系统初始化接口异常"
    echo "Response: $RESPONSE"
fi

# 测试setup状态接口
if curl -s http://localhost:8686/api/v1/setup/status | grep -q '"is_setup"'; then
    log_success "✅ 设置状态接口正常"
else
    log_error "❌ 设置状态接口异常"
fi

echo ""
log_success "🎉 更新完成！"
echo "==============================="
echo "应用信息："
echo "- PID: $APP_PID"
echo "- 端口: 8686"
echo "- 日志: $DEPLOY_DIR/logs/app.log"
echo ""
echo "管理命令："
echo "- 查看日志: tail -f $DEPLOY_DIR/logs/app.log"
echo "- 停止应用: kill $APP_PID"
echo "- 重启应用: $DEPLOY_DIR/deploy.sh"
echo ""
echo "访问地址: http://$(hostname -I | awk '{print $1}'):8686"
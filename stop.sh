#!/bin/bash

# ESemail 停止脚本

APP_NAME="esemail"
DEPLOY_DIR="/opt/ESemail"
APP_PORT=${1:-"8686"}

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

stop_application() {
    log_info "停止 $APP_NAME 应用..."
    
    # 从PID文件停止
    if [ -f "$DEPLOY_DIR/$APP_NAME.pid" ]; then
        PID=$(cat "$DEPLOY_DIR/$APP_NAME.pid")
        if kill -0 $PID 2>/dev/null; then
            log_info "停止进程 $PID"
            kill $PID
            sleep 3
            
            # 如果还在运行，强制杀死
            if kill -0 $PID 2>/dev/null; then
                log_warn "进程仍在运行，强制杀死..."
                kill -9 $PID
            fi
        fi
        rm -f "$DEPLOY_DIR/$APP_NAME.pid"
    fi
    
    # 杀死所有相关进程
    if pgrep -f "$APP_NAME" > /dev/null; then
        log_info "杀死所有 $APP_NAME 进程..."
        pkill -f "$APP_NAME"
        sleep 2
    fi
    
    # 检查端口
    if lsof -Pi :$APP_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        PID=$(lsof -Pi :$APP_PORT -sTCP:LISTEN -t)
        log_warn "端口 $APP_PORT 仍被进程 $PID 占用，强制杀死..."
        kill -9 $PID
    fi
    
    log_success "$APP_NAME 已停止"
}

main() {
    stop_application
    log_success "🛑 应用已完全停止"
}

main "$@"
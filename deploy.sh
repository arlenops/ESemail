#!/bin/bash

# ESemail 自动部署脚本
# 用法: ./deploy.sh [server_ip] [port]

set -e  # 遇到错误立即退出

# 默认参数
SERVER_IP=${1:-"103.233.255.199"}
APP_PORT=${2:-"8686"}
APP_NAME="esemail"
DEPLOY_DIR="/opt/ESemail"
REPO_URL="https://github.com/arlenops/ESemail.git"

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

check_port() {
    log_info "检查端口 $APP_PORT 是否被占用..."
    if lsof -Pi :$APP_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        log_warn "端口 $APP_PORT 被占用，正在停止相关进程..."
        
        # 获取占用端口的进程ID
        PID=$(lsof -Pi :$APP_PORT -sTCP:LISTEN -t)
        if [ ! -z "$PID" ]; then
            log_info "杀死进程 $PID"
            kill -9 $PID
            sleep 2
        fi
        
        # 杀死所有 esemail 进程
        if pgrep -f "$APP_NAME" > /dev/null; then
            log_info "停止所有 $APP_NAME 进程..."
            pkill -f "$APP_NAME" || true
            sleep 3
        fi
        
        # 再次检查端口
        if lsof -Pi :$APP_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
            log_error "无法释放端口 $APP_PORT，请手动处理"
            exit 1
        fi
    fi
    log_success "端口 $APP_PORT 可用"
}

install_dependencies() {
    log_info "检查并安装依赖..."
    
    # 检查 Go 是否已安装
    if ! command -v go &> /dev/null; then
        log_info "安装 Go..."
        wget -q https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin
        rm go1.21.0.linux-amd64.tar.gz
    fi
    
    # 检查 Git 是否已安装
    if ! command -v git &> /dev/null; then
        log_info "安装 Git..."
        sudo apt update && sudo apt install -y git curl
    fi
    
    log_success "依赖检查完成"
}

deploy_code() {
    log_info "开始代码部署..."
    
    # 如果目录存在，先备份
    if [ -d "$DEPLOY_DIR" ]; then
        log_info "备份现有代码..."
        sudo mv "$DEPLOY_DIR" "${DEPLOY_DIR}.backup.$(date +%Y%m%d_%H%M%S)" || true
    fi
    
    # 克隆最新代码
    log_info "克隆代码到 $DEPLOY_DIR"
    sudo git clone $REPO_URL $DEPLOY_DIR
    cd $DEPLOY_DIR
    
    # 设置权限
    sudo chown -R $USER:$USER $DEPLOY_DIR
    
    log_success "代码部署完成"
}

build_application() {
    log_info "编译应用程序..."
    cd $DEPLOY_DIR
    
    # 下载依赖
    log_info "下载 Go 模块依赖..."
    go mod tidy
    
    # 编译
    log_info "编译 $APP_NAME..."
    go build -o $APP_NAME
    
    # 设置执行权限
    chmod +x $APP_NAME
    
    log_success "应用程序编译完成"
}

start_application() {
    log_info "启动应用程序..."
    cd $DEPLOY_DIR
    
    # 创建日志目录
    mkdir -p logs
    
    # 后台启动应用，输出到日志文件
    nohup ./$APP_NAME > logs/app.log 2>&1 &
    APP_PID=$!
    
    # 等待应用启动
    log_info "等待应用启动..."
    sleep 5
    
    # 检查进程是否还在运行
    if ! kill -0 $APP_PID 2>/dev/null; then
        log_error "应用启动失败，查看日志："
        tail -20 logs/app.log
        exit 1
    fi
    
    log_success "应用已启动，PID: $APP_PID"
    echo $APP_PID > $APP_NAME.pid
}

test_deployment() {
    log_info "测试部署结果..."
    
    # 等待服务完全启动
    sleep 3
    
    # 测试健康检查接口
    if curl -s http://localhost:$APP_PORT/api/v1/health > /dev/null; then
        log_success "健康检查接口响应正常"
    else
        log_warn "健康检查接口无响应，尝试setup状态接口..."
        if curl -s http://localhost:$APP_PORT/api/v1/setup/status > /dev/null; then
            log_success "setup状态接口响应正常"
        else
            log_error "应用可能启动失败，请检查日志"
            tail -20 $DEPLOY_DIR/logs/app.log
            exit 1
        fi
    fi
    
    # 测试系统初始化接口
    log_info "测试系统初始化接口..."
    INIT_RESPONSE=$(curl -s -X POST http://localhost:$APP_PORT/api/v1/system/init 2>/dev/null || echo "failed")
    if [ "$INIT_RESPONSE" != "failed" ]; then
        log_success "系统初始化接口响应正常"
    else
        log_warn "系统初始化接口测试失败（这可能是正常的）"
    fi
    
    log_success "部署测试完成"
}

show_status() {
    log_info "部署状态信息："
    echo "=================================="
    echo "应用名称: $APP_NAME"
    echo "部署目录: $DEPLOY_DIR"
    echo "运行端口: $APP_PORT"
    echo "进程ID: $(cat $DEPLOY_DIR/$APP_NAME.pid 2>/dev/null || echo '未知')"
    echo "日志文件: $DEPLOY_DIR/logs/app.log"
    echo "=================================="
    echo ""
    echo "管理命令："
    echo "查看日志: tail -f $DEPLOY_DIR/logs/app.log"
    echo "停止应用: kill \$(cat $DEPLOY_DIR/$APP_NAME.pid)"
    echo "重启应用: cd $DEPLOY_DIR && ./deploy.sh"
    echo ""
    echo "访问地址: http://localhost:$APP_PORT"
    if [ "$SERVER_IP" != "localhost" ] && [ "$SERVER_IP" != "127.0.0.1" ]; then
        echo "远程访问: http://$SERVER_IP:$APP_PORT"
    fi
}

main() {
    log_info "开始 ESemail 自动化部署..."
    log_info "目标服务器: $SERVER_IP"
    log_info "应用端口: $APP_PORT"
    
    check_port
    install_dependencies
    deploy_code
    build_application
    start_application
    test_deployment
    show_status
    
    log_success "🎉 部署完成！"
}

# 捕获中断信号
trap 'log_error "部署被中断"; exit 1' INT TERM

# 执行主函数
main "$@"
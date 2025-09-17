#!/bin/bash

# ESemail 一键部署脚本（仅本地模式）
set -e

deploy_local() {
    echo "🚀 开始本地部署..."

    # 拉取最新代码
    echo "📥 拉取最新代码..."
    if [ -d ".git" ]; then
        git fetch origin
        git reset --hard origin/main
        echo "✅ 代码已更新到最新版本"
    else
        echo "❌ 当前目录不是Git仓库，请先clone项目到本地"
        exit 1
    fi

    # 检查并安装Go
    if ! command -v go &> /dev/null; then
        echo "📦 安装Go..."
        wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        source ~/.bashrc
    fi

    # 检测并停止已运行的服务
    echo "🔍 检测业务端口..."
    PORTS=(8686 25 465 587 993 995)
    for port in "${PORTS[@]}"; do
        PID=$(lsof -ti:$port 2>/dev/null || true)
        if [ ! -z "$PID" ]; then
            echo "⚡ 停止端口 $port 上的进程 $PID"
            kill -9 $PID 2>/dev/null || true
        fi
    done

    # 停止可能的esemail进程
    pkill -f esemail || true
    sleep 2

    # 编译并启动
    echo "🔨 编译项目..."
    go mod tidy
    go build -o esemail

    # 自动加载本地配置文件（如存在）
    if [ -f "config/config.yaml" ]; then
        export ESEMAIL_CONFIG="$(pwd)/config/config.yaml"
        echo "⚙️  使用配置文件: $ESEMAIL_CONFIG"
    fi

    echo "🎯 启动服务..."
    nohup ./esemail > esemail.log 2>&1 &
    
    # 等待健康检查：最多重试10次（约30秒）
    ok=false
    for i in {1..10}; do
        sleep 3
        if curl -s http://localhost:8686/api/v1/health > /dev/null; then
            ok=true
            break
        fi
    done

    if [ "$ok" = true ]; then
        echo "✅ 本地部署成功！"
        echo "📊 访问地址: http://localhost:8686"
        echo "📋 日志文件: $(pwd)/esemail.log"
        tail -f esemail.log
    else
        echo "❌ 服务启动失败，查看日志(最近200行):"
        tail -200 esemail.log
        exit 1
    fi
}

# 主逻辑（仅本地部署）
deploy_local

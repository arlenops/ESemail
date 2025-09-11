#!/bin/bash

# ESemail 一键部署脚本
set -e

SERVER=""
PASSWORD=""
LOCAL_MODE=false

# 解析命令行参数
while [[ $# -gt 0 ]]; do
  case $1 in
    --server)
      SERVER="$2"
      shift 2
      ;;
    --password)
      PASSWORD="$2"
      shift 2
      ;;
    --local)
      LOCAL_MODE=true
      shift
      ;;
    *)
      echo "用法: $0 [--local | --server IP --password PASSWORD]"
      echo "  --local: 本地部署模式"
      echo "  --server: 远程服务器IP"
      echo "  --password: 远程服务器密码"
      exit 1
      ;;
  esac
done

# 本地部署函数
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
    
    # 清空旧数据
    echo "🗑️ 清空旧数据..."
    if [ -f "scripts/reset_data.sh" ]; then
        chmod +x scripts/reset_data.sh
        bash scripts/reset_data.sh
        echo "✅ 数据已清空"
    else
        echo "⚠️ 未找到数据重置脚本，手动清理数据目录..."
        rm -rf data/*.json data/certs/ data/mail/ data/keys/
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
    
    echo "🎯 启动服务..."
    nohup ./esemail > esemail.log 2>&1 &
    sleep 3
    
    # 验证启动
    if curl -s http://localhost:8686/api/v1/health > /dev/null; then
        echo "✅ 本地部署成功！"
        echo "📊 访问地址: http://localhost:8686"
        echo "📋 日志文件: $(pwd)/esemail.log"
        tail -f esemail.log
    else
        echo "❌ 服务启动失败，查看日志:"
        tail -20 esemail.log
    fi
}

# 远程部署函数
deploy_remote() {
    if [ -z "$SERVER" ] || [ -z "$PASSWORD" ]; then
        echo "❌ 远程部署需要提供服务器IP和密码"
        exit 1
    fi
    
    echo "🌐 开始远程部署到 $SERVER..."
    
    # 推送代码到GitHub
    echo "📤 推送代码到GitHub..."
    git add -A
    git commit -m "部署前代码同步 $(date)" || true
    git push origin main
    
    # 远程执行部署
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no root@$SERVER << 'EOF'
set -e

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

# 检查并安装依赖
if ! command -v go &> /dev/null; then
    echo "📦 安装Go..."
    wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
fi

if ! command -v git &> /dev/null; then
    echo "📦 安装Git..."
    apt update && apt install -y git
fi

export PATH=$PATH:/usr/local/go/bin

# 彻底清理旧代码
if [ -d "ESemail" ]; then
    echo "🧹 清理旧代码目录..."
    rm -rf ESemail
fi

# 重新克隆最新代码
echo "📥 克隆最新代码..."
git clone https://github.com/arlenops/ESemail.git
cd ESemail

# 清空旧数据
echo "🗑️ 清空旧数据..."
if [ -f "scripts/reset_data.sh" ]; then
    chmod +x scripts/reset_data.sh
    bash scripts/reset_data.sh
    echo "✅ 数据已清空"
else
    echo "⚠️ 未找到数据重置脚本，手动清理数据目录..."
    rm -rf data/*.json data/certs/ data/mail/ data/keys/
fi

# 创建环境标识文件
echo "ENVIRONMENT=production" > .env

# 检查是否有必要的修复代码
echo "🔍 验证关键修复是否存在..."
if ! grep -q "开发环境：模拟重启服务" internal/service/security.go; then
    echo "❌ 远程代码缺少关键修复！请确保推送了最新修复代码"
    exit 1
fi

# 编译并启动
echo "🔨 编译项目..."
go mod tidy
go build -o esemail

echo "🎯 启动服务..."
nohup ./esemail > esemail.log 2>&1 &
sleep 5

# 验证部署
if curl -s http://localhost:8686/api/v1/health > /dev/null; then
    echo "✅ 远程部署成功！"
    echo "📊 服务地址: http://$HOSTNAME:8686"
    echo "📋 日志位置: $(pwd)/esemail.log"
    echo "🔧 测试系统初始化..."
    INIT_TEST=$(curl -s -X POST http://localhost:8686/api/v1/system/init \
                -H "Content-Type: application/json" \
                -d '{"domain": "remote.test", "admin_email": "admin@remote.test", "admin_password": "test123456", "smtp_host": "localhost", "smtp_port": 587}' \
                | grep -o '"success":[^,]*' || echo '"success":false')
    if echo "$INIT_TEST" | grep -q '"success":true'; then
        echo "✅ 系统初始化测试通过"
    else
        echo "❌ 系统初始化测试失败"
        echo "📋 查看错误日志:"
        tail -20 esemail.log
        exit 1
    fi
else
    echo "❌ 服务启动失败，查看日志:"
    tail -20 esemail.log
    exit 1
fi
EOF
    
    echo "🎉 远程部署完成！"
    echo "🌍 访问地址: http://$SERVER:8686"
}

# 主逻辑
if [ "$LOCAL_MODE" = true ]; then
    deploy_local
elif [ ! -z "$SERVER" ]; then
    deploy_remote
else
    echo "❓ 请选择部署模式:"
    echo "   本地部署: $0 --local"
    echo "   远程部署: $0 --server YOUR_IP --password YOUR_PASSWORD"
fi
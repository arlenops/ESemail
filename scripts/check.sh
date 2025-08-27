#!/bin/bash

echo "检查 ESemail 代码质量..."

echo "1. 检查 Go 代码语法..."
if command -v go >/dev/null 2>&1; then
    echo "   - 运行 go vet..."
    go vet ./...
    
    echo "   - 运行 go fmt 检查..."
    if [ "$(gofmt -l . | wc -l)" -eq 0 ]; then
        echo "   ✓ 代码格式正确"
    else
        echo "   ✗ 代码格式需要修正"
        gofmt -l .
    fi
    
    echo "   - 检查编译..."
    export GOPROXY=https://goproxy.cn,direct
    if go build -o /tmp/esemail main.go; then
        echo "   ✓ 代码编译成功"
        rm -f /tmp/esemail
    else
        echo "   ✗ 代码编译失败"
        exit 1
    fi
else
    echo "   ⚠ Go 命令未找到，跳过语法检查"
fi

echo ""
echo "2. 检查项目结构..."

required_files=(
    "main.go"
    "go.mod" 
    "README.md"
    "DEPLOYMENT.md"
    "internal/config/config.go"
    "internal/api/router.go"
    "internal/service/health.go"
    "internal/service/system.go"
    "internal/service/setup.go"
    "web/templates/dashboard.html"
    "web/templates/setup.html"
    "web/static/js/dashboard.js"
    "web/static/css/dashboard.css"
    "scripts/deploy-server.sh"
)

missing_files=0
for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "   ✓ $file"
    else
        echo "   ✗ $file (缺失)"
        missing_files=$((missing_files + 1))
    fi
done

if [ $missing_files -eq 0 ]; then
    echo "   ✓ 所有必需文件都存在"
else
    echo "   ✗ 有 $missing_files 个文件缺失"
fi

echo ""
echo "3. 检查Web资源..."

if [ -d "web/static" ] && [ -d "web/templates" ]; then
    echo "   ✓ Web静态资源目录存在"
    
    if [ -f "web/static/css/bootstrap.min.css" ]; then
        echo "   ✓ Bootstrap CSS存在"
    else
        echo "   ⚠ Bootstrap CSS缺失"
    fi
    
    if [ -f "web/static/js/bootstrap.bundle.min.js" ]; then
        echo "   ✓ Bootstrap JS存在"
    else
        echo "   ⚠ Bootstrap JS缺失"
    fi
else
    echo "   ✗ Web静态资源目录缺失"
fi

echo ""
echo "4. 检查部署脚本..."

if [ -f "scripts/deploy-server.sh" ] && [ -x "scripts/deploy-server.sh" ]; then
    echo "   ✓ 部署脚本存在且可执行"
else
    echo "   ✗ 部署脚本缺失或不可执行"
fi

echo ""
echo "检查完成！"
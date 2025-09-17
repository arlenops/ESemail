#!/bin/bash

# SMTP 快速测试脚本
# 使用 curl 和 telnet 测试 SMTP 功能

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置
SMTP_HOST="mail.caiji.wiki"
SMTP_USER="yiqiu@caiji.wiki"
SMTP_PASS="123456789"
TEST_EMAIL="yiqiu@caiji.wiki"

echo_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

echo_error() {
    echo -e "${RED}✗ $1${NC}"
}

echo_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

echo_header() {
    echo -e "\n${BLUE}================================================${NC}"
    echo -e "${BLUE} $1 ${NC}"
    echo -e "${BLUE}================================================${NC}"
}

# 检查依赖
check_dependencies() {
    echo_header "检查依赖工具"

    local missing_deps=()

    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    else
        echo_success "curl 已安装"
    fi

    if ! command -v telnet &> /dev/null; then
        missing_deps+=("telnet")
    else
        echo_success "telnet 已安装"
    fi

    if ! command -v openssl &> /dev/null; then
        missing_deps+=("openssl")
    else
        echo_success "openssl 已安装"
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo_error "缺少依赖: ${missing_deps[*]}"
        echo_info "请安装: sudo apt-get install ${missing_deps[*]}"
        exit 1
    fi
}

# 测试DNS解析
test_dns() {
    echo_header "DNS 解析测试"

    if nslookup "$SMTP_HOST" > /dev/null 2>&1; then
        local ip=$(nslookup "$SMTP_HOST" | grep -A 1 "Name:" | tail -n 1 | awk '{print $2}')
        echo_success "DNS解析成功: $SMTP_HOST -> $ip"
    else
        echo_error "DNS解析失败: $SMTP_HOST"
        return 1
    fi
}

# 测试端口连通性
test_port() {
    local port=$1
    local description=$2

    echo_info "测试端口 $port ($description)"

    if timeout 5 bash -c "</dev/tcp/$SMTP_HOST/$port" 2>/dev/null; then
        echo_success "端口 $port 连接成功"
        return 0
    else
        echo_error "端口 $port 连接失败"
        return 1
    fi
}

# 测试SMTP响应
test_smtp_response() {
    local port=$1
    local use_ssl=$2

    echo_info "测试SMTP服务响应 (端口 $port)"

    if [ "$use_ssl" = "true" ]; then
        # SSL连接
        response=$(echo "QUIT" | openssl s_client -connect "$SMTP_HOST:$port" -quiet 2>/dev/null | head -1)
    else
        # 普通连接
        response=$(echo "QUIT" | telnet "$SMTP_HOST" "$port" 2>/dev/null | head -1)
    fi

    if [[ "$response" == *"220"* ]]; then
        echo_success "SMTP服务响应正常: $response"
        return 0
    else
        echo_error "SMTP服务响应异常: $response"
        return 1
    fi
}

# 使用curl测试SMTP发送
test_smtp_send() {
    local port=$1
    local ssl_option=$2
    local protocol_name=$3

    echo_info "测试邮件发送 ($protocol_name)"

    # 创建临时邮件内容
    local mail_content=$(cat << EOF
From: $SMTP_USER
To: $TEST_EMAIL
Subject: SMTP测试邮件 - $protocol_name - $(date)

这是一封SMTP功能测试邮件

测试信息:
- 发送方式: $protocol_name
- 发送时间: $(date)
- 发件人: $SMTP_USER
- 收件人: $TEST_EMAIL

如果您收到这封邮件，说明SMTP功能工作正常！

---
ESemail SMTP 测试脚本
EOF
)

    # 使用curl发送邮件
    if curl $ssl_option \
        --url "smtp://$SMTP_HOST:$port" \
        --user "$SMTP_USER:$SMTP_PASS" \
        --mail-from "$SMTP_USER" \
        --mail-rcpt "$TEST_EMAIL" \
        --upload-file <(echo "$mail_content") \
        --silent \
        --show-error 2>/dev/null; then
        echo_success "邮件发送成功 ($protocol_name)"
        return 0
    else
        echo_error "邮件发送失败 ($protocol_name)"
        return 1
    fi
}

# 主测试函数
main() {
    echo_header "ESemail SMTP 功能快速验证"
    echo_info "测试服务器: $SMTP_HOST"
    echo_info "测试账户: $SMTP_USER"
    echo_info "测试时间: $(date)"

    # 检查依赖
    check_dependencies

    # DNS测试
    if ! test_dns; then
        echo_error "DNS测试失败，无法继续"
        exit 1
    fi

    echo_header "端口连通性测试"

    # 测试各端口
    local ports_status=()

    if test_port 25 "SMTP标准"; then
        ports_status[25]=1
    else
        ports_status[25]=0
    fi

    if test_port 587 "SMTP提交/STARTTLS"; then
        ports_status[587]=1
    else
        ports_status[587]=0
    fi

    if test_port 465 "SMTPS/SSL"; then
        ports_status[465]=1
    else
        ports_status[465]=0
    fi

    echo_header "SMTP 服务响应测试"

    # 测试SMTP响应
    if [ "${ports_status[25]}" = "1" ]; then
        test_smtp_response 25 false
    fi

    if [ "${ports_status[587]}" = "1" ]; then
        test_smtp_response 587 false
    fi

    if [ "${ports_status[465]}" = "1" ]; then
        test_smtp_response 465 true
    fi

    echo_header "邮件发送功能测试"

    local send_success=0

    # 测试邮件发送
    if [ "${ports_status[465]}" = "1" ]; then
        if test_smtp_send 465 "--ssl" "SMTPS (SSL)"; then
            send_success=$((send_success + 1))
        fi
    fi

    if [ "${ports_status[587]}" = "1" ]; then
        if test_smtp_send 587 "--ssl" "SMTP (STARTTLS)"; then
            send_success=$((send_success + 1))
        fi
    fi

    if [ "${ports_status[25]}" = "1" ]; then
        if test_smtp_send 25 "" "SMTP (明文)"; then
            send_success=$((send_success + 1))
        fi
    fi

    # 显示结果汇总
    echo_header "测试结果汇总"

    if [ $send_success -gt 0 ]; then
        echo_success "SMTP功能测试通过！成功发送 $send_success 封测试邮件"

        echo_header "推荐的WordPress配置"
        if [ "${ports_status[465]}" = "1" ]; then
            echo_info "推荐使用 SSL 连接 (最安全):"
            echo "  SMTP主机: $SMTP_HOST"
            echo "  端口: 465"
            echo "  加密: SSL"
            echo "  用户名: $SMTP_USER"
        elif [ "${ports_status[587]}" = "1" ]; then
            echo_info "推荐使用 TLS 连接:"
            echo "  SMTP主机: $SMTP_HOST"
            echo "  端口: 587"
            echo "  加密: TLS/STARTTLS"
            echo "  用户名: $SMTP_USER"
        fi

        echo_info "请检查收件箱查看测试邮件"

    else
        echo_error "所有SMTP发送测试都失败了"
        echo_info "可能的原因:"
        echo "  1. 用户名或密码错误"
        echo "  2. 服务器配置问题"
        echo "  3. SSL证书问题"
        echo "  4. 防火墙限制"
        exit 1
    fi
}

# 运行主函数
main "$@"
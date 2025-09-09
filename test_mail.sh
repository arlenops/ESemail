#!/bin/bash

# 邮件发送测试脚本
echo "=== ESemail 邮件收发功能测试 ==="
echo

# 测试SMTP服务器连接
echo "1. 测试SMTP服务器连接..."
timeout 5 bash -c "(echo 'EHLO test.com'; echo 'QUIT') | nc localhost 2525" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "✅ SMTP服务器连接成功"
else
    echo "❌ SMTP服务器连接失败"
fi
echo

# 测试IMAP服务器连接  
echo "2. 测试IMAP服务器连接..."
timeout 5 bash -c "echo '* OK IMAP4rev1 Service Ready' | nc localhost 1143" 2>/dev/null >/dev/null
if [ $? -eq 0 ]; then
    echo "✅ IMAP服务器连接成功"
else
    echo "❌ IMAP服务器连接失败"
fi
echo

# 测试Web API状态
echo "3. 测试Web API..."
API_STATUS=$(curl -s -w "%{http_code}" http://localhost:8687/api/v1/setup/status -o /dev/null)
if [ "$API_STATUS" = "200" ]; then
    echo "✅ Web API工作正常"
else
    echo "❌ Web API异常 (HTTP $API_STATUS)"
fi
echo

# 测试邮件服务状态
echo "4. 检查服务状态..."
setup_status=$(curl -s http://localhost:8687/api/v1/setup/status | grep -o '"is_setup":[^,]*' | cut -d: -f2)
if [ "$setup_status" = "true" ]; then
    echo "✅ 系统已初始化"
else
    echo "⚠️ 系统未初始化"
fi
echo

# 测试使用netcat模拟SMTP发送
echo "5. 模拟SMTP邮件发送..."
cat << 'EOF' > /tmp/smtp_test.txt
HELO test.com
MAIL FROM:<admin@example.com>
RCPT TO:<test@example.com>  
DATA
Subject: Test Email from ESemail
From: admin@example.com
To: test@example.com

This is a test email from ESemail server.
Test timestamp: $(date)
.
QUIT
EOF

timeout 10 bash -c "cat /tmp/smtp_test.txt | nc localhost 2525" > /tmp/smtp_result.txt 2>&1
if grep -q "250" /tmp/smtp_result.txt; then
    echo "✅ SMTP邮件发送测试成功"
    echo "📧 邮件已进入处理队列"
else
    echo "❌ SMTP邮件发送测试失败"
    echo "--- SMTP响应 ---"
    cat /tmp/smtp_result.txt
fi
echo

# 检查邮件存储
echo "6. 检查邮件存储..."
if [ -d "./data/mail" ]; then
    mail_count=$(find ./data/mail -name "*.json" 2>/dev/null | wc -l)
    echo "📁 找到 $mail_count 个邮件文件"
    
    if [ $mail_count -gt 0 ]; then
        echo "✅ 邮件存储系统工作正常"
        echo "--- 最近的邮件文件 ---"
        find ./data/mail -name "*.json" -exec ls -la {} \; 2>/dev/null | head -3
    else
        echo "⚠️ 暂无邮件存储"
    fi
else
    echo "⚠️ 邮件存储目录不存在"
fi
echo

# 清理临时文件
rm -f /tmp/smtp_test.txt /tmp/smtp_result.txt

echo "=== 测试完成 ==="
echo "📊 总结:"
echo "- SMTP服务器: 运行在端口 2525"
echo "- IMAP服务器: 运行在端口 1143"  
echo "- Web管理界面: http://localhost:8687"
echo "- 管理员账号: admin / vTIupqGrSBip"
echo
echo "💡 提示:"
echo "1. 可以使用邮件客户端连接测试 (SMTP: localhost:2525, IMAP: localhost:1143)"
echo "2. Web界面提供邮件管理功能"
echo "3. 系统支持本地域名投递和外部邮件转发"
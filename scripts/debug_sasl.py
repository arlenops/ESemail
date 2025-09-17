#!/usr/bin/env python3
"""
SASL配置诊断脚本
用于调试ESemail的SASL认证配置问题

使用方法:
python3 debug_sasl.py
"""

import subprocess
import sys
import socket
import time
from datetime import datetime

def print_header(title):
    """打印带颜色的标题"""
    print(f"\n{'='*60}")
    print(f"{title.center(60)}")
    print(f"{'='*60}")

def print_info(message):
    """打印信息消息"""
    print(f"ℹ {message}")

def print_success(message):
    """打印成功消息"""
    print(f"✓ {message}")

def print_error(message):
    """打印错误消息"""
    print(f"✗ {message}")

def run_command(cmd):
    """运行命令并返回输出"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)

def test_smtp_ehlo():
    """测试SMTP EHLO响应"""
    print_header("SMTP EHLO响应测试")

    try:
        # 连接到SMTP服务器
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('mail.caiji.wiki', 587))

        # 接收欢迎消息
        welcome = sock.recv(1024).decode().strip()
        print_success(f"连接成功: {welcome}")

        # 发送EHLO命令
        sock.send(b'EHLO test.localhost\r\n')
        time.sleep(0.5)

        response = sock.recv(1024).decode().strip()
        print_info("EHLO响应:")
        for line in response.split('\n'):
            line = line.strip()
            if line:
                if 'AUTH' in line:
                    print_success(f"  {line}")
                else:
                    print(f"  {line}")

        # 检查是否包含AUTH
        if 'AUTH' in response:
            print_success("✓ 发现AUTH扩展 - SASL认证已启用")
            return True
        else:
            print_error("✗ 未发现AUTH扩展 - SASL认证未启用")
            return False

        sock.send(b'QUIT\r\n')
        sock.close()

    except Exception as e:
        print_error(f"EHLO测试失败: {e}")
        return False

def check_postfix_sasl_config():
    """检查Postfix SASL配置"""
    print_header("Postfix SASL配置检查")

    # 检查main.cf中的SASL配置
    code, output, error = run_command("postconf | grep sasl")
    if code == 0 and output:
        print_success("发现SASL配置:")
        for line in output.split('\n'):
            if line.strip():
                print(f"  {line}")
    else:
        print_error("未发现SASL配置")

    # 检查master.cf中的submission端口配置
    code, output, error = run_command("grep -A 10 'submission' /etc/postfix/master.cf")
    if code == 0 and output:
        print_success("Submission端口配置:")
        for line in output.split('\n')[:10]:
            if line.strip():
                print(f"  {line}")
    else:
        print_error("未找到submission端口配置")

def check_dovecot_sasl():
    """检查Dovecot SASL配置"""
    print_header("Dovecot SASL配置检查")

    # 检查Dovecot认证配置
    code, output, error = run_command("doveconf auth_mechanisms")
    if code == 0:
        print_success(f"Dovecot认证机制: {output.strip()}")
    else:
        print_error("无法获取Dovecot认证机制配置")

    # 检查Dovecot服务状态
    code, output, error = run_command("systemctl is-active dovecot")
    if code == 0 and 'active' in output:
        print_success("Dovecot服务运行正常")
    else:
        print_error(f"Dovecot服务状态异常: {output}")

def check_sasl_auth_socket():
    """检查SASL认证套接字"""
    print_header("SASL认证套接字检查")

    # 检查Postfix chroot环境中的认证套接字
    paths_to_check = [
        "/var/spool/postfix/private/auth",
        "/var/run/dovecot/auth-postfix",
        "/var/spool/postfix/private/dovecot-auth"
    ]

    for path in paths_to_check:
        code, output, error = run_command(f"ls -la {path}")
        if code == 0:
            print_success(f"找到认证套接字: {path}")
            print(f"  {output.strip()}")
        else:
            print_info(f"未找到: {path}")

def test_manual_auth():
    """尝试手动认证测试"""
    print_header("手动认证测试")

    # 生成base64编码的认证字符串
    import base64
    auth_plain = f"\0yiqiu@caiji.wiki\0123456789"
    auth_b64 = base64.b64encode(auth_plain.encode()).decode()

    print_info(f"认证字符串 (base64): {auth_b64}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('mail.caiji.wiki', 587))

        # 接收欢迎消息
        sock.recv(1024)

        # EHLO
        sock.send(b'EHLO test.localhost\r\n')
        response = sock.recv(1024).decode()

        if 'AUTH' not in response:
            print_error("服务器不支持AUTH命令")
            sock.close()
            return False

        # STARTTLS
        sock.send(b'STARTTLS\r\n')
        tls_response = sock.recv(1024).decode().strip()
        print_info(f"STARTTLS响应: {tls_response}")

        sock.close()

    except Exception as e:
        print_error(f"手动认证测试失败: {e}")
        return False

def generate_diagnostic_report():
    """生成诊断报告"""
    print_header("SASL诊断报告")

    print(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"目标服务器: mail.caiji.wiki")

    # 运行所有检查
    smtp_auth_ok = test_smtp_ehlo()
    check_postfix_sasl_config()
    check_dovecot_sasl()
    check_sasl_auth_socket()
    test_manual_auth()

    print_header("诊断结论")

    if smtp_auth_ok:
        print_success("SASL认证配置正常，可以进行SMTP认证")
    else:
        print_error("SASL认证配置有问题，需要进一步调试")
        print_info("可能的解决方案:")
        print("  1. 重启Postfix服务: sudo systemctl restart postfix")
        print("  2. 重启Dovecot服务: sudo systemctl restart dovecot")
        print("  3. 检查Postfix和Dovecot的认证套接字连接")
        print("  4. 验证/etc/postfix/main.cf中的SASL配置")

def main():
    """主函数"""
    print_header("ESemail SASL配置诊断工具")
    print_info("此工具将诊断SMTP SASL认证配置问题")

    generate_diagnostic_report()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n测试被用户中断")
        sys.exit(1)
    except Exception as e:
        print_error(f"脚本执行出错: {e}")
        sys.exit(1)
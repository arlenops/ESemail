#!/usr/bin/env python3
"""
SMTP 功能验证脚本
用于测试 ESemail 服务器的 SMTP 功能是否正常工作

使用方法:
python3 test_smtp.py

环境要求:
pip install colorama
"""

import smtplib
import ssl
import socket
import sys
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

try:
    from colorama import init, Fore, Style
    init()
except ImportError:
    print("请安装 colorama: pip install colorama")
    sys.exit(1)

# SMTP 服务器配置
SMTP_CONFIGS = {
    "SSL": {
        "host": "mail.caiji.wiki",
        "port": 465,
        "use_tls": False,
        "use_ssl": True,
        "description": "SMTPS (端口465，直接SSL连接)"
    },
    "TLS": {
        "host": "mail.caiji.wiki",
        "port": 587,
        "use_tls": True,
        "use_ssl": False,
        "description": "SMTP提交 (端口587，STARTTLS)"
    },
    "PLAIN": {
        "host": "mail.caiji.wiki",
        "port": 25,
        "use_tls": False,
        "use_ssl": False,
        "description": "SMTP标准 (端口25，明文)"
    }
}

# 邮件账户配置
EMAIL_CONFIG = {
    "username": "yiqiu@caiji.wiki",
    "password": "123456789",
    "from_email": "yiqiu@caiji.wiki",
    "to_email": "yiqiu@caiji.wiki"  # 发送给自己进行测试
}

def print_header(title):
    """打印带颜色的标题"""
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{title.center(60)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

def print_success(message):
    """打印成功消息"""
    print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")

def print_error(message):
    """打印错误消息"""
    print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")

def print_info(message):
    """打印信息消息"""
    print(f"{Fore.YELLOW}ℹ {message}{Style.RESET_ALL}")

def test_port_connectivity(host, port):
    """测试端口连通性"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        return False

def test_smtp_connection(config_name, config):
    """测试SMTP连接"""
    print_info(f"测试 {config['description']}")

    # 测试端口连通性
    if not test_port_connectivity(config['host'], config['port']):
        print_error(f"端口 {config['port']} 无法连接")
        return False

    print_success(f"端口 {config['port']} 连接成功")

    try:
        # 创建SMTP连接
        if config['use_ssl']:
            # SSL连接 (465端口)
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(config['host'], config['port'], context=context)
        else:
            # 普通连接
            server = smtplib.SMTP(config['host'], config['port'])

            if config['use_tls']:
                # 启用STARTTLS (587端口)
                server.starttls()

        print_success("SMTP服务器连接成功")

        # 获取服务器信息
        server.noop()
        print_success("服务器响应正常")

        # 尝试认证
        try:
            server.login(EMAIL_CONFIG['username'], EMAIL_CONFIG['password'])
            print_success("SMTP认证成功")

            # 发送测试邮件
            success = send_test_email(server, config_name)

            server.quit()
            return success

        except smtplib.SMTPAuthenticationError as e:
            print_error(f"SMTP认证失败: {e}")
            server.quit()
            return False

    except smtplib.SMTPConnectError as e:
        print_error(f"SMTP连接失败: {e}")
        return False
    except smtplib.SMTPException as e:
        print_error(f"SMTP错误: {e}")
        return False
    except Exception as e:
        print_error(f"未知错误: {e}")
        return False

def send_test_email(server, method):
    """发送测试邮件"""
    try:
        # 创建邮件
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG['from_email']
        msg['To'] = EMAIL_CONFIG['to_email']
        msg['Subject'] = f"SMTP测试邮件 - {method} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        # 邮件正文
        body = f"""
这是一封SMTP功能测试邮件

测试信息:
- 发送方式: {method}
- 发送时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- 发件人: {EMAIL_CONFIG['from_email']}
- 收件人: {EMAIL_CONFIG['to_email']}
- 测试状态: 成功

如果您收到这封邮件，说明SMTP功能工作正常！

---
ESemail SMTP 测试脚本
        """

        msg.attach(MIMEText(body, 'plain', 'utf-8'))

        # 发送邮件
        server.send_message(msg)
        print_success(f"测试邮件发送成功 ({method})")
        return True

    except Exception as e:
        print_error(f"邮件发送失败: {e}")
        return False

def test_dns_resolution():
    """测试DNS解析"""
    print_info("测试DNS解析")
    try:
        import socket
        ip = socket.gethostbyname("mail.caiji.wiki")
        print_success(f"DNS解析成功: mail.caiji.wiki -> {ip}")
        return True
    except Exception as e:
        print_error(f"DNS解析失败: {e}")
        return False

def main():
    """主函数"""
    print_header("ESemail SMTP 功能验证脚本")

    print_info(f"测试目标服务器: {SMTP_CONFIGS['SSL']['host']}")
    print_info(f"测试账户: {EMAIL_CONFIG['username']}")
    print_info(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 测试DNS解析
    print_header("DNS 解析测试")
    if not test_dns_resolution():
        print_error("DNS解析失败，无法继续测试")
        return False

    # 测试各种SMTP配置
    results = {}

    for config_name, config in SMTP_CONFIGS.items():
        print_header(f"测试 {config_name} 连接")
        results[config_name] = test_smtp_connection(config_name, config)
        time.sleep(1)  # 避免过快连接

    # 显示测试结果汇总
    print_header("测试结果汇总")

    success_count = 0
    for config_name, success in results.items():
        config = SMTP_CONFIGS[config_name]
        if success:
            print_success(f"{config_name} ({config['description']}) - 测试通过")
            success_count += 1
        else:
            print_error(f"{config_name} ({config['description']}) - 测试失败")

    print(f"\n{Fore.CYAN}总结: {success_count}/{len(results)} 项测试通过{Style.RESET_ALL}")

    if success_count > 0:
        print_success("SMTP服务器至少有一种连接方式可用")

        # 推荐配置
        print_header("推荐的WordPress配置")
        if results.get('SSL'):
            print_info("推荐使用 SSL 连接 (最安全):")
            print(f"  SMTP主机: mail.caiji.wiki")
            print(f"  端口: 465")
            print(f"  加密: SSL")
            print(f"  用户名: yiqiu@caiji.wiki")
            print(f"  密码: [您的密码]")
        elif results.get('TLS'):
            print_info("推荐使用 TLS 连接:")
            print(f"  SMTP主机: mail.caiji.wiki")
            print(f"  端口: 587")
            print(f"  加密: TLS/STARTTLS")
            print(f"  用户名: yiqiu@caiji.wiki")
            print(f"  密码: [您的密码]")
    else:
        print_error("所有SMTP连接测试都失败了")
        print_info("可能的原因:")
        print("  1. 服务器未启动或配置错误")
        print("  2. 防火墙阻止了SMTP端口")
        print("  3. 用户名或密码错误")
        print("  4. SSL证书配置问题")

    return success_count > 0

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}测试被用户中断{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print_error(f"脚本执行出错: {e}")
        sys.exit(1)
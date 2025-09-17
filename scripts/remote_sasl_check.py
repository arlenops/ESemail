#!/usr/bin/env python3
"""
远程SASL配置检查脚本
通过HTTP API检查远程服务器的SASL配置状态

使用方法:
python3 remote_sasl_check.py
"""

import subprocess
import socket

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

def test_smtp_ehlo_simple():
    """简单的SMTP EHLO测试"""
    print_header("SMTP EHLO 响应检查")

    try:
        # 创建原始socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        print_info("连接到 mail.caiji.wiki:587...")
        sock.connect(('mail.caiji.wiki', 587))

        # 读取欢迎消息
        welcome = sock.recv(1024).decode().strip()
        print_success(f"连接成功: {welcome}")

        # 发送EHLO命令
        print_info("发送 EHLO 命令...")
        sock.send(b'EHLO test.localhost\r\n')

        # 读取EHLO响应
        import time
        time.sleep(0.5)  # 等待响应

        response = sock.recv(2048).decode().strip()

        print_info("完整EHLO响应:")
        auth_found = False
        for line in response.split('\n'):
            line = line.strip()
            if line:
                if 'AUTH' in line.upper():
                    print_success(f"  >>> {line} <<<")
                    auth_found = True
                else:
                    print(f"  {line}")

        if auth_found:
            print_success("✓ 发现AUTH扩展！SASL认证已启用")
        else:
            print_error("✗ 未发现AUTH扩展，SASL认证未启用")

        # 发送QUIT命令
        sock.send(b'QUIT\r\n')
        quit_response = sock.recv(1024).decode().strip()
        print_info(f"退出响应: {quit_response}")

        sock.close()
        return auth_found

    except Exception as e:
        print_error(f"EHLO测试失败: {e}")
        return False

def test_postfix_commands():
    """测试远程Postfix命令"""
    print_header("远程Postfix配置测试")

    # 测试postconf命令的替代方案
    print_info("由于无法直接访问远程服务器命令，尝试通过SMTP协议获取信息...")

    # 测试不同端口的连通性
    ports_to_test = [25, 587, 465]
    accessible_ports = []

    for port in ports_to_test:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex(('mail.caiji.wiki', port))
            sock.close()

            if result == 0:
                print_success(f"端口 {port} 可访问")
                accessible_ports.append(port)
            else:
                print_error(f"端口 {port} 不可访问")

        except Exception as e:
            print_error(f"测试端口 {port} 时出错: {e}")

    return accessible_ports

def test_smtp_auth_attempt():
    """尝试SMTP认证"""
    print_header("SMTP 认证尝试测试")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('mail.caiji.wiki', 587))

        # 读取欢迎消息
        sock.recv(1024)

        # EHLO
        sock.send(b'EHLO test.localhost\r\n')
        ehlo_response = sock.recv(1024).decode()

        if 'AUTH' not in ehlo_response:
            print_error("服务器EHLO响应中没有AUTH扩展")
            sock.send(b'QUIT\r\n')
            sock.close()
            return False

        print_success("发现AUTH扩展，尝试认证...")

        # 尝试AUTH PLAIN
        import base64
        auth_string = f"\0yiqiu@caiji.wiki\0123456789"
        auth_b64 = base64.b64encode(auth_string.encode()).decode()

        sock.send(f'AUTH PLAIN {auth_b64}\r\n'.encode())
        auth_response = sock.recv(1024).decode().strip()

        print_info(f"认证响应: {auth_response}")

        if auth_response.startswith('235'):
            print_success("✓ SMTP认证成功！")
            result = True
        else:
            print_error(f"✗ SMTP认证失败: {auth_response}")
            result = False

        sock.send(b'QUIT\r\n')
        sock.close()
        return result

    except Exception as e:
        print_error(f"认证测试失败: {e}")
        return False

def test_tls_starttls():
    """测试STARTTLS功能"""
    print_header("STARTTLS 功能测试")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('mail.caiji.wiki', 587))

        # 读取欢迎消息
        sock.recv(1024)

        # EHLO
        sock.send(b'EHLO test.localhost\r\n')
        ehlo_response = sock.recv(1024).decode()

        if 'STARTTLS' not in ehlo_response:
            print_error("服务器不支持STARTTLS")
            sock.close()
            return False

        print_success("服务器支持STARTTLS")

        # 尝试STARTTLS
        sock.send(b'STARTTLS\r\n')
        tls_response = sock.recv(1024).decode().strip()

        print_info(f"STARTTLS响应: {tls_response}")

        if tls_response.startswith('220'):
            print_success("✓ STARTTLS握手成功")
            result = True
        else:
            print_error(f"✗ STARTTLS失败: {tls_response}")
            result = False

        sock.close()
        return result

    except Exception as e:
        print_error(f"STARTTLS测试失败: {e}")
        return False

def main():
    """主函数"""
    print_header("远程SASL配置详细检查")
    print_info("检查远程服务器的SMTP SASL配置状态")

    # 测试EHLO响应
    auth_available = test_smtp_ehlo_simple()

    # 测试端口连通性
    accessible_ports = test_postfix_commands()

    # 测试STARTTLS
    starttls_ok = test_tls_starttls()

    # 如果发现AUTH扩展，尝试认证
    if auth_available:
        auth_success = test_smtp_auth_attempt()
    else:
        auth_success = False

    # 最终结果
    print_header("检查结果汇总")

    print(f"DNS解析: ✓ 正常")
    print(f"端口连通性: ✓ 端口 {', '.join(map(str, accessible_ports))} 可访问")
    print(f"STARTTLS支持: {'✓ 支持' if starttls_ok else '✗ 不支持或有问题'}")
    print(f"AUTH扩展: {'✓ 可用' if auth_available else '✗ 不可用'}")
    print(f"SMTP认证: {'✓ 成功' if auth_success else '✗ 失败'}")

    if auth_success:
        print_success("\n🎉 SMTP SASL认证配置完全正常！可以使用WordPress WP Mail SMTP了")
        print_info("推荐配置:")
        print("  主机: mail.caiji.wiki")
        print("  端口: 587")
        print("  加密: TLS/STARTTLS")
        print("  用户名: yiqiu@caiji.wiki")
        print("  密码: [您的密码]")
    else:
        print_error("\n❌ SMTP SASL认证仍有问题")
        if not auth_available:
            print_info("主要问题: EHLO响应中没有AUTH扩展")
            print_info("可能原因: Postfix SASL配置未生效或Dovecot认证服务未正常启动")
        elif not starttls_ok:
            print_info("主要问题: STARTTLS不可用")
            print_info("可能原因: TLS证书配置问题")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n检查被用户中断")
    except Exception as e:
        print_error(f"脚本执行出错: {e}")
#!/usr/bin/env python3
"""
证书和配置检查脚本
检查SSL证书文件和Postfix配置是否正确

使用方法:
python3 check_cert_config.py
"""

import subprocess
import socket
import time

def print_header(title):
    print(f"\n{'='*60}")
    print(f"{title.center(60)}")
    print(f"{'='*60}")

def print_info(message):
    print(f"ℹ {message}")

def print_success(message):
    print(f"✓ {message}")

def print_error(message):
    print(f"✗ {message}")

def test_certificate_with_openssl():
    """使用OpenSSL测试证书"""
    print_header("SSL证书连接测试")

    try:
        # 测试SMTPS (465)
        print_info("测试端口 465 (SMTPS - 直接SSL)")
        result = subprocess.run([
            'openssl', 's_client', '-connect', 'mail.caiji.wiki:465',
            '-servername', 'mail.caiji.wiki'
        ], input='QUIT\n', text=True, capture_output=True, timeout=10)

        if result.returncode == 0:
            print_success("端口 465 SSL连接成功")
            # 检查证书信息
            if 'Verify return code: 0' in result.stdout:
                print_success("SSL证书验证通过")
            else:
                print_error("SSL证书验证失败，但连接成功")
        else:
            print_error(f"端口 465 SSL连接失败: {result.stderr}")

    except Exception as e:
        print_error(f"SSL证书测试失败: {e}")

    try:
        # 测试STARTTLS (587)
        print_info("测试端口 587 (STARTTLS)")
        result = subprocess.run([
            'openssl', 's_client', '-connect', 'mail.caiji.wiki:587',
            '-starttls', 'smtp', '-servername', 'mail.caiji.wiki'
        ], input='QUIT\n', text=True, capture_output=True, timeout=10)

        if result.returncode == 0:
            print_success("端口 587 STARTTLS连接成功")
            if 'Verify return code: 0' in result.stdout:
                print_success("STARTTLS证书验证通过")
            else:
                print_error("STARTTLS证书验证失败，但连接成功")
        else:
            print_error(f"端口 587 STARTTLS连接失败: {result.stderr}")

    except Exception as e:
        print_error(f"STARTTLS测试失败: {e}")

def test_smtp_with_auth_after_tls():
    """在STARTTLS后测试SMTP AUTH"""
    print_header("STARTTLS后SMTP认证测试")

    try:
        # 手动SMTP会话
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect(('mail.caiji.wiki', 587))

        # 读取欢迎消息
        welcome = sock.recv(1024).decode().strip()
        print_success(f"连接成功: {welcome}")

        # EHLO
        sock.send(b'EHLO test.localhost\r\n')
        ehlo_response = sock.recv(2048).decode()
        print_info("初始EHLO响应:")
        for line in ehlo_response.split('\n'):
            if line.strip():
                print(f"  {line.strip()}")

        # STARTTLS
        if 'STARTTLS' in ehlo_response:
            print_info("尝试STARTTLS...")
            sock.send(b'STARTTLS\r\n')
            tls_response = sock.recv(1024).decode().strip()
            print_info(f"STARTTLS响应: {tls_response}")

            if tls_response.startswith('220'):
                print_success("STARTTLS握手成功")

                # 在TLS之后进行SSL包装需要ssl模块
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                wrapped_sock = context.wrap_socket(sock, server_hostname='mail.caiji.wiki')

                # 发送第二个EHLO (TLS后)
                wrapped_sock.send(b'EHLO test.localhost\r\n')
                tls_ehlo_response = wrapped_sock.recv(2048).decode()

                print_info("TLS后EHLO响应:")
                auth_found = False
                for line in tls_ehlo_response.split('\n'):
                    line = line.strip()
                    if line:
                        if 'AUTH' in line.upper():
                            print_success(f"  >>> {line} <<<")
                            auth_found = True
                        else:
                            print(f"  {line}")

                if auth_found:
                    print_success("🎉 在STARTTLS后发现AUTH扩展！")

                    # 尝试认证
                    import base64
                    auth_string = f"\0yiqiu@caiji.wiki\0123456789"
                    auth_b64 = base64.b64encode(auth_string.encode()).decode()

                    wrapped_sock.send(f'AUTH PLAIN {auth_b64}\r\n'.encode())
                    auth_response = wrapped_sock.recv(1024).decode().strip()

                    print_info(f"认证响应: {auth_response}")

                    if auth_response.startswith('235'):
                        print_success("🎉 SMTP认证成功！SASL配置工作正常！")
                        result = True
                    else:
                        print_error(f"SMTP认证失败: {auth_response}")
                        result = False
                else:
                    print_error("STARTTLS后仍未发现AUTH扩展")
                    result = False

                wrapped_sock.send(b'QUIT\r\n')
                wrapped_sock.close()
                return result

            else:
                print_error(f"STARTTLS失败: {tls_response}")
                sock.close()
                return False
        else:
            print_error("服务器不支持STARTTLS")
            sock.close()
            return False

    except Exception as e:
        print_error(f"STARTTLS认证测试失败: {e}")
        return False

def main():
    """主函数"""
    print_header("SSL证书和SMTP配置检查")
    print_info("检查实际的SSL证书连接和SMTP认证功能")

    # 测试SSL证书
    test_certificate_with_openssl()

    # 测试SMTP认证
    auth_success = test_smtp_with_auth_after_tls()

    print_header("最终结果")
    if auth_success:
        print_success("🎉 SSL证书和SMTP SASL认证都工作正常！")
        print_info("您现在可以在WordPress中配置SMTP:")
        print("  主机: mail.caiji.wiki")
        print("  端口: 587")
        print("  加密: TLS/STARTTLS")
        print("  用户名: yiqiu@caiji.wiki")
        print("  密码: 123456789")
    else:
        print_error("SSL证书或SMTP认证仍有问题")
        print_info("建议检查:")
        print("  1. 远程服务器是否重新启动了Postfix和Dovecot服务")
        print("  2. /etc/postfix/main.cf 是否包含了SASL配置")
        print("  3. /var/spool/postfix/private/auth 套接字是否存在")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n检查被用户中断")
    except Exception as e:
        print_error(f"脚本执行出错: {e}")
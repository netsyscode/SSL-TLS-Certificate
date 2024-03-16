
from OpenSSL import SSL
from OpenSSL.crypto import dump_certificate, FILETYPE_PEM
import urllib3
from OpenSSL import crypto
import http.client
import ssl

def get_certificate_chain_with_proxy(url, proxy):

    ip =  socket.gethostbyname(url)

        # Create an HTTP connection to the proxy
    proxy_conn = http.client.HTTPConnection("127.0.0.1", 33210)
        # Use the CONNECT method to initiate a tunnelled connection
    headers = {
        "Host" : f"{url}:443",
        "Authorization": "Bearer YourAccessToken",  # 如果需要认证的话
    }
    proxy_conn.set_tunnel(ip, 443, headers)

        # Connect to the proxy
    proxy_conn.connect()
        # Replace the socket with the proxy's socket
    sock = proxy_conn.sock


    # 使用 SSL 包装套接字
    ssl_socket = ssl.wrap_socket(sock)

    # 在 SSL/TLS 连接上发送数据
    ssl_socket.sendall(b"GET / HTTP/1.1\r\nHost: " + url.encode() + b"\r\n\r\n")

    # 接收响应
    response = ssl_socket.recv(4096)
    print(response.decode())



    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE)

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_tlsext_host_name(url.encode())  # 关键: 对应不同域名的证书
    sock_ssl.set_connect_state()

    try:
        sock_ssl.do_handshake()
    except SSL.WantReadError:
        pass

    # Retrieve the peer certificate
    certs = sock_ssl.get_peer_cert_chain()
    print(certs)
    return certs

    cert_pem = [dump_certificate(FILETYPE_PEM, cert).decode('utf-8') for cert in certs]
    sock.close()
    return cert_pem

import time
import select
import socket
import dns.resolver

def f():
    domain = 'www.google.com'
    port = 443

    dns_server = "8.8.8.8"

    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8']
        resolver.timeout = 2

        answers = dns.resolver.resolve(domain, 'A')  # A记录
        print(f"A records for {domain}:")
        for rdata in answers:
            print(rdata.address)

        answers = dns.resolver.resolve(domain, 'AAAA')  # AAAA记录 (IPv6)
        print(f"AAAA records for {domain}:")
        for rdata in answers:
            print(rdata.address)

        issue_ca = []
        issue_wildcard_ca = []
        answers = resolver.resolve(domain, 'CAA')  # CAA记录
        print(answers)

        for rdata in answers:
            if rdata.flags == 0 and rdata.tag == "issue":
                issue_ca.append(rdata.value)
            if rdata.flags == 0 and rdata.tag == "issuewild":
                issue_wildcard_ca.append(rdata.value)

        return (issue_ca, issue_wildcard_ca)

    except:
        pass
    
    ip =  socket.gethostbyname(domain)
    # ip =  socket.getaddrinfo(domain, port)
    # ip =  socket.getaddrinfo(domain, 80)
    print(ip)



    PROXY_ADDR = ("127.0.0.1", 33210)
    # CONNECT = "CONNECT {}:{} HTTP/1.1\r\nConnection: close\r\n\r\n".format(ip , port).encode()
    # CONNECT = "CONNECT [240c:4003:111:3f1f:0:ff:b0ea:3686]:443 HTTP/1.1\r\nConnection: close\r\n\r\n".encode()
    # CONNECT = "CONNECT {}:{} HTTP/1.0\r\n\r\n".format(ip, port).encode()
    CONNECT = f"CONNECT {domain}:{port} HTTP/1.1\r\nHost: {ip}:{port}\r\n\r\n".encode()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(PROXY_ADDR)
    s.send(CONNECT)
    print(CONNECT)
    print(s.recv(4096))

    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE)

    ss = SSL.Connection(ctx, s)
    ss.set_tlsext_host_name(domain.encode())  # 关键: 对应不同域名的证书
    ss.set_connect_state()

    retry_count = 0
    last_error = None
    while True:
        if retry_count >= 2:
            raise Exception
        try:
            ss.do_handshake()
            break
        except SSL.WantReadError as e:
            print(f"Error code1: {e.args}")
            # 等待套接字可读
            readable, _, _ = select.select([ss], [], [], 1)
            # Timeout occurs
            if not readable:
                last_error = e
                retry_count += 1
                continue
        except SSL.SysCallError as e:
            print(f"Error code2: {e.args}")
            last_error = e
            retry_count += 1
            time.sleep(0.5)
            continue

    cert = ss.get_peer_certificate()
    print(cert.get_notAfter())
    print(cert.get_subject().get_components())
    ss.shutdown()
    ss.close()






def fetch_raw_cert_chain(host : str, host_ip : str, port=443, proxy_host="127.0.0.1", proxy_port=33210):

    try:
        '''
            Well, OPENSSL.SSL.Connection only accepts socket.socket,
            we can not use socks.socksocket() from "socks" PySocks to set up proxy
            Instead, we use http.client.HTTPConnection and set_tunnel to
            use the CONNECT method to initiate a tunnelled connection
        '''
        if proxy_host:
            proxy_conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=3)
            proxy_conn.set_tunnel(host_ip, port)
        else:
            proxy_conn = http.client.HTTPConnection(host, port, timeout=3)

        proxy_conn.connect()
        proxy_socket = proxy_conn.sock

        # CONNECT = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host_ip}:{port}\r\n\r\n".encode()
        # proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # proxy_socket.connect(("127.0.0.1", 33210))
        # proxy_socket.send(CONNECT)
        # print(proxy_socket.recv(4096))



        '''
            TODO: handle various SSL/TLS context types
        '''
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_verify(SSL.VERIFY_NONE)

        print(f"Getting certs from {host}...")
        sock_ssl = SSL.Connection(ctx, proxy_socket)
        sock_ssl.set_tlsext_host_name(host.encode())  # 关键: 对应不同域名的证书
        sock_ssl.set_connect_state()

        retry_count = 0
        last_error = None
        while True:
            if retry_count >= 3:
                raise Exception
            try:
                sock_ssl.do_handshake()
                break
            except SSL.WantReadError as e:
                import traceback
                traceback.print_tb(e.__traceback__)
                # 等待套接字可读
                readable, _, _ = select.select([sock_ssl], [], [], 3)
                # Timeout occurs
                if not readable:
                    print(f"Error code1: {e.args}")
                    last_error = e
                    retry_count += 1
                    continue
            except SSL.SysCallError as e:
                last_error = e
                retry_count += 1
                time.sleep(0.5)
                continue

        # Retrieve the peer certificate
        certs = sock_ssl.get_peer_cert_chain()
        cert_pem = [dump_certificate(FILETYPE_PEM, cert).decode('utf-8') for cert in certs]
        print(f"Success fetching certificate for {host} : {len(certs)}")
        proxy_socket.close()
        return cert_pem, None

    except Exception as e:
        print(f"Error fetching certificate for {host}: {e} {e.__class__}")
        # proxy_socket.close()
        # return [], f"{last_error} {last_error.__class__}"
        pass






if __name__ == "__main__":
    # f()
    target_url = "www.google.com"  # 替换为你要查询的网站 URL
    proxy_url = "http://127.0.0.1:33210"  # 替换为你的代理服务器地址和端口

    # fetch_raw_cert_chain(target_url, socket.gethostbyname(target_url), proxy_host=None, proxy_port=None)
    fetch_raw_cert_chain(target_url, socket.gethostbyname(target_url))

    cert_chain = get_certificate_chain_with_proxy(target_url, proxy_url)
    for cert in cert_chain:
        cert : crypto.X509
        print(cert.get_subject())
        print(cert.get_issuer())

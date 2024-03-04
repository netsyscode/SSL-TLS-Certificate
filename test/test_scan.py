
from OpenSSL import SSL
from OpenSSL.crypto import dump_certificate, FILETYPE_PEM
import urllib3
from OpenSSL import crypto
import http.client

def get_certificate_chain_with_proxy(url, proxy):

        # Create an HTTP connection to the proxy
    proxy_conn = http.client.HTTPConnection("127.0.0.1", 33210)
        # Use the CONNECT method to initiate a tunnelled connection
    proxy_conn.set_tunnel(url, 443)
        # Connect to the proxy
    proxy_conn.connect()
        # Replace the socket with the proxy's socket
    sock = proxy_conn.sock

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


if __name__ == "__main__":
    target_url = "apple.com"  # 替换为你要查询的网站 URL
    proxy_url = "http://127.0.0.1:33210"  # 替换为你的代理服务器地址和端口

    cert_chain = get_certificate_chain_with_proxy(target_url, proxy_url)
    for cert in cert_chain:
        cert : crypto.X509
        print(cert.get_subject())
        print(cert.get_issuer())

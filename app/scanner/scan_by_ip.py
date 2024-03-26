

import socket
import ipaddress
from .scan_base import Scanner


class IPScanner(Scanner):

    def __init__(self) -> None:
        super().__init__()

    def start(self):
        # 设置扫描的IP地址范围
        network = ipaddress.ip_network('192.168.1.0/24')

        # 遍历IP地址范围内的所有IP地址
        for ip in network.hosts():
            # 尝试连接IP地址的80端口（HTTP）
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((str(ip), 80))
            
            # 如果连接成功，则说明该IP地址存在
            if result == 0:
                print(f"{ip} is up.")
            
            sock.close()
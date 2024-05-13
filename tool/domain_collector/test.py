import ipaddress

# 给定的IPv4地址
address = "192.168.1.1"

# 创建IPv4Address对象
ipv4_address = ipaddress.IPv4Address(address)
print(type(ipv4_address))

# 获取地址
address_str = str(ipv4_address)

print(address_str)  # 输出：192.168.1.1


from urllib.parse import urlparse
domain = urlparse("one.digicert.com")
print(domain)


import requests
from forcediphttpsadapter.adapters import ForcedIPHTTPSAdapter



# print(requests.get("https://182.61.200.6/", headers={'Host': 'baidu.com'}, verify=False, proxy_host=None).content)
# print(requests.get("https://93.184.216.34/", headers={'Host': 'www.example.com.com'}, verify=False).content)


session = requests.Session()
session.mount("https://www.google.com", ForcedIPHTTPSAdapter(dest_ip='185.45.7.185'))
response = session.get(
    'https://185.45.7.185/', headers={'Host': 'www.google.com'}, verify=False)
print(response.content)



import dns.resolver
from typing import Dict, Tuple, List
from ..logger.logger import my_logger


def get_dns_caa_records(host : str, timeout=5) -> Tuple[List[str], List[str]]:
    pass


def resolve_host_dns(host : str, dns_server="8.8.8.8", timeout=2) -> Tuple[List[str], List[str]]:

    try:
        ipv4 = []
        ipv6 = []
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [dns_server]
        resolver.timeout = timeout

        answers = dns.resolver.resolve(host, 'A')  # A记录
        for rdata in answers:
            ipv4.append(rdata.address)

        answers = dns.resolver.resolve(host, 'AAAA')  # AAAA记录 (IPv6)
        for rdata in answers:
            ipv6.append(rdata.address)

        # answers = dns.resolver.resolve(host, 'CNAME')  # CNAME记录
        # print(f"CNAME records for {host}:")
        # for rdata in answers:
        #     print(rdata.target)

        # answers = dns.resolver.resolve(host, 'MX')  # MX记录
        # print(f"MX records for {host}:")
        # for rdata in answers:
        #     print(f"Preference: {rdata.preference}, Mail Server: {rdata.exchange}")

        # answers = dns.resolver.resolve(host, 'TXT')  # TXT记录
        # print(f"TXT records for {host}:")
        # for rdata in answers:
        #     print(rdata.strings)

        # answers = dns.resolver.resolve(host, 'NS')  # NS记录
        # print(f"NS records for {host}:")
        # for rdata in answers:
        #     print(rdata.target)

        # issue_ca = []
        # issue_wildcard_ca = []
        # answers = resolver.resolve(host, 'CAA')  # CAA记录
        # print(answers)

        # for rdata in answers:
        #     if rdata.flags == 0 and rdata.tag == "issue":
        #         issue_ca.append(rdata.value)
        #     if rdata.flags == 0 and rdata.tag == "issuewild":
        #         issue_wildcard_ca.append(rdata.value)

        # return (issue_ca, issue_wildcard_ca)
        return ipv4, ipv6

    except dns.resolver.NoAnswer:
        my_logger.debug(f"No DNS records found for {host}")
        return [], []

    except dns.resolver.NXDOMAIN:
        my_logger.debug(f"Domain {host} does not exist")
        return [], []

    except dns.resolver.NoNameservers:
        my_logger.debug(f"No nameservers found for {host}")
        return [], []

    except dns.resolver.Timeout:
        my_logger.warn(f"DNS query for {host} timed out")
        return [], []

    except Exception as e:
        my_logger.warn(f"Error: {e}")
        return [], []


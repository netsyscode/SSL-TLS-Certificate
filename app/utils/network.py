
import dns.resolver
from typing import Dict, Tuple
from ..logger.logger import my_logger

def get_dns_caa_records(domain : str, timeout=5) -> Tuple[list[str], list[str]]:

    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.timeout = timeout

        # answers = dns.resolver.resolve(domain, 'A')  # A记录
        # print(f"A records for {domain}:")
        # for rdata in answers:
        #     print(rdata.address)

        # answers = dns.resolver.resolve(domain, 'AAAA')  # AAAA记录 (IPv6)
        # print(f"AAAA records for {domain}:")
        # for rdata in answers:
        #     print(rdata.address)

        # answers = dns.resolver.resolve(domain, 'CNAME')  # CNAME记录
        # print(f"CNAME records for {domain}:")
        # for rdata in answers:
        #     print(rdata.target)

        # answers = dns.resolver.resolve(domain, 'MX')  # MX记录
        # print(f"MX records for {domain}:")
        # for rdata in answers:
        #     print(f"Preference: {rdata.preference}, Mail Server: {rdata.exchange}")

        # answers = dns.resolver.resolve(domain, 'TXT')  # TXT记录
        # print(f"TXT records for {domain}:")
        # for rdata in answers:
        #     print(rdata.strings)

        # answers = dns.resolver.resolve(domain, 'NS')  # NS记录
        # print(f"NS records for {domain}:")
        # for rdata in answers:
        #     print(rdata.target)

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

    except dns.resolver.NoAnswer:
        my_logger.debug(f"No DNS records found for {domain}")
        return [], []

    except dns.resolver.NXDOMAIN:
        my_logger.debug(f"Domain {domain} does not exist")
        return [], []

    except dns.resolver.NoNameservers:
        my_logger.debug(f"No nameservers found for {domain}")
        return [], []

    except dns.resolver.Timeout:
        my_logger.warn(f"DNS query for {domain} timed out")
        return [], []

    except Exception as e:
        my_logger.warn(f"Error: {e}")
        return [], []


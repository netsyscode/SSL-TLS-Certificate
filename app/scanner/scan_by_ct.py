


# '''
#     Created on 01/17/24
#     Collect CT log entries and parse the certificates
# '''

# from mysql.connector import Error, errorcode

# from webPKIScanner.logger.logger import *
# from webPKIScanner.ctParser.ctParser import *
# from webPKIScanner.commonHelpers.sqlHelpers.sqlHelper import SQLConnection
# from webPKIScanner.certAnalyzer.x509CertUtils import BIMAP_CERTIFICATE_TYPE_AND_NAME, getCertSHA256Hex

# from cryptography.x509 import Certificate
# from cryptography.hazmat.primitives.serialization import Encoding

# import json
# import base64
# import requests
# from datetime import datetime
# from OpenSSL import crypto
# from urllib3.exceptions import SSLError
from .scan_base import Scanner


class CTScanner(Scanner):
    pass

#     def __init__(self, log_server) -> None:
#         self.log_server = log_server
#         self.connection = SQLConnection("ctstorage")
#         self.scan_time = datetime.now().strftime("%Y%m%d")
#         self.ct_storage_table_name = f"{self.scan_time}_ct_store"
#         self.createStorageTable()


#     def start(self):

#         ct_log_server_url = f'https://{self.log_server}/ct/v1/get-entries'
#         start = 0

#         while start < 100000:
#             window_size = 1000
#             end = start + window_size
#             params = {'start': start, 'end': end}
#             try:
#                 response = requests.get(ct_log_server_url, params=params, verify=True)
#             except Exception as e:
#                 print(f"{e}")
#                 continue

#             if response.status_code == 200:
#                 entries = json.loads(response.text)['entries']
#                 window_size = len(entries)
#             else:
#                 my_logger.dumpLog(WARNING, f"Requesting CT entries from {start} to {end} failed.")
#                 continue

#             for entry in entries:

#                 leaf_cert = merkle_tree_header.parse(base64.b64decode(entry['leaf_input']))

#                 if leaf_cert.LogEntryType == "X509LogEntryType":
#                     # We have a normal x509 entry
#                     cert_data_string = certificate.parse(leaf_cert.Entry).CertData
#                     try:
#                         chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data_string).to_cryptography()]
#                     except crypto.Error as e:
#                         chain = [None]

#                     # Parse the `extra_data` structure for the rest of the chain
#                     extra_data = certificate_chain.parse(base64.b64decode(entry['extra_data']))
#                     for cert in extra_data.Chain:
#                         try:
#                             chain.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData).to_cryptography())
#                         except crypto.Error as e:
#                             chain.append(None)

#                     for cert in chain:
#                         self.insert(cert)

#                 else:
#                     # We have a precert entry
#                     continue
#                     extra_data = pre_cert_entry.parse(base64.b64decode(entry['extra_data']))
#                     chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, extra_data.LeafCert.CertData).to_cryptography()]

#                     for cert in extra_data.Chain:
#                         chain.append(
#                             crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData).to_cryptography()
#                         )
#             start = start + window_size


#     def createStorageTable(self):
#         try:
#             drop_table_query = f"""
#                 drop table {self.ct_storage_table_name}
#             """
#             self.connection.cursor.execute(drop_table_query)
#             self.connection.connection.commit()

#         except Error as err:
#             my_logger.dumpLog(WARNING, f"{err}")

#         try:
#             create_table_query = f"""
#                 CREATE TABLE {self.ct_storage_table_name} (
#                     id INT AUTO_INCREMENT PRIMARY KEY,
#                     cert_type VARCHAR(16),
#                     sha256 VARCHAR(64) UNIQUE KEY,
#                     cert_str TEXT
#                 )
#             """

#             self.connection.cursor.execute(create_table_query)
#             self.connection.connection.commit()
#         except Error as err:
#             my_logger.dumpLog(ERROR, f"Other error: {err}")


#     def insert(self, cert_ : Certificate):

#         try:
#             insert_query = f"""
#                 INSERT IGNORE INTO {self.ct_storage_table_name}
#                 (cert_type, sha256, cert_str)
#                 VALUES (%s, %s, %s)
#             """

#             if cert_ is None:
#                 data = (
#                     "Test",
#                     "-1",
#                     "-1"
#                 )
#             else:
#                 data = (
#                     "Test",
#                     getCertSHA256Hex(cert_),
#                     cert_.public_bytes(Encoding.PEM).decode(),
#                 )

#             self.connection.cursor.execute(insert_query, data)
#             self.connection.connection.commit()

#         except Error as err:
#             my_logger.dumpLog(ERROR, f"Other error: {err}")


# start = datetime.now()
# collector = CTScanner(log_server = "oak.ct.letsencrypt.org/2023")
# collector.start()
# end = datetime.now()
# diff = end - start

# my_logger.dumpLog(INFO, f"Collecting 100000 Certs time: {diff.total_seconds()}")


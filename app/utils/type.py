
from enum import Enum

# Scan method for a particular scan process
class ScanType(Enum):
    SCAN_BY_DOMAIN = 0
    SCAN_BY_IP = 1
    SCAN_BY_CT = 2

# Status of a particular scan process
class ScanStatusType(Enum):
    RUNNING = 0
    COMPLETED = 1
    SUSPEND = 2
    KILLED = 3

# Identifiers for X509 cert type based on its position in the cert chain
class CertType(Enum):
    LEAF = 0
    INTERMEDIATE = 1
    ROOT = 2

# Identifiers for x509 leaf cert basd on its policies
class LeafCertType(Enum):
    DV = 0
    IV = 1
    OV = 2
    EV = 3

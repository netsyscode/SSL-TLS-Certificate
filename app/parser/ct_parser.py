
'''
    Created on 01/17/24
    Data structures for CT log entries
'''

from construct import (
    Struct,
    Byte,
    Int16ub,
    Int64ub,
    Enum,
    Bytes,
    Int24ub,
    this,
    GreedyBytes,
    GreedyRange,
    Terminated
)

merkle_tree_header = Struct(
    "Version"         / Byte,
    "MerkleLeafType"  / Byte,
    "Timestamp"       / Int64ub,
    "LogEntryType"    / Enum(Int16ub, X509LogEntryType=0, PrecertLogEntryType=1),
    "Entry"           / GreedyBytes
)

certificate = Struct(
    "Length" / Int24ub,
    "CertData" / Bytes(this.Length)
)

certificate_chain = Struct(
    "ChainLength" / Int24ub,
    "Chain" / GreedyRange(certificate),
)

pre_cert_entry = Struct(
    "LeafCert" / certificate,
    "CertChain" / certificate_chain,
    Terminated
)

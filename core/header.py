"""
Author: Edunbar2
Version 1.0
Description:
    A series of helpful functions to handel formatting and manipulation of header before package is sent.
        Wire format (V1.0)
        Field           Size(bytes)         Description
        Version             1               Protocol version
        Flags               1               Control Flags (SYN, ACK, FIN, ETC)
        Header Length       1               Total header length in bytes
        Reserverved         1               Future use / alignment
        Sequence Number     4               Used for ordering
        Ack number          4               ACKs received data
        Source Port         2               Sender's application port
        Dest port           2               Target application port
        Timestamp           4               For replay protection / RTT estimation
        HMAC                16              HMAC of header + paylaod (truncated SHA-256)
        Payload             N               Application data
"""

import struct
import time
from secureTCP.config import DEFAULT_PORT


        ###CONSTANTS###
HEADER_FORMAT = "!BBBBLLHHHL" # 22 Bytes (Exclude HMAC)
HMAC_LEN = 16
HEADER_FORMAT_FULL = HEADER_FORMAT+"16s"
HEADER_LEN = struct.calcsize(HEADER_FORMAT_FULL)
# Additional Constants
RESERVED = 0x0


# Packs the header in preparation for attachment to payload. Does not include HMAC.
def pack_header(payload_len, src_port, dst_port, seq_num=0, ack_num=0, version=1, flags=0b0) -> bytes:
    timestamp = int(time.time())
    return struct.pack( HEADER_FORMAT,
                     version, flags, HEADER_LEN,
                        RESERVED, seq_num, ack_num, payload_len,
                        src_port, dst_port, timestamp )

# Unpack header received and return as tuple.
def unpack_header(header) -> tuple:
    if len(header) != HEADER_LEN:
        raise ValueError(f"Header length must be {HEADER_LEN}, got {len(header)}")
    return struct.unpack(HEADER_FORMAT_FULL, header)

# Validate version in header field
def validate_version(header, expected_version) -> bool:
    version, *rest_of_header = struct.unpack(HEADER_FORMAT_FULL, header)
    return version == expected_version

# Validate Length of header
def validate_header_len(header: bytes) -> bool:
    unpackedHeader = struct.unpack(HEADER_FORMAT_FULL, header)
    return unpackedHeader[2] == HEADER_LEN
# Get hmac from header
def get_hmac(header) -> bytes:
    unpackedHeader = struct.unpack(HEADER_FORMAT_FULL, header)
    return unpackedHeader[10]
"""
Author: Edunbar2
Version: 1.0
Description: SecureTCP v1.0 packet logic and manipulation
"""
from dataclasses import dataclass
from typing import Tuple
from secureTCP.core.header import pack_header, unpack_header, validate_header_len, validate_version
from secureTCP.core.crypto import compute_hmac, validate_hmac
from secureTCP.config import CURRENT_VERSION

@dataclass
class ParsedPacket:
    valid: bool
    version: int
    flags: int
    header_len: int
    reserved: int
    seq_num: int
    ack_num: int
    payload_len: int
    src_port: int
    dst_port: int
    timestamp: int
    hmac: bytes
    payload: bytes



def build_packet(payload: bytes, src_port: int, dst_port: int, seq_num=0, ack_num=0, version=1, flags=0b0, key=None) -> bytes:
    """
    Build a full SecureTCP packet with header, HMAC, and payload.

    Parameters:
        payload (bytes): The data to send.
        src_port (int): Source port number.
        dst_port (int): Destination port number.
        seq_num (int): Sequence number.
        ack_num (int): Acknowledgment number.
        version (int): Protocol version (default 1).
        flags (int): Bitmask flags.
        key (bytes): Optional override for HMAC key.

    Returns:
        bytes: The complete packet ready to send.
    """

    payload_len = len(payload)
    partial_header = pack_header(payload_len, src_port, dst_port, seq_num, ack_num, version, flags)
    computed_hmac = compute_hmac(partial_header, payload)

    full_header = partial_header + computed_hmac

    packet = full_header + payload

    return packet

def parse_packet(packet: bytes) -> ParsedPacket:
    """
    Parse a received SecureTCP packet into components.

    Parameters:
        packet (bytes): The full packet to parse.

    Returns:
        dict: A dictionary containing:
            - 'valid': Whether the packet passed validation.
            - 'header': Unpacked header fields.
            - 'payload': Payload as bytes.
            - 'src_port': Extracted source port.
            - 'dest_port': Extracted destination port.
    """

    header = packet[:38]
    payload = packet[38:]

    version, flags, hlen, reserved, seq, ack, plen, src_port, dst_port, ts, hmac = unpack_header(header)
    valid = is_valid_packet(packet)

    return ParsedPacket(
        valid=valid,
        version=version,
        flags=flags,
        header_len=hlen,
        reserved=reserved,
        seq_num=seq,
        ack_num=ack,
        payload_len=plen,
        src_port=src_port,
        dst_port=dst_port,
        timestamp=ts,
        hmac=hmac,
        payload=payload
    )

def is_valid_packet(packet: bytes) -> bool:
    """
    Validate a SecureTCP packet by checking version, length, and HMAC.

    Parameters:
        packet (bytes): The full packet to validate.

    Returns:
        bool: True if the packet is valid, False otherwise.
    """
    if not validate_version(packet[:38], CURRENT_VERSION):
        return False
    if not validate_header_len(packet[:38]):
        return False

    partial_header, received_hmac, payload = extract_header_parts(packet)
    return validate_hmac(partial_header, payload, received_hmac)


def extract_header_parts(packet: bytes) -> tuple:
    """
    Extract the partial header (22B), HMAC (16B), and payload from a packet.

    Parameters:
        packet (bytes): Full SecureTCP packet.

    Returns:
        tuple: (partial_header, received_hmac, payload)
    """

    partial_header = packet[:22]
    received_hmac = packet[22:38]
    payload = packet[38:]
    return partial_header, received_hmac, payload


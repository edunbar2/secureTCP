"""
Author: Edunbar2
Version: 1.0
Description:
"""

import socket
from secureTCP.config import DEFAULT_INTERFACE

def send_packet(packet: bytes, dest_ip: str):
    """
        Send a raw SecureTCP packet to a destination IP.

        Parameters:
            packet (bytes): Fully constructed SecureTCP packet (IP header + SecureTCP header + HMAC + payload)
            dest_ip (str): Destination IP address to send to
        """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
            sock.sendto(packet, (dest_ip, 0))
    except PermissionError:
        print("Error: Raw socket access denied.  You may need root or CAP_NET_RAW.")
"""
Author: Edunbar2
Version: 1.0
Description: Example function for receiving SecureTCP packet.
"""
import socket
import sys

from secureTCP.core.packet import parse_packet
from secureTCP.transport.connection import handle_packet
from secureTCP.config import  DEFAULT_INTERFACE

ETH_HEADER_OFFSET = 14
IP_HEADER_OFFSET = 20

def main():
    print("[Receiver] Starting up SecureTCP listener...")

    # Open a raw packet socket
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    sock.bind((DEFAULT_INTERFACE, 0))

    while True:
        try:
            packet, addr = sock.recvfrom(65535)

            # Ethernet + IP header = 14 + 20 bytes
            ip_header = packet[:ETH_HEADER_OFFSET + IP_HEADER_OFFSET]
            src_ip = socket.inet_ntoa(ip_header[12:16])
            dst_ip = socket.inet_ntoa(ip_header[16:20])

            # SecureTCP header starts at byte 34
            securetcp_packet = packet[ETH_HEADER_OFFSET + IP_HEADER_OFFSET]

            parsed_packet = parse_packet(securetcp_packet)
            handle_packet(parsed_packet, src_ip, dst_ip
                          )
        except KeyboardInterrupt:
            print("\n[Receiver] Shutdown requested. Exiting.")
            sys.exit(0)
        except Exception as e:
            print(f"[Receiver] Error: {e}")


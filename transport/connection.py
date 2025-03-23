"""
Author: Edunbar2
Version: 1.0
Description: SecureTCP v1.0 state machine logic.
"""
import random
import time

from enum import Enum, auto

from secureTCP.core.flags import has_flag, SYN, ACK, FIN, RST, set_flag
from secureTCP.core.packet import parse_packet, build_packet, ParsedPacket
from secureTCP.transport.conn_table import get_connection, create_connection, remove_connection

class ConnectionState(Enum):
    CLOSED = auto()
    LISTEN = auto()
    SYN_SENT = auto()
    SYN_RECEIVED = auto()
    ESTABLISHED = auto()
    FIN_WAIT = auto()
    CLOSING = auto()
    TIME_WAIT = auto()
    TERMINATED = auto()

class SecureTCPConnection:

    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        self.state=ConnectionState.LISTEN
        self.seq_num = 0
        self.ack_num = 0
        self.timestamp = time.time()

        self.secure = False
        self.flags_last_seen = 0
        self.retries = 0
        self.buffer = b""


def handle_listen(conn, parsed_packet):
    if not has_flag(parsed_packet.flags, SYN) or has_flag(parsed_packet.flag, ACK):
        return # Invalid for LISTEN state

    # Accept the connection - update state
    conn.state = ConnectionState.SYN_RECEIVED
    conn.ack_num = parsed_packet.seq_num + 1
    conn.seq_num = random.randint(1, 100000)

    conn.secure=True # valid HMAC already verified
    conn.flags_last_seen = parsed_packet.flags

    # prepare SYN+ACK
    flags = set_flag(SYN, ACK)
    response = build_packet(
        payload=b"",
        src_port=conn.dst_port,
        dst_port=conn.src_port,
        seq_num=conn.seq_num,
        ack_num=conn.ack_num,
        version=parsed_packet.version,
        flags=flags
    )

    send_packet(response, conn.src_ip)


def handle_syn_sent(conn, parsed_packet):
    pass


def handle_syn_received(conn, parsed_packet):
    pass


def handle_established(conn, parsed_packet):
    pass


def handle_fin_wait(conn, parsed_packet):
    pass


def handle_closing(conn, parsed_packet):
    pass


def handle_time_wait(conn, parsed_packet):
    pass


def handle_packet(parsed_packet: ParsedPacket, src_ip: str, dst_ip: str):
    if not parsed_packet.valid:
        return
    # lookup connection
    conn = get_connection(src_ip, parsed_packet.src_port, dst_ip, parsed_packet.dst_port)
    if conn is None:
        if has_flag(parsed_packet.flags, SYN) and not has_flag(parsed_packet.flags, ACK):
            conn = create_connection(
                SecureTCPConnection(src_ip, parsed_packet.src_port, dst_ip, parsed_packet.dst_port)
            )

        # Dispatch based on current connection state
        match conn.state:
            case ConnectionState.LISTEN:
                handle_listen(conn, parsed_packet)
            case ConnectionState.SYN_SENT:
                handle_syn_sent(conn, parsed_packet)
            case ConnectionState.SYN_RECEIVED:
                handle_syn_received(conn, parsed_packet)
            case ConnectionState.ESTABLISHED:
                handle_established(conn, parsed_packet)
            case ConnectionState.FIN_WAIT:
                handle_fin_wait(conn, parsed_packet)
            case ConnectionState.CLOSING:
                handle_closing(conn, parsed_packet)
            case ConnectionState.TIME_WAIT:
                handle_time_wait(conn, parsed_packet)
            case ConnectionState.TERMINATED:
                remove_connection(conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port)
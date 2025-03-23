"""
Author: Edunbar2
Version: 1.0
Description: SecureTCP v1.0 state machine logic.
"""
import random
import time

from enum import Enum, auto

from secureTCP.core.flags import has_flag, SYN, ACK, FIN, RST, set_flag
from secureTCP.core.packet import build_packet, ParsedPacket
from secureTCP.transport.conn_table import get_connection, create_connection, remove_connection, list_connections
from secureTCP.transport.socket_raw import send_packet

# duration to wait before closing in seconds
TIME_WAIT_DURATION = 10

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

def cleanup_connections():
    """
    Iterates over the connection table and removes expired TIME_WAIT connections
    :return:
    """
    now = time.time()
    for key, conn in list_connections().items():
        if conn.state == ConnectionState.TIME_WAIT:
            if now - conn.timestamp > TIME_WAIT_DURATION:
                print(f"[CLEANUP] Removing TIME_WAIT connection {key}")
                conn.state = ConnectionState.TERMINATED
                remove_connection(*key)

def handle_listen(conn, parsed_packet):
    if not has_flag(parsed_packet.flags, SYN) or has_flag(parsed_packet.flags, ACK):
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
    print(f"[LISTEN → SYN_RECEIVED] Sent SYN+ACK to {conn.src_ip}:{conn.src_port}")

def handle_syn_sent(conn, parsed_packet):
    # Must have both SYN and ACK sent
    if not has_flag(parsed_packet.flags, SYN) or not has_flag(parsed_packet.flags, ACK):
        return # Invalid handshake response

    # Ensure SYN was acknowledged correctly
    if parsed_packet.ack_num != conn.seq_num + 1:
        return # Possible spoofing or corruption

    # Accept SYN+ACK, respond with ACK
    conn.state = ConnectionState.ESTABLISHED
    conn.secure = True
    conn.ack_num = parsed_packet.seq_num + 1
    conn.timestamp = time.time()
    conn.flags_last_seen = parsed_packet.flags

    # Send ACK to complete handshake
    flags = ACK
    response = build_packet(
        payload=b"",
        src_port=conn.dst_port,
        dst_port=conn.src_port,
        seq_num=conn.seq_num + 1,
        ack_num=conn.ack_num,
        version=parsed_packet.version,
        flags=flags
    )

    send_packet(response, conn.src_ip)

    print(f"[SYN_SENT → ESTABLISHED] Completed handshake with {conn.src_ip}:{conn.src_port}")

def handle_syn_received(conn, parsed_packet):
    # Must be a pure ACK (no SYN, FIN, etc.)
    if not has_flag(parsed_packet.flags, ACK) or has_flag(parsed_packet.flags, SYN) or has_flag(parsed_packet.flags, FIN):
        return # Invalid packet for this state

    # Must acknowledge the correct sequence number
    if parsed_packet.ack_num != conn.seq_num + 1:
        return # Invalid ACk - possible attack or corruption

    #All good - Establish connection
    conn.state = ConnectionState.ESTABLISHED
    conn.secure == True # HMAC should have already been validated
    conn.flags_last_seen = parsed_packet.flags
    conn.timestamp = time.time()
    conn.ack_num = parsed_packet.seq_num + parsed_packet.payload_len

    print(f"[SYN_RECEIVED → ESTABLISHED] Connection confirmed with {conn.src_ip}:{conn.src_port}")

def handle_established(conn, parsed_packet):
    # Validate the ACK flag ( data should always be acknowledged )
    if not has_flag(parsed_packet.flags, ACK):
        return # Ignor non-ACK packet in this state

    payload = parsed_packet.payload
    seq = parsed_packet.seq_num
    payload_len = parsed_packet.payload_len

    # Check if seq == expected ack_num (ordering check)
    if seq != conn.ack_num:
        print(f"[WARN] Unexpected sequence number: got {seq}, expected {conn.ack_num}")
        return

    if payload_len == 0:
        print(f"[WARN] ACK packet, ignoring...")
        return # No need to ACK empty packets (already acknowledged)

    # Update connection state
    conn.ack_num = seq + payload_len
    conn.timestamp = time.time()
    conn.flags_last_seen = parsed_packet.flags

    # Store payload
    if payload:
        conn.buffer += payload

    ack_packet = build_packet(
        payload=b"",
        src_port=conn.dst_port,
        dst_port=conn.src_port,
        seq_num=conn.seq_num,
        ack_num=conn.ack_num,
        version=parsed_packet.version,
        flags=ACK
    )
    send_packet(ack_packet, conn.src_ip)

    print(f"[ESTABLISHED] ACK sent to {conn.src_ip}:{conn.src_port} (ack_num={conn.ack_num})")

def handle_fin_wait(conn, parsed_packet):
    got_ack = has_flag(parsed_packet.flags, ACK)
    got_fin = has_flag(parsed_packet.flags, FIN)

    if not got_fin and not got_ack:
        return # No teardown-related response

    if got_ack:
        print(f"[FIN_WAIT] Peer acknowledged our FIN.")

    if got_fin:
        # Respond with final ACK
        conn.ack_num = parsed_packet.seq_num + 1
        ack_packet = build_packet(
            payload=b"",
            src_port=conn.dst_port,
            dst_port=conn.src_port,
            seq_num=conn.seq_num,
            ack_num=conn.ack_num,
            version=parsed_packet.version,
            flags=ACK
        )
        send_packet(ack_packet, conn.src_ip)

        # if received ACK+FIN, close fully
        if got_ack and got_fin:
            conn.state = ConnectionState.TIME_WAIT
            conn.timestamp = time.time()
            print(f"[FIN_WAIT → TIME_WAIT] Teardown confirmed with {conn.src_ip}:{conn.src_port}")

def handle_closing(conn: SecureTCPConnection, parsed_packet: ParsedPacket):
    if not has_flag(parsed_packet.flags, FIN):
        return # Not a teardown request

    # Acknowledge FIN
    conn.ack_num = parsed_packet.seq_num + 1
    ack_packet = build_packet(
        payload=b"",
        src_port=conn.dst_port,
        dst_port=conn.src_port,
        seq_num=conn.seq_num,
        ack_num=conn.ack_num,
        version=parsed_packet.version,
        flags=ACK
    )
    send_packet(ack_packet, conn.src_ip)

    conn.state = ConnectionState.TIME_WAIT
    conn.timestamp = time.time()

    print(f"[CLOSING] Received FIN from peer. Sent ACK. → TIME_WAIT")

def handle_time_wait(conn, parsed_packet):
    if has_flag(parsed_packet.flags, FIN):
        # Duplicate FIN received - re-ACK
        conn.ack_num = parsed_packet.seq_num + 1
        ack_packet = build_packet(
            payload=b"",
            src_port=conn.dst_port,
            dst_port=conn.src_port,
            seq_num=conn.seq_num,
            ack_num=conn.ack_num,
            version=parsed_packet.version,
            flags=ACK
        )
        send_packet(ack_packet, conn.src_ip)
        print(f"[TIME_WAIT] Duplicate FIN received. ACK re-sent.")

    # Refresh timeout to keep connection alive.
    conn.timestamp = time.time()

def send_rst(src_ip, src_port, dst_port, version, seq_num=0, ack_num=0,):
    """
    Description:
        Construct and send a Reset packet.
    Parameters:
        :param src_ip: IP original packet was sent from
        :param src_port: Port original packets was sent from
        :param dst_port: Port original packet arrived at
        :param seq_num: sequence number for new packet
        :param ack_num: acknowledgement number for new packet
        :param version:  current protocol version
    """
    flags = RST
    rst_packet = build_packet(
        payload=b"",
        src_port=dst_port,
        dst_port=src_port,
        seq_num=seq_num,
        ack_num=ack_num,
        version=version,
        flags=flags
    )
    send_packet(rst_packet, src_ip)
    print(f"[RST] Sent reset to {src_ip}:{src_port}")


def handle_packet(parsed_packet: ParsedPacket, src_ip: str, dst_ip: str):
    if not parsed_packet.valid:
        return
    # lookup connection
    conn = get_connection(src_ip, parsed_packet.src_port, dst_ip, parsed_packet.dst_port)
    if conn is None:
        if has_flag(parsed_packet.flags, SYN) and not has_flag(parsed_packet.flags, ACK):
            print(f"[NEW CONNECTION] {src_ip}:{parsed_packet.src_port} → {dst_ip}:{parsed_packet.dst_port}")
            conn = create_connection(
                SecureTCPConnection(src_ip, parsed_packet.src_port, dst_ip, parsed_packet.dst_port)
            )
        else:
            # No session and not a valid SYN - RST
            send_rst(
                src_ip=src_ip,
                src_port=parsed_packet.src_port,
                dst_port=parsed_packet.dst_port,
                version=parsed_packet.version
            )
            return

    if has_flag(parsed_packet.flags, RST):
        print(f"[RST] Received reset from {conn.src_ip}:{conn.src_port}")
        conn.state = ConnectionState.TERMINATED
        print(f"[TERMINATED] Session removed: {conn.src_ip}:{conn.src_port}")
        remove_connection(conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port)
        return

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
            print(f"[TERMINATED] Session removed: {conn.src_ip}:{conn.src_port}")
            remove_connection(conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port)

    cleanup_connections()
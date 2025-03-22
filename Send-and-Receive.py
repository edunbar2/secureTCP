import socket
import struct
import sys



def send_data():
    print("Data being sent!")
    source_ip = "10.10.27.54"
    dest_ip = "10.10.27.50"
    protocol_number = 253 # Experimental/Custom protocol

    # Build IP header
    ip_ver_ihl = (4 << 4) + 5
    ip_tos = 0
    ip_tot_len = 20+6
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = protocol_number
    ip_check = 0
    ip_saddr = socket.inet_aton(source_ip) # Convert to binary
    ip_addr = socket.inet_aton(dest_ip)

    # Pack the IP header
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                            ip_ttl, ip_proto, ip_check, ip_saddr, ip_addr)
    # Pack the l4 header

    '''l4 Header layout:
        1. Version: 1 byte 
        2. Flags: 1 byte 
        3. Total Length ( bytes ): 2 bytes
        4. Destination port: 2 bytes  
        
        Length of header: 6 bytes
    '''
    data = b"And yet here I am... despite no help along my way."
    header_len = 6
    len_data = len(data)
    dest_port = 9011
    l4_header = struct.pack('!BBHH', 1, 0, header_len + len_data, dest_port)

    # Combine header information with data
    packet = ip_header + l4_header + data
    # Send packet
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sender.sendto(packet, (dest_ip, 0))

def receivce_data():
    print("Listening for data...")
    receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    receiver.bind(("ens18", 0))
    eth_len = 14
    ip_len = 20
    l4_len = 6
    while True:
        packet, addr = receiver.recvfrom(65535)
        ip_header = packet[eth_len:eth_len + ip_len]
        l4_header = packet[eth_len + ip_len:eth_len + ip_len + l4_len]
        data = packet[eth_len + ip_len + l4_len:]
        l4_version, l4_flags, length, dest_port = struct.unpack('!BBHH', l4_header)
        if dest_port == 9011:
            print(f"From {addr}: version={l4_version}, flags={l4_flags}, len={length}, dest_port={dest_port}")
            print(f"Message: {data}")



def main():
    print("Entering Main")
    if len(sys.argv) >= 1:
        print("Args correct")
        action = sys.argv[1]
        if action.lower() == "send":
            send_data()
        elif action.lower() == "receive":
            receivce_data()


if __name__ == "__main__":
    main()
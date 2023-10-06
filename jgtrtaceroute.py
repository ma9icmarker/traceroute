import socket
import sys

def main(destination_host):
    destination_port = 33434  # Port number used for sending UDP packets
    message = 'hello'  # Payload of the UDP packet
    
    try:
        # Resolve the destination host to its corresponding IP address
        destination_ip = socket.gethostbyname(destination_host)
    except socket.gaierror:
        print("Invalid destination address.")
        sys.exit(1)

    print('Tracing the route to {0}'.format(destination_ip))

    # Prepare a socket to send UDP packets.
    sending_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sending_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Prepare a socket to listen for ICMP messages.
    # Note: Using SOCK_DGRAM instead of SOCK_RAW to avoid needing root privileges.
    receiving_socket = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)

    # Set socket option to include IP header (ICMP header) in received packets.
    receiving_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

    # Initialize variables for tracking the current hop count
    received_ip = None
    initial_hop = 1
    
    while received_ip != destination_ip:
        # Set the socket's TTL to the current hop so that the packet reaches it before being stopped.
        sending_socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_TTL, initial_hop)

        # Attempt to send a UDP packet to the destination IP address
        sending_socket.sendto(bytes(message, 'utf-8'),
                              (destination_ip, destination_port))

        # Receive any incoming ICMP packet. Ignore the first return value from recvfrom, which is the included data.
        _, addr = receiving_socket.recvfrom(1500)
        received_ip = addr[0]
        print('Hop {0}: ICMP message received from {1}'.format(
            initial_hop, received_ip))
        initial_hop += 1

if __name__ == '__main__':
    # Check if the required command line argument is provided
    if len(sys.argv) < 2:
        print("Missing argument - you must include the destination. Usage: python traceroute.py <destination>")
        sys.exit(1)

    destination = sys.argv[1]  # Get the destination host from command line argument
    main(destination)

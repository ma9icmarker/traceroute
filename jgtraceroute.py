import socket
import sys

def main(destination_host):
    # Constants
    destination_port = 33434  # Port number used for sending UDP packets
    message = 'hello'  # Payload of the UDP packet
    
    try:
        # Resolve the destination host to its corresponding IP address
        destination_ip = socket.gethostbyname(destination_host)
    except socket.gaierror:
        print("Error: Invalid destination address.")
        sys.exit(1)

    print('Tracing the route to {0}'.format(destination_ip))

    # Prepare a socket to send UDP packets.
    sending_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sending_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Prepare a socket to listen for ICMP messages.
    # Note: Using SOCK_RAW and IPPROTO_ICMP to capture ICMP packets.
    receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    receiving_socket.settimeout(10)  # Set a timeout for receiving ICMP packets (10 seconds). You can increase this and it will work, but short timings are bettter if you want validate the loop.

    received_ip = None
    initial_hop = 1
    
    try:
        while received_ip != destination_ip:
            # Set the socket's TTL to the current hop so that the packet reaches it before being stopped.
            sending_socket.setsockopt(
                socket.IPPROTO_IP, socket.IP_TTL, initial_hop)

            # Attempt to send a UDP packet to the destination IP address
            sending_socket.sendto(bytes(message, 'utf-8'),
                                  (destination_ip, destination_port))

            try:
                # Receive any incoming ICMP packet. Ignore the first return value from recvfrom, which is the included data.
                _, addr = receiving_socket.recvfrom(1500)
                received_ip = addr[0]
                print('Hop {0}: ICMP message received from {1}'.format(
                    initial_hop, received_ip))
            except socket.timeout:
                print('Hop {0}: No response'.format(initial_hop))

            initial_hop += 1
    except KeyboardInterrupt:
        print("Traceroute interrupted. Exiting...")
    finally:
        # Close the sockets before exiting
        sending_socket.close()
        receiving_socket.close()

if __name__ == '__main__':
    # Check if the required command line argument is provided
    if len(sys.argv) < 2:
        print("Error: Missing argument. Usage: python traceroute.py <destination>")
        sys.exit(1)

    destination = sys.argv[1]
    main(destination)

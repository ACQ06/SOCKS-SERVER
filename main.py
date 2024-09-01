import socket
import threading
import struct

class Socks5Proxy:
    def __init__(self, host='127.0.0.1', port=1080):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen(5)
        print(f"SOCKS5 Proxy listening on {host}:{port}")

    def handle_client(self, client_socket):
        # Initial greeting from the client
        client_socket.recv(262)

        # Response: No authentication required
        client_socket.send(b"\x05\x00")

        # Handle the client request
        req = client_socket.recv(4)
        version, cmd, _, address_type = struct.unpack("!BBBB", req)

        if cmd == 1:  # TCP/IP stream connection
            self.handle_tcp(client_socket, address_type)
        elif cmd == 3:  # UDP associate
            self.handle_udp(client_socket)
        else:
            client_socket.close()

    def handle_tcp(self, client_socket, address_type):
        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(client_socket.recv(4))
        elif address_type == 3:  # Domain name
            domain_length = client_socket.recv(1)[0]
            address = client_socket.recv(domain_length).decode()
        else:
            client_socket.close()
            return

        port = struct.unpack('!H', client_socket.recv(2))[0]

        # Connect to the target server
        try:
            remote_socket = socket.create_connection((address, port))
            client_socket.send(b"\x05\x00\x00\x01" + socket.inet_aton(address) + struct.pack("!H", port))

            # Start relaying data between the client and the target server
            threading.Thread(target=self.relay_tcp, args=(client_socket, remote_socket)).start()
            threading.Thread(target=self.relay_tcp, args=(remote_socket, client_socket)).start()

        except Exception as e:
            print(f"Failed to connect to {address}:{port} - {e}")
            client_socket.close()

    def handle_udp(self, client_socket):
        # Response with the same client address and port
        client_socket.send(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

        # Bind a UDP socket to receive datagrams
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind(('0.0.0.0', 0))

        while True:
            data, addr = udp_socket.recvfrom(4096)
            threading.Thread(target=self.relay_udp, args=(data, addr, udp_socket)).start()

    def relay_tcp(self, source, destination):
        while True:
            try:
                data = source.recv(4096)
                if not data:
                    break
                destination.send(data)
            except Exception:
                break
        source.close()
        destination.close()

    def relay_udp(self, data, addr, udp_socket):
        try:
            # Strip the SOCKS5 UDP header
            header = data[:3]
            payload = data[3:]
            udp_socket.sendto(payload, addr)
        except Exception as e:
            print(f"Failed to relay UDP data - {e}")

    def start(self):
        while True:
            client_socket, _ = self.server.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    proxy = Socks5Proxy()
    proxy.start()

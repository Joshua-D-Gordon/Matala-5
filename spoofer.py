import socket
import struct

class Spoofer:
    def __init__(self, protocol, fake_senders_ip, fake_senders_port, dest_ip, dest_port):
        self.protocol = protocol
        self.fake_ip = fake_senders_ip
        self.fake_port = fake_senders_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port

    def run(self):
        try:
            fake_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except socket.error as e:
            print(e)
            exit(1)

        ip_header = struct.pack("!4s4sBBH", socket.inet_aton(self.fake_ip), socket.inet_aton(self.dest_ip), 0, 0, 0)

        if self.protocol == "ICMP":
            icmp_header = struct.pack("bbHHh", 8, 0, 0, 0, 0)
            packet = ip_header + icmp_header

        elif self.protocol == "UDP":
            udp_header = struct.pack("!HHHH", self.fake_port, self.dest_port, 8, 0)
            packet = ip_header + udp_header

        try:
            fake_socket.sendto(packet, (self.dest_ip, 0))
            print("Sent fake spoof")
        except socket.error as e:
            print(e)
        finally:
            fake_socket.close()

if "__main__" == __name__:
    
#spoof = Spoofer("TCP", "192.168.0.100", 12345, "192.168.0.1", 80)
#spoof.run()

import socket
import datetime
import struct

HOST = "127.0.0.1"
PORT = 0
ID_1 = 332307073
ID_2 = 332307072
MAX_SIZE = 65536


class Sniffer:
    def __init__(self, protocol):
        self.file_name = str(ID_1) + "_" + str(ID_2)
        self.protocol = protocol
        self.host = HOST
        self.port = PORT

    def run(self):
        with open("{}.pcap".format(self.file_name), "wb") as f:
            print("PCAP file: {} opened and ready to write to".format(self.file_name))

            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            while True:
                packet, addr = self.socket.recvfrom(MAX_SIZE)
                header = struct.unpack("!6s6sH", packet[:14])

                if header[2] == 0x0800:
                    ip_header = struct.unpack("!BBHHHBBH4s4s", packet[14:34])
                    packet_protocol = ip_header[6]
                    if packet_protocol == 6:  # TCP
                        tcp_header = struct.unpack("!HHLLBBHHH", packet[34:54])
                        source_ip = socket.inet_ntoa(ip_header[8])
                        dest_ip = socket.inet_ntoa(ip_header[9])
                        source_port = tcp_header[0]
                        dest_port = tcp_header[1]
                        data = packet[54:]  # Payload data

                        # Check if Telnet protocol (port 23)
                        if source_port == 23 or dest_port == 23:
                            timestamp = str(datetime.datetime.now())
                            total_length = ip_header[2]
                            cache_flag = tcp_header[4] & 0x20 != 0
                            steps_flag = tcp_header[4] & 0x40 != 0
                            type_flag = tcp_header[4] & 0x80 != 0
                            status_code = tcp_header[5]
                            cache_control = tcp_header[6]

                            # Prepare the packet information in the desired format
                            packet_info = {
                                "source_ip": source_ip,
                                "dest_ip": dest_ip,
                                "source_port": source_port,
                                "dest_port": dest_port,
                                "timestamp": timestamp,
                                "total_length": total_length,
                                "cache_flag": cache_flag,
                                "steps_flag": steps_flag,
                                "type_flag": type_flag,
                                "status_code": status_code,
                                "cache_control": cache_control,
                                "data": data.hex()  # Convert data to hexadecimal
                            }

                            # Write the packet information to the PCAP file
                            f.write(packet)
                            print("Captured Telnet packet: {}".format(packet_info))


if __name__ == "__main__":
    sniffer = Sniffer("TCP")
    sniffer.run()

'''To use this program:

Save the code to a file named sniffing_passwords.py.
Run the program on the machine where you want to capture Telnet traffic.
Perform Telnet sessions on the network you are monitoring.
The program will capture the Telnet packets and print out their details.
The captured packets will be saved to a PCAP file named `<ID_1>_<ID_2>.pcap'''
import socket
import datetime
import struct
import os

HOST = "127.0.0.1"
PORT = 0
ID_1 = 332307073
ID_2 = 332307072
MAX_SIZE = 65536

class Sniffer:
    def __init__(self, protocol):
        self.file_name = str(ID_1) +"_"+str(ID_2)
        self.protocol = protocol
        self.host = HOST
        self.port = PORT

    def run(self):
        with open("{}".format(self.file_name), "w") as f:
            print("file: {} opened and ready to writ to".format(self.file_name))

            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            while True:
                packet, addr = self.socket.recvfrom(MAX_SIZE)
                header = struct.unpack("!6s6sH", packet[:14])

                if header[2] == 0x0800:
                    ip_header = struct.unpack("!BBHHHBBH4s4s", packet[14:34])
                    Packet_protocol = ip_header[6]
                match(Packet_protocol):
                    case 6: #TCP
                        tcp_header = struct.unpack("!HHLLBBHHH", packet[34:54])
                        # Extract relevant information from the headers
                        source_ip = socket.inet_ntoa(ip_header[8])
                        dest_ip = socket.inet_ntoa(ip_header[9])
                        source_port = tcp_header[0]
                        dest_port = tcp_header[1]
                        timestamp = str(datetime.datetime.now())
                        total_length = ip_header[2]
                        cache_flag = tcp_header[4] & 0x20 != 0
                        steps_flag = tcp_header[4] & 0x40 != 0
                        type_flag = tcp_header[4] & 0x80 != 0
                        status_code = tcp_header[5]
                        cache_control = tcp_header[6]
                        data = packet[54:]  # Payload data

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

                        # Write the packet information to the output file
                        f.write(str(packet_info) + "\n")
                        return
                    case 17: #UDP
                        return
                    case 1: #ICMP
                        return
                    case 2: #IGMP
                        return
                    case _: #DEFAULT
                        return
            
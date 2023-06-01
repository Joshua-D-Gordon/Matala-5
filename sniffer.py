import socket
import time
import os

class sniffer:
    def __init__(self, id_1, id_2, protocol, host, port):
        self.file_name = id_1 + id_2
        self.protocol = protocol
        self.host = host
        self.port = port

    
        

        
    
    def run(self):
        with open("{}".format(self.file_name), "w") as f:

            match(self.protocol):
                case "TCP":
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.s = s
                    self.s.bind((self.host, self.port))
                    self.s.listen()
                    self.conn, self.addr = s.accept()
                    with self.conn:
                        print('Connected by', self.addr)

                        data = self.conn.recv(1024)
                        # get X from data{ source_ip: <input>, dest_ip: <input>, source_port: <input>, dest_port: <input>, timestamp: <input>, total_length: <input>, cache_flag: <input>, steps_flag: <input>, type_flag: <input>, status_code: <input>, cache_control: <input>, data: <input> }
                        #write to file
                        #f.write(X)

                case "UDP":
                    return
                case "ICMP":
                    return
                case "IGMP":
                    return
                case _: #DEFAULT
                    return
            
from scapy.all import sniff, TCP, IP
import datetime




ID_1 = 332307073
ID_2 = 214329633

class PacketSniffer:
    def __init__(self, server_port, proxy_port):
        self.file_name = str(ID_1)+"_"+str(ID_2)
        #self.CLIENT_PORT = client_port
        self.SERVER_PORT = server_port
        self.PROXY_PORT = proxy_port
        
    def sniff_packets(self):
        sniff(filter="tcp", prn=self.process_packet)

    def process_packet(self, packet):
        if TCP in packet and (packet[TCP].sport in [ self.SERVER_PORT, self.PROXY_PORT] or packet[TCP].dport in [ self.SERVER_PORT, self.PROXY_PORT]):
            # Extract relevant information from the packet
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            source_port = packet[TCP].sport
            dest_port = packet[TCP].dport
            timestamp = str(datetime.datetime.now())
            total_length = packet[IP].len
            cache_flag = packet[TCP].flags & TCP_FLAG_PUSH != 0
            steps_flag = packet[TCP].flags & TCP_FLAG_ACK != 0
            type_flag = packet[TCP].flags & TCP_FLAG_URG != 0
            status_code = packet[TCP].flags & TCP_FLAG_RST != 0
            cache_control = packet[TCP].flags & TCP_FLAG_SYN != 0
            data = packet[TCP].payload

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
            with open(self.file_name, "a") as f:
                f.write(str(packet_info) + "\n")

if __name__ == "__main__":
    print("Started")
    DEFAULT_SERVER_PORT = 9999 # The default port for the server
    DEFAULT_PROXY_PORT = 9998 # The default port for the proxy

    #cp = DEFAULT_SERVER_PORT

    sp = DEFAULT_SERVER_PORT
    pp = DEFAULT_PROXY_PORT
    sniffer = PacketSniffer(sp,pp)
    sniffer.sniff_packets()
    print("here")
    


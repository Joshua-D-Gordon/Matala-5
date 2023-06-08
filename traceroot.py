from scapy.all import IP, ICMP, sr1

class Traceroute:
    def __init__(self, destination):
        self.destination = destination

    def send_packet(self, ttl):
        packet = IP(dst=self.destination, ttl=ttl) / ICMP()
        reply = sr1(packet, verbose=False, timeout=5)
        if reply is not None:
            return reply.src
        #else:
            #return ""

    def run(self):
        ttl = 1
        while True:
            router_ip = self.send_packet(ttl)
            if router_ip == "*":
                print(f"{ttl}: *")
            else:
                print(f"{ttl}: {router_ip}")

            if router_ip == self.destination:
                break

            ttl += 1

if __name__ == "__main__":
    destination = '8.8.8.8'
    traceroute = Traceroute(destination)
    traceroute.run()

    
    
    '''from scapy.all import IP, ICMP, sr1

def traceroute(destination):
    ttl = 1
    max_hops = 30
    dst_reached = False

    print("Traceroute to", destination)

    while not dst_reached and ttl <= max_hops:
        packet = IP(dst=destination, ttl=ttl) / ICMP()
        reply = sr1(packet, verbose=False)

        if reply is None:
            print(ttl, "* * *")
        elif reply.type == 0:
            print(ttl, reply.src)
            dst_reached = True
        else:
            print(ttl, reply.src)

        ttl += 1

    if not dst_reached:
        print("Destination not reached within", max_hops, "hops")

# Usage example
traceroute("www.example.com")
'''
class traceroot:
    def __init__(self, destip):
        self.ttl = 1
        self.destip = destip
    def run(self):
        current_ip = 0
        while self.destip != current_ip:
            #send packet with self.ttl
            #current_ip = returned ip
            #self.ttl+=1
    
    
    
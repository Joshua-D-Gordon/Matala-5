class spoofer:
    def __init__(self, protocol, fake_senders_ip):
        self.protocol = protocol
        self.fakeid = fake_senders_ip

    def run(self):
        match(self.protocol):
            case "ICMP":
                return

            case "UDP":
                return
            case "TCP":
                return
            case _:
                return
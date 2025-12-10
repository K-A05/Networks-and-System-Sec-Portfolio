import subprocess
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, conf, get_if_addr
"""
Defining a worm class object that can simulate the actions of a network worm, including ARP scanning, ICMP flushing, and MAC address fingerprinting.
Key Concepts
• Worm Propagation: The method by which a worm spreads across a network, often by scanning for vulnerable hosts.
• ARP Scanning: A technique to discover live hosts on a local network by sending ARP requests.
• ICMP Flushing: Sending ICMP echo requests (pings) to determine if hosts are alive and measure response times.
• MAC Address Fingerprinting: Identifying device manufacturers based on MAC address prefixes (OUIs).    
"""

class Worm:
    def __init__(self, range="192.168.1.0/24"): # initialise the propogation simulator with a network range
        self.network_range = range
        self.vendor_map = self.load_oui_map()

    def arp_scan(self):
        # Create an ARP request packet
        arp = ARP(pdst=self.network_range) # create ARP packet and set detination IP to network range
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=2, verbose=0)[0]
        live_hosts = []
        for sent, received in result:
            vendor = self.get_mac_vendor(received.hwsrc)
            live_hosts.append({'ip': received.psrc, 'mac': received.hwsrc, 'vendor': vendor})
        return live_hosts
    
    def icmp_flush(self, hosts):
        responses = {}
        for host in hosts:
            import time
            start = time.time()
            packet = IP(dst=host) / ICMP()
            reply = sr1(packet, timeout=1, verbose=0)
            end = time.time()
            rtt = round((end - start) * 1000, 2)  # RoundTripTime in milliseconds
            if reply:
                responses[host] = {"status": "Alive", "rtt_ms": rtt}
            else:
                responses[host] = {"status": "No response", "rtt_ms": None}
        return responses
    
    def load_oui_map(self):
        venor_map = {}
        try:
            with open("oui.txt", "r") as f:
                for line in f:
                    if "(hex)" in line:
                        parts = line.split("(hex)")
                        vendor_oui = parts[0].strip().replace("-", ":")
                        vendor_name = parts[1].strip()
                        venor_map[vendor_oui] = vendor_name
        except FileNotFoundError:
            print("OUI file not found. MAC fingerprinting will be limited.")
            return venor_map
        print(venor_map)

    def mac_fingerprint(self, ip):
        
        oui = get_if_addr().upper()[0:8]
        vendor = self.vendor_map.get(oui, "Unknown Vendor")
        if vendor == "Unknown Vendor":
            try:
                result = subprocess.run(["curl", "-s", f"https://api.macvendors.com/{oui}"], capture_output=True, text=True)
                if result.returncode == 0 and result.stdout:
                    vendor = result.stdout.strip()
            except Exception as e:
                print(f"Error fetching vendor from API: {e}")

        return vendor   
                 
    
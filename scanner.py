from scapy.all import ARP, Ether, srp
from tabulate import tabulate

def scan_network(ip_range):
    # create ARP request packet
    arp = ARP(pdst = ip_range)
    ether = Ether(dst = "ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    print(f"[+] Scanning network {ip_range}...\n")

    result = srp(packet, timeout = 2, verbose = 0)[0]

    devices = []

    for sent, received in result:
        devices.append({
            'IP': received.psrc,
            'MAC': received.hwsrc
        })

    return devices

def display(devices):
    print(tabulate(devices, headers="keys"))

if __name__ == "__main__":
    target_range = "192.168.29.0/24"
    scanned_devices = scan_network(target_range)
    display(scanned_devices)
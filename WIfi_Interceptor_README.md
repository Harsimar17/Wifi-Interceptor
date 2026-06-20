# WiFi Interceptor

An **educational** ARP-spoofing man-in-the-middle (MITM) tool that discovers
every device on your local network, routes their traffic through your machine,
and prints the domains they visit — extracted from **TLS SNI** (works even when
DNS is encrypted) and **plaintext DNS**.

> ⚠️ **Legal / ethical warning**
> ARP spoofing intercepts other people's network traffic. Run this **only** on a
> network you own and **only** against devices you have explicit permission to
> monitor. Doing this to devices or networks you don't control is illegal in
> most jurisdictions, even on home WiFi. You are responsible for how you use it.

---

## What it does

1. **Scans the subnet** (ARP scan) to find all connected devices.
2. **Spoofs ARP** so each device thinks your machine is the router, and the
   router thinks your machine is each device.
3. **Enables IP forwarding** so traffic still reaches the internet (devices keep
   working — you're a transparent relay, not a black hole).
4. **Sniffs and prints domains** each device connects to:
   - `[SNI]` — hostname from the TLS ClientHello (visible even with HTTPS).
   - `[DNS]` — plaintext DNS queries (only if the device isn't using DoH/DoT).
5. **Restores ARP tables** on exit (Ctrl+C) so the network isn't left broken.

Output is tagged by the source device's IP, and currently filtered to hosts
starting with `www.`:

```
[192.168.1.41] [SNI] www.youtube.com
[192.168.1.55] [SNI] www.amazon.com
```

---

## Requirements

- Python 3.x
- [scapy](https://scapy.net/)
- Root / admin privileges (raw sockets)
- macOS or Linux (Windows partially supported — see notes)

```bash
pip install scapy
```

---

## Usage

```bash
sudo python3 WIfi_Interceptor.py
```

Press **Ctrl+C** to stop — it will restore the ARP tables before exiting.

---

## Configuration

Settings are constants near the top of `main()`:

| Setting      | Default            | Description                                  |
|--------------|--------------------|----------------------------------------------|
| `gateway_ip` | `192.168.1.1`      | Your router's IP.                            |
| `subnet`     | `192.168.1.0/24`   | The network range to scan and spoof.         |

Find your gateway IP with `ip route` (Linux) / `netstat -nr` (macOS) /
`ipconfig` (Windows). Adjust `subnet` to match your network.

### Filtering output

- **`www.` filter** — `show()` only prints hosts starting with `www.`. Remove the
  `if not host.startswith("www."): return` line to see everything.
- **Noise filter** — `NOISE_DOMAINS` hides known ad/tracker/telemetry domains.
  Add or remove registered domains (eTLD+1) to taste.
- **Root-domain collapse** — `root_domain()` reduces subdomains to their
  registered domain and handles multi-part TLDs (e.g. `bbc.co.uk`).

---

## How domain detection works

| Technique | Sees | Limitation |
|-----------|------|------------|
| **TLS SNI** | The hostname in each new HTTPS handshake | Only at connection *start*; reused/kept-alive connections send no new ClientHello. Hidden by ECH / iCloud Private Relay. |
| **Plaintext DNS** | Domains looked up over UDP port 53 | Most modern phones encrypt DNS (DoH/DoT), so this is often empty. |

Because of this, you only see a domain **at the moment a fresh connection is
made**. To force already-open connections to reappear, toggle the target
device's WiFi off/on so everything reconnects with new handshakes.

---

## Troubleshooting

- **No devices found** — check `subnet`/`gateway_ip` match your network; make
  sure you're on WiFi.
- **`Could not resolve MAC`** — the device may be offline or on a different
  subnet. The script also falls back to the system ARP cache.
- **`WARNING: ... Ethernet destination MAC`** — suppressed via the scapy logger;
  packets are sent at layer 2 with explicit Ethernet headers.
- **SNI always `None`** — you're inspecting an already-established connection
  (record type `0x17` = application data). Open a *new* connection to see the
  `0x16` ClientHello.
- **Nothing prints even on fresh connections** — the ARP spoof isn't taking
  effect (some APs have client isolation / dynamic ARP inspection). Verify with:
  ```bash
  sudo tcpdump -i en0 -n "host <device-ip> and tcp port 443"
  ```
- **Private Relay** — on iPhone, disable Settings → iCloud → Private Relay, or
  SNI will be hidden.

---

## Disclaimer

This project is provided for **educational and authorized security-testing
purposes only**. The author assumes no liability for misuse.

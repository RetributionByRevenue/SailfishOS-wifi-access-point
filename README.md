# SailfishOS Wi-Fi Access Point + VPN Travel Router

Turn a SailfishOS phone into a discreet Wi-Fi access point whose clients are routed exclusively through an OpenVPN tunnel — with a permanent, stateless kill switch that prevents any AP client traffic from leaking outside the tunnel, even during VPN setup, outages, or reconnects.

<img src=https://raw.githubusercontent.com/RetributionByRevenue/SailfishOS-wifi-access-point/refs/heads/main/wifi.PNG>

The phone's Wi-Fi chip is operated in concurrent station + AP mode. `wlan0` connects upstream as a normal client; a virtual `wlan1` interface is created on the same radio and runs in AP mode, broadcasting `test_ap` on the `10.10.0.0/24` subnet.

<img src="https://github.com/RetributionByRevenue/SailfishOS-wifi-access-point/blob/main/wlan1_dhcp_server%20screenshot.PNG?raw=true">

A small Python DHCP server (built on Scapy) hands out leases to AP clients. You will need to create a Python virtual environment and `pip install scapy` for this piece.

---

## Network topology

```
                    +------------------------+
   AP client  --->  | wlan1 (test_ap)        |  10.10.0.0/24
   (10.10.0.x)      |   |                    |
                    |   v                    |
                    | iptables FORWARD       |   <-- kill switch lives here
                    |   |                    |
                    |   v                    |
                    | tun0 (OpenVPN)         |  <-- only allowed egress
                    |   |                    |
                    |   v                    |
                    | wlan0 (or rmnet)       |  <-- upstream
                    +------------------------+
```

The only allowed exit for AP traffic is `tun0`. Every other egress path is dropped at the kernel forwarding layer.

---

## Anti-leak design (how it doesn't leak)

The hardened script installs one iptables rule and never removes it during normal operation:

```bash
iptables -A FORWARD -i wlan1 ! -o tun+ -j DROP
```

Read literally: **any packet entering from `wlan1` whose outgoing interface is not a `tun*` device gets dropped, period.**

This rule is *stateless* and *always-on*. It doesn't care what phase the script is in, whether the VPN is up, restarting, dead, or never started. The implications across every realistic failure mode:

| Scenario | Kill switch effect |
|---|---|
| Script just started, no `tun0` yet | All `wlan1` traffic dropped → fail-closed during setup |
| VPN tunnel up, normal operation | `wlan1 → tun0` allowed; `wlan1 → wlan0` dropped → no leak |
| Modem outage, openvpn retrying | `tun0` still exists, can't deliver → packets fail silently |
| openvpn crashes, `tun0` gone | All `wlan1` traffic instantly drops → no exposure window |
| Routes get reshuffled by ConnMan | Rule keys on *interface*, not routing → still safe |

There is no point in time, including the VPN-handshake window, where an AP client can send a packet out via `wlan0` or cellular. The original 30 s blind sleep used to be an exposure window; the kill switch closes it permanently.

Compare to a routing-only approach (just changing the default route to `tun0`): if the route is removed for any reason (interface down, ConnMan re-adding its own default, openvpn exiting), traffic falls back to whatever default route exists — typically the real upstream. The kill switch is independent of routing; it survives all that.

---

## Other features

**Active VPN readiness probe** — instead of `sleep 30`, the script polls `ip link show tun0 up` AND `ping -I tun0 8.8.8.8` once per second for up to 600 s. The script proceeds only when the tunnel is verified end-to-end reachable.

**Glanceable physical status indicator** — a background daemon pings `8.8.8.8` every few seconds. The phone's blue LED is solid when the path to the internet is alive and dark when ping shows 100% packet loss. Lets you see at a glance whether your travel router is working without unlocking the phone.

**Step-by-step progress trace** — every phase of setup and teardown prints a numbered cyan banner (`==> step N/15: ...`) so you can see exactly what's happening and where any failure occurred.

**Clean teardown** — pressing `2` at the prompt at the end runs a 9-step reset: kills the DHCP server, LED daemon, wpa_supplicants, and openvpn; flushes iptables (NAT + FORWARD); restores `FORWARD` policy to `ACCEPT`; removes `tun0`; deletes the virtual `wlan1`; flushes residual routes; disables IP forwarding; restarts the normal client `wpa_supplicant` on `wlan0`; toggles ConnMan; and turns off the LED. Returns the phone to plain-Wi-Fi-client state, ready for normal use.

**Self-healing for ordinary outages** — when the modem goes down or your ISP hiccups, the OpenVPN Access Server-style `.ovpn` directives (`keepalive 10 60`, `persist-tun`, `persist-key`, `resolv-retry infinite`) handle reconnection automatically. No script intervention needed. Kill switch keeps you safe during the gap.

**No log accumulation** — every background process (`openvpn`, the LED daemon, the DHCP server) has `>/dev/null 2>&1` on its launch line. `nohup.out` is not created. journald entries from `wpa_supplicant` are bounded by systemd's `SystemMaxUse`.

**Tight, readable output** — the post-setup `netstat -nr` is filtered through `awk` to drop the noisy MSS / Window / irtt columns and aligned to fit IPv4 + CIDR notation cleanly.

---

## What requires user attention

Only one common operation isn't auto-recovered: **toggling Wi-Fi off and on via the phone's UI**. ConnMan tears down both `wpa_supplicant` instances when Wi-Fi is disabled, destroying the virtual `wlan1` AP entirely. ConnMan does not know how to recreate it on re-enable. To recover, press `2` to reset cleanly, then re-run the script.

A real internet outage (modem off, ISP down, VPN server unreachable) does *not* require attention — see the table above.

---

## Requirements

- SailfishOS device with a Wi-Fi chip that supports concurrent station + AP mode on a single radio (tested on Xperia 10 III).
- Root access on the phone (the script uses `iptables`, `iw`, `ip`, writes to `/proc/sys/...` and `/sys/class/leds/...`).
- An OpenVPN client profile at `/home/defaultuser/Desktop/mark-home.ovpn`.
- A Python virtual environment at `/home/defaultuser/python/venv/` with `scapy` installed.
- `wlan1_dhcp_server.py` at `/home/defaultuser/python/wlan1_dhcp_server.py`.

---

## Usage

```bash
# as root
sh main_secure.sh
```

Watch the 15 colored step banners scroll by. When you see:

```
VPN is up -- AP clients will reach internet via tun0
```

…your travel router is live. Connect any client to SSID `test_ap` (PSK `12345678`) and it will egress through the VPN tunnel.

When you're done:

```
Press 2 to reset phone networking (undo all script changes), anything else to ignore:
2
```

Phone returns to normal client-only state.

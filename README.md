# SailfishOS Wi-Fi Access Point + VPN Travel Router

<img src=https://raw.githubusercontent.com/RetributionByRevenue/SailfishOS-wifi-access-point/refs/heads/main/wifi.PNG>

Phone makes Wi-Fi. Clients join it. All their traffic goes out an OpenVPN tunnel.

Tunnel down = clients get nothing. They never fall back to the café Wi-Fi.

One file, `router.py`. Python 3 standard library only. No pip, no venv, no scapy.
Runs on the `python3` SailfishOS already ships.

---

## Run

```bash
devel-su ./router.py
```

Setup steps scroll by, then a live dashboard. When **VPN TUNNEL** says `HEALTHY`,
join SSID `test_ap` (PSK `12345678` — change it) and you are through the tunnel.

`r` reconnect · `q` tear down and quit · `Ctrl-C` close dashboard, router keeps running

```bash
devel-su ./router.py --headless   # no dashboard
devel-su ./router.py --status     # is it alive, is it leaking
devel-su ./router.py --down       # stop, restore normal Wi-Fi
devel-su ./router.py --stage N    # build only part of it
```

Note the `./` — `router.py` is not on root's PATH.

---

## Stages

Build it in pieces. Handy over SSH, because the full stage bounces `wlan0`.

| stage | adds | safe over Wi-Fi SSH |
|-------|------|---------------------|
| 1 | dashboard, OpenVPN, supervisor | yes |
| 2 | `wlan1` AP, DHCP server | yes |
| 3 | leak guard, NAT, routing, ConnMan | **no** |

Steps that drop your link are tagged `[SSH-KILLER]`. `--down` undoes only the
stage that was built.

---

## How it can't leak

Two layers. Either one alone stops it. Both are re-checked every 4 seconds and
rebuilt if they drift.

**netfilter** — `FORWARD` policy is `DROP`, with one ACCEPT for `wlan1 → tun+`.
Flush the chain and it is still closed, because the policy is the guarantee, not
the rule.

**routing** — `wlan1` gets its own routing table whose fallback is a blackhole.
No tunnel means the packet dies during route lookup, before netfilter is even
consulted. So netfilter failing completely is still not enough to leak.

NAT is `-o tun+` only. Masquerading out `wlan0` could only ever turn a leak into
a *working* leak.

Read `install_leak_guard()` and `install_ap_policy_route()`. Code is law.

---

## Needs

- SailfishOS phone whose Wi-Fi does station + AP at once (tested: Xperia 10 III)
- root
- an OpenVPN profile at `/home/defaultuser/Desktop/mark-home.ovpn`
- `python3`

SSID, PSK, paths and timeouts are constants at the top of `router.py`.

---

## Real world

VPN server on an Ubuntu laptop in **Canada**. Phone in **Malaysia**. A client on
`test_ap` measured **~23 Mbps down / ~44 Mbps up** through the tunnel. Auto-reconnect
has been watched recovering on its own after upstream Wi-Fi dropped.

---

## Architecture

```mermaid
flowchart TB
    subgraph clients["AP clients · 10.10.0.x"]
        C["laptop / phone / tablet"]
    end

    subgraph phone["SailfishOS phone · Malaysia"]
        direction TB
        WLAN1["wlan1 — AP<br/>SSID test_ap<br/>gateway 10.10.0.1/24"]
        DHCP["DHCP server thread<br/>stdlib socket, bound to wlan1"]
        LG{"iptables FORWARD<br/>leak guard<br/>from wlan1, not out tun+ = DROP"}
        TUN0["tun0 — OpenVPN client"]
        NAT["NAT MASQUERADE<br/>src 10.10.0.0/16"]
        WLAN0["wlan0 — station<br/>upstream Wi-Fi client"]
        SUP(["supervisor<br/>ping -I tun0 every 4s<br/>kill + redial on failure"])
    end

    NET(("public Internet"))

    subgraph canada["Ubuntu 20.04 laptop · Canada"]
        AS["OpenVPN Access Server"]
    end

    EXIT(("Internet · VPN exit"))

    C -. "DHCP lease" .-> DHCP
    C == "client traffic" ==> WLAN1
    WLAN1 ==> LG
    LG == "egress via tun+ (allowed)" ==> TUN0
    LG -. "any other egress" .-> X["DROP · fail-closed"]
    TUN0 ==> NAT
    NAT ==> WLAN0
    WLAN0 == "encrypted tunnel" ==> NET
    NET ==> AS
    AS ==> EXIT

    SUP -. monitors .-> TUN0
    SUP -. monitors .-> WLAN0

    classDef guard fill:#fdecea,stroke:#c0392b,color:#111;
    classDef drop fill:#f8d7da,stroke:#842029,color:#842029;
    class LG guard;
    class X drop;
```

#!/usr/bin/env python3
# =============================================================================
#  SailfishOS Travel Router  ·  single file, stdlib only
# -----------------------------------------------------------------------------
#  Turns the phone into a Wi-Fi AP (test_ap on wlan1) whose clients are routed
#  exclusively through an OpenVPN tunnel (tun0). A stateless, always-on iptables
#  leak guard drops any AP traffic not egressing via tun+, so clients are
#  fail-closed during setup, outages and reconnects.
#
#  One process, three threads:
#      main       -- full-screen live dashboard (pure ANSI, no curses)
#      dhcp       -- DHCP server for AP clients (socket + struct, no scapy)
#      supervisor -- verifies the tunnel passes traffic; redials when it doesn't
#
#  No pip, no venv, no scapy. Everything here is Python 3 standard library;
#  device orchestration shells out to iw / iptables / ip / wpa_supplicant /
#  openvpn / dbus-send, exactly as the original shell version did.
#
#  Usage (as root, e.g. `devel-su ./router.py`):
#      ./router.py             bring the router up and show the dashboard
#      ./router.py --headless  bring it up with no dashboard (for SSH/cron)
#      ./router.py --status    one-shot snapshot of a running router
#      ./router.py --down      tear down a running router and restore Wi-Fi
#
#  Keys:  [r] force reconnect now   [q] tear down & quit
# =============================================================================

import ipaddress
import json
import os
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
import tty
from collections import deque
from datetime import datetime

# ----------------------------- configuration ---------------------------------
AP_SSID   = "test_ap"                 # broadcast network name
AP_PSK    = "12345678"                # AP pre-shared key (WPA2)
AP_IFACE  = "wlan1"                   # virtual AP interface
AP_ADDR   = "10.10.0.1"               # AP gateway address
AP_CIDR   = 24
AP_MAC    = "12:34:56:78:ab:ce"       # AP L2 identity
AP_FREQ   = 2412                      # 2412 MHz == channel 1
AP_SUBNET = "10.10.0.0/24"            # pool the DHCP server hands out from
NAT_SRC   = "10.10.0.0/16"            # source range to masquerade
WAN_IFACE = "wlan0"                   # upstream station interface

OVPN_CONFIG = "/home/defaultuser/Desktop/mark-home.ovpn"
LED_PATH    = "/sys/class/leds/blue/brightness"

PROBE_HOST        = "8.8.8.8"         # reachability target
CHECK_INTERVAL    = 4                 # supervisor poll cadence (s)
DIAL_TIMEOUT      = 90                # reconnect: wait for tun0 (s)
INIT_DIAL_TIMEOUT = 600               # first boot: wait for tun0 (s)
UI_REFRESH        = 1.0               # dashboard refresh / key poll (s)

DNS_SERVERS = ["8.8.8.8", "8.8.4.4"]
LEASE_TIME  = 86400                   # 24h; T1/T2 are derived from this
DECLINE_HOLD = 3600                   # keep a declined address out of the pool

# ------------------------------ runtime state --------------------------------
STATE_DIR   = "/tmp/travelrouter"
STATUS_FILE = os.path.join(STATE_DIR, "status")
EVENTS_FILE = os.path.join(STATE_DIR, "events")
GW_FILE     = os.path.join(STATE_DIR, "wlan0_gw")
LEASE_FILE  = os.path.join(STATE_DIR, "dhcp_leases.json")
PID_FILE    = os.path.join(STATE_DIR, "router.pid")
STAGE_FILE  = os.path.join(STATE_DIR, "stage")

# Bring-up is staged so the router can be built incrementally over SSH. Each
# stage is a superset of the one below it. Stages 1 and 2 deliberately avoid
# every step that would drop the connection you are typing on.
STAGE_DESC = {
    1: "dashboard + OpenVPN + supervisor (no AP, no iptables) — safe over SSH",
    2: "stage 1 + virtual wlan1 AP + DHCP server + INPUT rule — safe over SSH",
    3: "full router: leak guard, NAT, tunnel routing, ConnMan — WILL drop SSH",
}
FULL_STAGE = 3

# --------------------------------- colours -----------------------------------
ESC       = "\033"
C_RESET   = ESC + "[0m";  C_BOLD = ESC + "[1m";  C_DIM = ESC + "[2m"
C_RED     = ESC + "[31m"; C_GRN  = ESC + "[32m"; C_YEL = ESC + "[33m"
C_CYN     = ESC + "[36m"
CLR_EOL   = ESC + "[K";   CUR_HOME = ESC + "[H"; CLR_DOWN = ESC + "[J"
CUR_HIDE  = ESC + "[?25l"; CUR_SHOW = ESC + "[?25h"
CLR_SCREEN = ESC + "[2J"


# =============================================================================
#  shared state  --  written by worker threads, read by the dashboard
# =============================================================================
class State:
    """Everything the UI needs to render, guarded by one lock.

    The shell version published this to a status file because the supervisor
    was a separate process. In-process threads can share it directly; the file
    is still written so `--status` works from another shell.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.vpn = "starting"          # healthy | reconnecting | down | starting
        self.wan = "unknown"
        self.ssid = ""
        self.attempts = 0
        self.msg = "starting…"
        self.ts = "--:--:--"
        self.events = deque(maxlen=200)
        self.dhcp_alive = False
        self.dhcp_leases = 0
        self.stage = FULL_STAGE
        self.stop = threading.Event()   # set once, tears every thread down

    def update(self, **kw):
        with self._lock:
            for k, v in kw.items():
                setattr(self, k, v)
            self.ts = time.strftime("%H:%M:%S")
            snap = {
                "VPN": self.vpn, "WAN": self.wan, "SSID": self.ssid,
                "ATTEMPTS": self.attempts, "LASTMSG": self.msg, "TS": self.ts,
                "DHCP": "up" if self.dhcp_alive else "down",
                "LEASES": self.dhcp_leases,
            }
        _write_status_file(snap)

    def snapshot(self):
        with self._lock:
            return {
                "vpn": self.vpn, "wan": self.wan, "ssid": self.ssid,
                "attempts": self.attempts, "msg": self.msg, "ts": self.ts,
                "dhcp_alive": self.dhcp_alive, "dhcp_leases": self.dhcp_leases,
                "stage": self.stage, "events": list(self.events),
            }

    def log(self, line):
        stamped = "%s %s" % (time.strftime("%H:%M:%S"), line)
        with self._lock:
            self.events.append(stamped)
        try:
            with open(EVENTS_FILE, "a") as fh:
                fh.write(stamped + "\n")
        except OSError:
            pass


STATE = State()


def _write_status_file(snap):
    try:
        tmp = STATUS_FILE + ".tmp"
        with open(tmp, "w") as fh:
            for k, v in snap.items():
                fh.write("%s=%s\n" % (k, v))
        os.replace(tmp, STATUS_FILE)
    except OSError:
        pass


# =============================================================================
#  small helpers
# =============================================================================
# On SailfishOS the tools we shell out to live in /sbin and /usr/sbin, which are
# NOT on defaultuser's PATH (that is just /usr/local/bin:/bin:/usr/bin). Depending
# on how the script is invoked we may inherit that restricted PATH, in which case
# every ip/iptables/iw/openvpn call would fail with ENOENT and be silently
# swallowed by sh(). Guarantee they are reachable.
for _sbin in ("/sbin", "/usr/sbin", "/usr/local/sbin"):
    _parts = os.environ.get("PATH", "").split(":")
    if _sbin not in _parts:
        os.environ["PATH"] = ":".join([_ for _ in _parts if _] + [_sbin])


def require_tools():
    """Names we depend on, and where they actually resolve. Empty list == fine."""
    import shutil
    needed = ["ip", "iw", "iptables", "openvpn", "wpa_supplicant", "ping", "pkill"]
    return [t for t in needed if shutil.which(t) is None]


def sh(cmd, timeout=15, capture=True):
    """Run a command. Returns (rc, stdout). Never raises, never blocks forever."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        out = proc.stdout.decode("utf-8", "replace") if capture else ""
        return proc.returncode, out
    except (subprocess.TimeoutExpired, OSError):
        return 1, ""


def ok(cmd, timeout=15):
    return sh(cmd, timeout=timeout, capture=False)[0] == 0


def led(on):
    try:
        with open(LED_PATH, "w") as fh:
            fh.write("255" if on else "0")
    except OSError:
        pass


# ---- connectivity predicates -------------------------------------------------
def iface_up(name):
    rc, out = sh(["ip", "-o", "link", "show", name])
    return rc == 0 and "state UP" in out


def tun_up():
    return ok(["ip", "link", "show", "tun0", "up"])


def ap_on_air():
    """wlan1 being UP is NOT the same as the SSID being broadcast. The beacon
    only exists once the AP wpa_supplicant is running; if it failed to start,
    the interface still shows UP with an address and looks fine. Check for an
    actual SSID on the interface instead."""
    rc, out = sh(["iw", "dev", AP_IFACE, "info"])
    return rc == 0 and re.search(r"^\s*ssid\s+\S", out, re.M) is not None


_IPT_W = None


def ipt(*args):
    """iptables argv, with -w when supported.

    Without -w, a call that loses the xtables lock fails outright. render()
    polls iptables twice a second while the supervisor and install_nat() also
    call it, so contention is routine -- and because ok() swallows failures, a
    lost lock during the leak-guard install would silently leave the router
    open. -w makes the call wait instead of fail.
    """
    global _IPT_W
    if _IPT_W is None:
        _IPT_W = ["-w"] if sh(["iptables", "-w", "-S", "FORWARD"],
                              capture=False)[0] == 0 else []
    return ["iptables"] + _IPT_W + list(args)


# FORWARD rules, in install order. The AP is default-denied by the chain POLICY,
# not merely by a rule, so a flushed chain is closed rather than open.
AP_ALLOW_RULE  = ["-i", AP_IFACE, "-o", "tun+", "-j", "ACCEPT"]
LEAK_GUARD_RULE = ["-i", AP_IFACE, "!", "-o", "tun+", "-j", "DROP"]
OTHER_FWD_RULE = ["!", "-i", AP_IFACE, "-j", "ACCEPT"]

DHCP_IN_RULE = ["-i", AP_IFACE, "-p", "udp", "--dport", "67", "-j", "ACCEPT"]


def dhcp_input_allowed():
    return ok(ipt("-C", "INPUT", *DHCP_IN_RULE))


def allow_dhcp_input():
    """Let client DHCP reach our socket.

    SailfishOS runs ConnMan's firewall with `-P INPUT DROP`, and connman-INPUT
    has no rule for inbound DHCP: its only DHCP rule is `--sport 67 --dport 68`,
    which is the phone acting as a *client*, and its blanket UDP ACCEPT only
    covers `--dports 1024:65535`, so port 67 falls through to the DROP policy.

    The scapy implementation never hit this, because sniff() uses an AF_PACKET
    socket that sees frames BEFORE netfilter's INPUT chain runs. A plain UDP
    socket sits after it, so every client DISCOVER was silently dropped.

    Inserted at position 1, ahead of the jump to connman-INPUT, so ConnMan
    rewriting its own chain cannot shadow it. Re-asserted by the supervisor
    because the ConnMan Wi-Fi toggle at stage 3 rebuilds those rules.
    """
    if not dhcp_input_allowed():
        ok(ipt("-I", "INPUT", "1", *DHCP_IN_RULE))
    return dhcp_input_allowed()


def deny_dhcp_input():
    ok(ipt("-D", "INPUT", *DHCP_IN_RULE))


def leak_guard_on():
    """True only if AP traffic cannot forward anywhere except tun+.

    Checks the chain POLICY as well as the DROP rule. The rule alone is not the
    guarantee: with policy ACCEPT, an empty FORWARD chain forwards everything.
    """
    rc, out = sh(ipt("-S", "FORWARD"))
    if rc != 0 or "-P FORWARD DROP" not in out:
        return False
    return ok(ipt("-C", "FORWARD", *LEAK_GUARD_RULE))


def install_leak_guard():
    """Make the AP fail closed, and keep it closed even if this chain is flushed.

    Policy DROP is the load-bearing part. Previously the guard was a single DROP
    rule in a chain whose policy was ACCEPT, so any flush -- ours at setup,
    ConnMan rebuilding its chains, or a crash between flush and re-add -- left
    FORWARD empty and *open* while wlan1 was already beaconing and ip_forward
    was already 1. With policy DROP an empty chain is closed.

    OTHER_FWD_RULE keeps the phone's unrelated forwarding (USB/Bluetooth
    tethering) working. It is added last on purpose: if it is ever lost, the
    failure is restrictive rather than permissive.
    """
    ok(ipt("-F", "FORWARD"))
    ok(ipt("-P", "FORWARD", "DROP"))
    for rule in (AP_ALLOW_RULE, LEAK_GUARD_RULE, OTHER_FWD_RULE):
        ok(ipt("-A", "FORWARD", *rule))
    return leak_guard_on()


def release_leak_guard():
    """Undo install_leak_guard(). Only for teardown."""
    ok(ipt("-F", "FORWARD"))
    ok(ipt("-P", "FORWARD", "ACCEPT"))


def vpn_ok():
    """Healthy only if tun0 is up AND actually passes traffic through itself."""
    return tun_up() and ok(["ping", "-I", "tun0", "-c1", "-W2", PROBE_HOST], timeout=6)


def upstream_ok():
    return iface_up(WAN_IFACE) and ok(
        ["ping", "-c1", "-W2", "-I", WAN_IFACE, PROBE_HOST], timeout=6
    )


def default_route_dev():
    rc, out = sh(["ip", "route", "show", "default"])
    m = re.search(r"dev (\S+)", out)
    return m.group(1) if m else ""


def egress_dev(dest=PROBE_HOST):
    """Which interface traffic to `dest` ACTUALLY leaves by.

    Reading the `default` route alone lies here. OpenVPN's `redirect-gateway
    def1` installs 0.0.0.0/1 and 128.0.0.0/1 via tun0; both are more specific
    than `default`, so they win for every destination except the VPN server
    itself (which gets its own /32 via the real gateway to avoid a loop).
    Meanwhile ConnMan re-adds its own `default via <gw> dev wlan0` for the
    managed service whenever it reconnects. So the default route can read wlan0
    while 100% of traffic is tunnelled. Ask the kernel instead of guessing.
    """
    rc, out = sh(["ip", "route", "get", dest])
    m = re.search(r"\bdev\s+(\S+)", out)
    return m.group(1) if rc == 0 and m else ""


def client_egress_dev(dest=PROBE_HOST):
    """Same question, but for a packet arriving from an AP client."""
    rc, out = sh(["ip", "route", "get", dest, "from", AP_ADDR.rsplit(".", 1)[0] + ".2",
                  "iif", AP_IFACE])
    m = re.search(r"\bdev\s+(\S+)", out)
    return m.group(1) if rc == 0 and m else ""


def ssid_now():
    rc, out = sh(["iw", "dev", WAN_IFACE, "link"])
    m = re.search(r"^\s*SSID: (.+)$", out, re.M)
    return m.group(1).strip() if m else ""


# ---- route management --------------------------------------------------------
def capture_gw():
    rc, out = sh(["ip", "route", "show", "default"])
    for line in out.splitlines():
        if "dev " + WAN_IFACE in line:
            m = re.search(r"via (\S+)", line)
            if m:
                try:
                    with open(GW_FILE, "w") as fh:
                        fh.write(m.group(1))
                except OSError:
                    pass
                return m.group(1)
    return None


def ensure_wlan0_route():
    """We need a path to reach the VPN server before we can dial it."""
    rc, out = sh(["ip", "route", "show", "default"])
    if "dev " + WAN_IFACE in out:
        return True
    try:
        with open(GW_FILE) as fh:
            gw = fh.read().strip()
    except OSError:
        return False
    if not gw:
        return False
    return ok(["ip", "route", "add", "default", "via", gw, "dev", WAN_IFACE])


def route_via_tun():
    for _ in range(16):
        rc, out = sh(["ip", "route", "show", "default"])
        if not out.strip():
            break
        if not ok(["ip", "route", "del", "default"]):
            break
    ok(["ip", "route", "add", "default", "dev", "tun0"])


def clear_ap_nat():
    """Remove MASQUERADE rules for the AP subnet left behind by a previous run.

    Setup never used to do this -- only teardown did -- so after any exit that
    skipped teardown (Ctrl-C, crash, SIGKILL) the old rules were still loaded.
    Combined with an open FORWARD chain that turned a leak into a *working*
    NATed connection out wlan0 rather than a stream of dead packets.

    Only our own rules are removed; flushing POSTROUTING wholesale would also
    destroy ConnMan's tethering NAT.
    """
    rc, out = sh(ipt("-t", "nat", "-S", "POSTROUTING"))
    if rc != 0:
        return
    for line in out.splitlines():
        if line.startswith("-A POSTROUTING") and NAT_SRC in line:
            ok(ipt("-t", "nat", "-D", *line.split()[1:]))


def install_nat(verbose=False):
    """MASQUERADE the AP subnet out tun+ only. Safe to re-run.

    Deliberately *only* tun+. This used to enumerate every interface and
    masquerade out all of them, wlan0 included. For a leak-guarded router that
    is worse than useless: the only egress clients are ever permitted is tun+,
    so a wlan0 rule can never help a legitimate packet -- it can only turn a
    leak into a working connection. It also left ~13 stale rules behind and
    fired 14 iptables calls on every reconnect.

    The wildcard (rather than tun0) matters because when the first dial times
    out there is no tun device yet to enumerate; tun+ covers whatever the VPN
    brings up later, whenever it appears.
    """
    if not ok(ipt("-t", "nat", "-C", "POSTROUTING",
                  "-s", NAT_SRC, "-o", "tun+", "-j", "MASQUERADE")):
        ok(ipt("-t", "nat", "-A", "POSTROUTING",
               "-s", NAT_SRC, "-o", "tun+", "-j", "MASQUERADE"))
    if verbose:
        print("      %smasquerade via tun+ only%s" % (C_DIM, C_RESET))


def vpn_dial():
    STATE.log("dialing OpenVPN (%s)" % OVPN_CONFIG)
    try:
        subprocess.Popen(
            ["openvpn", "--dev", "tun", "--config", OVPN_CONFIG],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        STATE.log("openvpn failed to start: %s" % exc)


def wait_tun(timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if STATE.stop.is_set():
            return False
        if vpn_ok():
            return True
        time.sleep(1)
    return False


def kill_openvpn(timeout=8):
    """SIGTERM openvpn, then verify. It takes a moment to unwind its tunnel, and
    a teardown that returns while it is still alive leaves the VPN up."""
    ok(["pkill", "openvpn"])
    deadline = time.time() + timeout
    while time.time() < deadline:
        if sh(["pgrep", "openvpn"], capture=False)[0] != 0:
            return True
        time.sleep(0.5)
    ok(["pkill", "-9", "openvpn"])
    time.sleep(0.5)
    return sh(["pgrep", "openvpn"], capture=False)[0] != 0


def kill_tunnel():
    kill_openvpn()
    ok(["ip", "route", "flush", "dev", "tun0"])
    ok(["ip", "link", "delete", "tun0"])


# =============================================================================
#  DHCP SERVER  --  stdlib only
# =============================================================================
# Scapy was only ever used to hand-build Ether()/IP()/UDP() frames. None of that
# is needed if replies go out as broadcast, which every mainstream client
# accepts -- so this is a plain UDP socket plus struct.
#
# The SO_BINDTODEVICE call below is load-bearing. Binding ("", 67) alone would
# receive broadcasts arriving on *every* interface, so the server would answer
# DISCOVERs on wlan0 -- i.e. run a rogue DHCP server on whatever café network
# the phone is attached to. sniff(iface=...) used to provide that containment
# implicitly; here it must be explicit.
#
# Note we cannot bind AP_ADDR:67 instead: Linux will not deliver a
# 255.255.255.255 broadcast to a socket bound to a unicast address, so the
# DISCOVER would never arrive.

DHCP_MAGIC = b"\x63\x82\x53\x63"

# option codes we care about
OPT_SUBNET, OPT_ROUTER, OPT_DNS      = 1, 3, 6
OPT_REQUESTED, OPT_LEASE, OPT_TYPE   = 50, 51, 53
OPT_SERVER_ID, OPT_T1, OPT_T2        = 54, 58, 59

DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = 1, 2, 3, 4, 5, 6, 7, 8

SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)


def mac_str(raw):
    return ":".join("%02x" % b for b in raw[:6])


def parse_options(blob):
    """Walk the TLV option block. Returns {code: bytes}."""
    opts, i = {}, 0
    while i < len(blob):
        code = blob[i]
        if code == 0:                      # pad
            i += 1
            continue
        if code == 255:                    # end
            break
        if i + 1 >= len(blob):
            break
        length = blob[i + 1]
        opts[code] = blob[i + 2:i + 2 + length]
        i += 2 + length
    return opts


def encode_options(pairs):
    out = bytearray()
    for code, payload in pairs:
        out += bytes([code, len(payload)]) + payload
    out += b"\xff"
    return bytes(out)


class DHCPServer(threading.Thread):
    """Minimal RFC 2131 server for the AP subnet."""

    daemon = True

    def __init__(self, state, iface=AP_IFACE, server_ip=AP_ADDR,
                 subnet=AP_SUBNET, lease_file=LEASE_FILE, lease_time=LEASE_TIME):
        super().__init__(name="dhcp")
        self.state = state
        self.iface = iface
        self.server_ip = server_ip
        self.subnet = ipaddress.ip_network(subnet)
        self.lease_file = lease_file
        self.lease_time = lease_time
        self.leases = {}                   # mac -> (ip, expires_epoch)
        self.declined = {}                 # ip -> hold-until epoch
        self.sock = None
        self._lock = threading.Lock()
        self.load_leases()

    # ---- lease bookkeeping --------------------------------------------------
    # The scapy version kept leases in memory and refilled the pool from .2 on
    # every start, so restarting it while clients were still associated handed
    # out duplicates. Persisting to disk and deriving the pool from live leases
    # removes that whole class of bug.
    #
    # Leases are {mac: (ip, expires_epoch)}. Without an expiry the pool is never
    # reclaimed: every device that ever associated holds its address forever,
    # and a /24 eventually runs out with no way back short of deleting the file.
    def load_leases(self):
        try:
            with open(self.lease_file) as fh:
                stored = json.load(fh)
        except (OSError, ValueError):
            return
        if not isinstance(stored, dict):
            return
        now = time.time()
        for mac, entry in stored.items():
            ip, expires = None, None
            if isinstance(entry, dict):                   # current format
                ip, expires = entry.get("ip"), entry.get("expires")
            elif isinstance(entry, (list, tuple)) and entry:
                ip = entry[0]                             # legacy (ip, lease_time)
            elif isinstance(entry, str):
                ip = entry                                # legacy bare ip
            if ip is None:
                continue
            try:
                if ipaddress.ip_address(str(ip)) not in self.subnet:
                    continue
            except (ValueError, TypeError):
                continue
            try:
                expires = float(expires)
            except (TypeError, ValueError):
                expires = now + self.lease_time           # legacy: start the clock now
            if expires > now:
                self.leases[mac] = (str(ip), expires)

    def save_leases(self):
        try:
            os.makedirs(os.path.dirname(self.lease_file), exist_ok=True)
            tmp = self.lease_file + ".tmp"
            with open(tmp, "w") as fh:
                json.dump({m: {"ip": ip, "expires": exp}
                           for m, (ip, exp) in self.leases.items()}, fh)
            os.replace(tmp, self.lease_file)
        except OSError as exc:
            self.state.log("dhcp: could not persist leases: %s" % exc)

    def prune_expired(self):
        """Drop leases past their expiry, and release declined holds. Caller
        holds the lock."""
        now = time.time()
        dead = [m for m, (_, exp) in self.leases.items() if exp <= now]
        for m in dead:
            ip, _ = self.leases.pop(m)
            self.state.log("dhcp: lease expired %s (%s)" % (ip, m))
        for ip in [i for i, until in self.declined.items() if until <= now]:
            del self.declined[ip]
            self.state.log("dhcp: declined address %s returned to the pool" % ip)
        return dead

    def pool(self):
        return [str(ip) for ip in self.subnet.hosts() if str(ip) != self.server_ip]

    def _blocked(self, mac):
        """Addresses we must not hand to `mac`: held by another client on an
        unexpired lease, or recently declined as already-in-use."""
        now = time.time()
        blocked = {ip for m, (ip, exp) in self.leases.items()
                   if m != mac and exp > now}
        blocked |= {ip for ip, until in self.declined.items() if until > now}
        return blocked

    def lease_for(self, mac):
        with self._lock:
            self.prune_expired()
            now = time.time()
            if mac in self.leases:                        # renew in place
                ip, _ = self.leases[mac]
                self.leases[mac] = (ip, now + self.lease_time)
                self.save_leases()
                return ip
            taken = self._blocked(mac)
            for ip in self.pool():
                if ip not in taken:
                    self.leases[mac] = (ip, now + self.lease_time)
                    self.save_leases()
                    self.state.dhcp_leases = len(self.leases)
                    return ip
        return None

    def claim(self, mac, ip):
        """Grant a specific address if it is ours to give and unheld."""
        try:
            addr = ipaddress.ip_address(str(ip))
        except ValueError:
            return False
        if addr not in self.subnet or str(addr) == self.server_ip:
            return False
        with self._lock:
            self.prune_expired()
            if str(addr) in self._blocked(mac):
                return False
            self.leases[mac] = (str(addr), time.time() + self.lease_time)
            self.save_leases()
            self.state.dhcp_leases = len(self.leases)
        return True

    def lease_ip(self, mac):
        """Current unexpired address for a client, or None."""
        with self._lock:
            entry = self.leases.get(mac)
            if entry and entry[1] > time.time():
                return entry[0]
        return None

    def release(self, mac):
        with self._lock:
            if self.leases.pop(mac, None):
                self.save_leases()
                self.state.dhcp_leases = len(self.leases)

    # ---- wire format --------------------------------------------------------
    def build_reply(self, req, msg_type, yiaddr, lease_opts=True):
        xid, flags, giaddr, chaddr = req["xid"], req["flags"], req["giaddr"], req["chaddr"]
        yi = socket.inet_aton(yiaddr) if yiaddr else b"\x00" * 4
        pkt = struct.pack(
            "!BBBBIHH4s4s4s4s16s64s128s",
            2, 1, 6, 0,          # op=BOOTREPLY, ethernet, 6-byte mac, hops
            xid, 0, flags,
            b"\x00" * 4,         # ciaddr
            yi,                  # yiaddr
            socket.inet_aton(self.server_ip),   # siaddr
            giaddr,
            chaddr.ljust(16, b"\x00"),
            b"\x00" * 64,        # sname
            b"\x00" * 128,       # file
        )
        opts = [(OPT_TYPE, bytes([msg_type])),
                (OPT_SERVER_ID, socket.inet_aton(self.server_ip))]
        if msg_type in (OFFER, ACK):
            # Network parameters go in every ACK/OFFER, but RFC 2131 4.3.5 says
            # a reply to an INFORM MUST NOT carry lease timing -- the client
            # configured its own address and holds no lease from us.
            opts += [
                (OPT_SUBNET, socket.inet_aton(str(self.subnet.netmask))),
                (OPT_ROUTER, socket.inet_aton(self.server_ip)),
                (OPT_DNS, b"".join(socket.inet_aton(d) for d in DNS_SERVERS)),
            ]
            if lease_opts:
                opts += [
                    (OPT_LEASE, struct.pack("!I", self.lease_time)),
                    (OPT_T1, struct.pack("!I", self.lease_time // 2)),
                    (OPT_T2, struct.pack("!I", self.lease_time * 7 // 8)),
                ]
        return pkt + DHCP_MAGIC + encode_options(opts)

    def send(self, payload, dest="255.255.255.255"):
        try:
            self.sock.sendto(payload, (dest, 68))
        except OSError as exc:
            self.state.log("dhcp: send failed: %s" % exc)

    # ---- request handling ---------------------------------------------------
    def requested_addr(self, req):
        """The address a client is asking us to confirm.

        Renewing clients (RFC 2131 §4.3.2, RENEWING/REBINDING) send a REQUEST
        with no requested_addr option at all -- the address lives in ciaddr.
        The scapy version treated a missing option as invalid and returned
        without replying, so every renewal at T1 was silently dropped.
        """
        if OPT_REQUESTED in req["opts"] and len(req["opts"][OPT_REQUESTED]) == 4:
            return socket.inet_ntoa(req["opts"][OPT_REQUESTED])
        if req["ciaddr"] != "0.0.0.0":
            return req["ciaddr"]
        return None

    def handle_discover(self, req):
        ip = self.lease_for(req["mac"])
        if not ip:
            self.state.log("dhcp: pool exhausted, no offer for %s" % req["mac"])
            return
        self.state.log("dhcp: OFFER %s -> %s" % (ip, req["mac"]))
        self.send(self.build_reply(req, OFFER, ip))

    def handle_request(self, req):
        mac = req["mac"]
        wanted = self.requested_addr(req)
        if not wanted:
            self.state.log("dhcp: REQUEST from %s with no address; ignoring" % mac)
            return

        held = self.lease_ip(mac)
        if held is None:
            # No record: either we restarted, or this is an INIT-REBOOT client
            # confirming an address from a previous session. Honour it when the
            # address is ours to give and nobody else holds it.
            if self.claim(mac, wanted):
                held = wanted
            else:
                self.state.log("dhcp: NAK %s for %s (unavailable)" % (wanted, mac))
                self.send(self.build_reply(req, NAK, None))
                return
        elif held != wanted:
            self.state.log("dhcp: NAK %s for %s (holds %s)" % (wanted, mac, held))
            self.send(self.build_reply(req, NAK, None))
            return

        self.state.log("dhcp: ACK %s -> %s" % (held, mac))
        self.send(self.build_reply(req, ACK, held))

    def handle_inform(self, req):
        """Client configured its own address and only wants network parameters.

        macOS and Windows both send INFORM in some flows (self-assigned or
        statically configured addresses, and some wake paths). The old server
        ignored anything that was not DISCOVER or REQUEST, so those clients got
        silence and no gateway/DNS -- which looks exactly like a broken network.

        Per RFC 2131 4.3.5: reply with an ACK carrying configuration options but
        NO lease timing and yiaddr = 0, unicast to the address in ciaddr. No
        lease is allocated, because we did not give out this address.
        """
        ci = req["ciaddr"]
        self.state.log("dhcp: INFORM from %s (ciaddr %s)" % (req["mac"], ci))
        pkt = self.build_reply(req, ACK, None, lease_opts=False)
        self.send(pkt, dest=ci if ci != "0.0.0.0" else "255.255.255.255")

    def handle_decline(self, req):
        """The client's ARP probe found the address already in use.

        RFC 2131 4.3.3: the server MUST mark the address unavailable. The
        address is in the requested_addr option -- ciaddr is zero in a DECLINE.
        Without this the client loops DISCOVER -> OFFER -> DECLINE forever on
        the same address, which is very likely what "connects, then stops
        working" looks like from the outside.

        It is logged loudly because it nearly always means a real conflict:
        something on the AP subnet with a static address, or a second DHCP
        server answering on this link.
        """
        mac = req["mac"]
        addr = None
        if OPT_REQUESTED in req["opts"] and len(req["opts"][OPT_REQUESTED]) == 4:
            addr = socket.inet_ntoa(req["opts"][OPT_REQUESTED])
        if addr is None:
            self.state.log("dhcp: DECLINE from %s carried no address; ignoring" % mac)
            return
        with self._lock:
            self.declined[addr] = time.time() + DECLINE_HOLD
            entry = self.leases.get(mac)
            if entry and entry[0] == addr:
                del self.leases[mac]
                self.save_leases()
            self.state.dhcp_leases = len(self.leases)
        self.state.log("dhcp: DECLINE %s from %s — address already in use; "
                       "withheld for %ds (check for a static IP or a second "
                       "DHCP server on %s)" % (addr, mac, DECLINE_HOLD, AP_IFACE))

    def process(self, data):
        if len(data) < 240 or data[236:240] != DHCP_MAGIC:
            return
        (op, htype, hlen, hops, xid, secs, flags,
         ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, bfile) = struct.unpack(
            "!BBBBIHH4s4s4s4s16s64s128s", data[:236])
        if op != 1:                        # only BOOTREQUEST
            return
        opts = parse_options(data[240:])
        if OPT_TYPE not in opts or not opts[OPT_TYPE]:
            return
        req = {
            "xid": xid, "flags": flags, "giaddr": giaddr,
            "chaddr": chaddr[:hlen] if hlen else chaddr[:6],
            "mac": mac_str(chaddr), "ciaddr": socket.inet_ntoa(ciaddr),
            "opts": opts,
        }
        mtype = opts[OPT_TYPE][0]
        if mtype == DISCOVER:
            self.handle_discover(req)
        elif mtype == REQUEST:
            self.handle_request(req)
        elif mtype == DECLINE:
            self.handle_decline(req)
        elif mtype == INFORM:
            self.handle_inform(req)
        elif mtype == RELEASE:
            self.state.log("dhcp: RELEASE from %s" % req["mac"])
            self.release(req["mac"])

    # ---- thread body --------------------------------------------------------
    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            # containment: only ever see/answer traffic on the AP interface
            self.sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE,
                                 self.iface.encode() + b"\x00")
            self.sock.bind(("", 67))
            self.sock.settimeout(1.0)
        except OSError as exc:
            self.state.log("dhcp: FAILED to bind on %s: %s" % (self.iface, exc))
            self.state.dhcp_alive = False
            return

        self.state.dhcp_alive = True
        self.state.dhcp_leases = len(self.leases)
        self.state.log("dhcp: listening on %s (%d lease(s) restored)"
                       % (self.iface, len(self.leases)))

        next_prune = time.time() + 60
        while not self.state.stop.is_set():
            if time.time() >= next_prune:
                next_prune = time.time() + 60
                with self._lock:
                    if self.prune_expired():
                        self.save_leases()
                    self.state.dhcp_leases = len(self.leases)
            try:
                data, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self.process(data)
            except Exception as exc:       # one bad packet must not kill the thread
                self.state.log("dhcp: error handling packet: %s" % exc)

        self.state.dhcp_alive = False
        try:
            self.sock.close()
        except OSError:
            pass


# =============================================================================
#  SUPERVISOR  --  the self-healing core
# =============================================================================
class Supervisor(threading.Thread):
    """Every CHECK_INTERVAL, verify the tunnel passes real traffic. If it does
    not, assume upstream Wi-Fi bounced, kill openvpn, wait for wlan0, redial,
    and put the default route back on tun0. Clients stay fail-closed throughout
    because the leak guard is never removed."""

    daemon = True

    def __init__(self, state, stage=FULL_STAGE):
        super().__init__(name="supervisor")
        self.state = state
        self.stage = stage
        self.reconnect_now = threading.Event()

    def run(self):
        attempts = 0
        led(True)
        while not self.state.stop.is_set():
            ssid = ssid_now()

            # ConnMan rebuilds its firewall chains when Wi-Fi is toggled --
            # which it does on its own during reconnects and roams, precisely
            # when this loop is busy recovering. Re-assert both rules rather
            # than assuming they survived. The guard was previously installed
            # once and thereafter only *observed* by the dashboard, so if it
            # vanished mid-session nothing put it back.
            if self.stage >= 3 and not leak_guard_on():
                self.state.log("supervisor: leak guard MISSING — reinstalling")
                if not install_leak_guard():
                    self.state.log("supervisor: leak guard REINSTALL FAILED")
            if self.stage >= 2:
                allow_dhcp_input()

            if not self.reconnect_now.is_set() and vpn_ok():
                attempts = 0
                self.state.update(vpn="healthy", wan="up", ssid=ssid,
                                  attempts=0, msg="tunnel healthy")
                led(True)
                self.state.stop.wait(CHECK_INTERVAL)
                continue

            if self.reconnect_now.is_set():
                self.reconnect_now.clear()
                self.state.log("manual reconnect requested")

            # ---- tunnel is NOT passing traffic -> recover --------------------
            led(False)
            self.state.update(vpn="down", ssid=ssid, msg="tunnel down — recovering")
            self.state.log("supervisor: tunnel not passing traffic; recovering")

            attempts += 1
            self.state.update(vpn="reconnecting", attempts=attempts,
                              msg="killing OpenVPN (attempt #%d)" % attempts)
            kill_tunnel()

            # wait until upstream Wi-Fi is genuinely back before redialing
            self.state.update(msg="waiting for Wi-Fi (%s)" % WAN_IFACE)
            while not self.state.stop.is_set():
                ensure_wlan0_route()
                if upstream_ok():
                    break
                self.state.update(wan="down", ssid=ssid_now(),
                                  msg="Wi-Fi down — waiting")
                led(False)
                self.state.stop.wait(2)
            if self.state.stop.is_set():
                break

            self.state.update(wan="up", ssid=ssid_now(),
                              msg="Wi-Fi back — redialing VPN")
            self.state.log("supervisor: upstream Wi-Fi reachable, redialing VPN")

            vpn_dial()
            self.state.update(msg="waiting for tunnel (%ds)" % DIAL_TIMEOUT)
            if wait_tun(DIAL_TIMEOUT):
                if self.stage >= 3:
                    route_via_tun()
                    install_nat()          # tun0 is new -- (re)assert its NAT rule
                attempts = 0
                led(True)
                self.state.update(vpn="healthy", attempts=0, msg="VPN reconnected")
                self.state.log("supervisor: VPN reconnected; route restored via tun0")
            else:
                led(False)
                self.state.update(vpn="down", msg="tunnel didn't come up — retrying")
                self.state.log("supervisor: tunnel failed to come up; will retry")
                self.state.stop.wait(2)


# =============================================================================
#  SETUP / TEARDOWN
# =============================================================================
STEP = [0]


def step(msg):
    STEP[0] += 1
    print("  %s▸%s %s[%02d]%s %s" % (C_CYN, C_RESET, C_DIM, STEP[0], C_RESET, msg))
    STATE.log("setup: " + msg)


AP_WPA_CONF = "/tmp/wpa_supplicant_ap.conf"
AP_CTRL_SOCK = "/var/run/wpa_supplicant/" + AP_IFACE


class SetupFailed(Exception):
    """Setup hit a condition that must not be continued past."""


def do_setup(stage=FULL_STAGE, quiet=False):
    """Bring the router up to `stage`. See STAGE_DESC.

    Steps marked SSH-KILLER drop the upstream link, so they only run at the
    full stage: killing wlan0's wpa_supplicant, and toggling ConnMan Wi-Fi.
    """
    if not quiet:
        print(CUR_HOME + CLR_SCREEN, end="")
        print("  %s%sBringing up the travel router — stage %d%s"
              % (C_BOLD, C_CYN, stage, C_RESET))
        print("  %s%s%s\n" % (C_DIM, STAGE_DESC.get(stage, ""), C_RESET))

    if stage >= 2:
        step("writing AP wpa_supplicant config to /tmp")
        with open(AP_WPA_CONF, "w") as fh:
            fh.write(
                "ctrl_interface=/var/run/wpa_supplicant\n"
                "ctrl_interface_group=0\n"
                "update_config=1\n\n"
                "network={\n"
                "    mode=2\n"
                '    ssid="%s"\n'
                "    frequency=%d\n"
                "    key_mgmt=WPA-PSK\n"
                '    psk="%s"\n'
                "}\n" % (AP_SSID, AP_FREQ, AP_PSK)
            )

    if stage >= 3:
        # FIRST, before ip_forward is enabled and before the AP is on air.
        # Previously this flushed FORWARD here and only re-added the guard nine
        # steps later, after the blocking ConnMan toggle -- leaving a window of
        # seconds where wlan1 was beaconing, ip_forward was 1, and FORWARD was
        # empty with policy ACCEPT. Clients hold the saved PSK and a persisted
        # lease, so they reassociate and transmit immediately; that window was
        # exactly when they were most likely to be sending.
        step("installing leak guard (FORWARD policy DROP; %s ↛ non-tun)" % AP_IFACE)
        if not install_leak_guard():
            print("      %sFATAL: leak guard could not be installed — refusing "
                  "to continue%s" % (C_RED, C_RESET))
            STATE.log("setup: FATAL, leak guard install failed")
            raise SetupFailed("leak guard install failed")

        step("clearing stale AP NAT rules from any previous run")
        clear_ap_nat()

        step("killing existing wpa_supplicant instances  [SSH-KILLER]")
        ok(["pkill", "wpa_supplicant"])
        time.sleep(1)

    if stage >= 2:
        step("creating virtual %s (AP) on top of %s" % (AP_IFACE, WAN_IFACE))
        ok(["iw", "dev", WAN_IFACE, "interface", "add", AP_IFACE,
            "type", "__ap", "addr", AP_MAC])
        ok(["ip", "addr", "add", "%s/%d" % (AP_ADDR, AP_CIDR), "dev", AP_IFACE])
        ok(["ip", "link", "set", AP_IFACE, "up"])

    if stage >= 3:
        step("enabling IPv4 forwarding")
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
                fh.write("1")
        except OSError:
            pass

    if stage >= 2:
        # wpa_supplicant refuses to start when a control socket for the
        # interface is left behind by an unclean exit ("ctrl_iface exists and
        # seems to be in use - cannot override it"), which happens every time
        # the AP interface is deleted out from under it. Clear ours first.
        # Match on our own config filename so we never touch the supplicant
        # serving wlan0 -- at stages 1-2 that is the upstream link.
        step("clearing any stale %s control socket" % AP_IFACE)
        ok(["pkill", "-f", AP_WPA_CONF])
        time.sleep(0.5)
        try:
            os.unlink(AP_CTRL_SOCK)
        except OSError:
            pass

        step("starting AP wpa_supplicant on %s (%s goes on air)" % (AP_IFACE, AP_SSID))
        ok(["/usr/sbin/wpa_supplicant", "-B", "-c", AP_WPA_CONF,
            "-O", "/var/run/wpa_supplicant", "-i", AP_IFACE])
        # Only verify the process survived here -- that is the stale-ctrl-socket
        # failure, and it shows up within a second. The beacon itself can take
        # far longer to appear on this driver, so it is checked at the end of
        # setup instead, by which point the VPN dial has covered the wait.
        time.sleep(1.5)
        if sh(["pgrep", "-f", AP_WPA_CONF], capture=False)[0] != 0:
            print("      %sWARNING: AP wpa_supplicant died on startup — %s will "
                  "NOT be on air%s" % (C_RED, AP_SSID, C_RESET))
            STATE.log("setup: AP wpa_supplicant FAILED to start")

    if stage >= 3:
        step("starting client wpa_supplicant on %s" % WAN_IFACE)
        ok(["/usr/sbin/wpa_supplicant", "-B", "-u",
            "-c", "/etc/wpa_supplicant/wpa_supplicant.conf",
            "-O", "/var/run/wpa_supplicant",
            "-P", "/var/run/wpa_supplicant.pid", "-i", WAN_IFACE])

        step("toggling ConnMan Wi-Fi to rebind %s  [SSH-KILLER]" % WAN_IFACE)
        for val in ("false", "true"):
            ok(["dbus-send", "--system", "--print-reply",
                "--dest=net.connman", "/net/connman/technology/wifi",
                "net.connman.Technology.SetProperty", "string:Powered",
                "variant:boolean:" + val])

    step("waiting for upstream Wi-Fi + capturing gateway")
    for _ in range(20):
        if iface_up(WAN_IFACE) and capture_gw():
            break
        time.sleep(1)

    step("dialing OpenVPN + probing tun0 (timeout %ds)" % INIT_DIAL_TIMEOUT)
    vpn_dial()
    if wait_tun(INIT_DIAL_TIMEOUT):
        if stage >= 3:
            route_via_tun()
            print("      %stunnel up — default route now via tun0%s" % (C_GRN, C_RESET))
            STATE.log("setup: tunnel up, default route via tun0")
        else:
            print("      %stunnel up and passing traffic (default route left alone "
                  "at stage %d)%s" % (C_GRN, stage, C_RESET))
            STATE.log("setup: tunnel up; routing untouched at stage %d" % stage)
    else:
        print("      %stunnel not up yet — supervisor will keep trying%s"
              % (C_YEL, C_RESET))
        STATE.log("setup: tunnel not up within timeout; handing off to supervisor")

    if stage >= 3:
        step("installing NAT MASQUERADE for AP subnet")
        install_nat(verbose=not quiet)

    if stage >= 2:
        step("stopping any competing DHCP daemon")
        ok(["pkill", "udhcpd"])

        step("allowing inbound DHCP on %s through the INPUT firewall" % AP_IFACE)
        if not allow_dhcp_input():
            print("      %sWARNING: could not install INPUT ACCEPT for udp/67 — "
                  "clients will not get leases%s" % (C_RED, C_RESET))
            STATE.log("setup: FAILED to allow inbound DHCP on %s" % AP_IFACE)

        step("verifying %s is on air" % AP_SSID)
        for _ in range(40):                       # up to 20s, usually already up
            if ap_on_air():
                break
            time.sleep(0.5)
        if ap_on_air():
            print("      %s%s broadcasting on %s%s" % (C_GRN, AP_SSID, AP_IFACE, C_RESET))
            STATE.log("setup: %s on air" % AP_SSID)
        else:
            print("      %sWARNING: no SSID on %s — clients cannot see the AP%s"
                  % (C_YEL, AP_IFACE, C_RESET))
            STATE.log("setup: no SSID on %s" % AP_IFACE)

    if not quiet:
        print("\n  %s%sStage %d up.%s Starting live dashboard…"
              % (C_GRN, C_BOLD, stage, C_RESET))
        time.sleep(1)


def do_teardown(stage=FULL_STAGE):
    """Undo whatever the given stage built, and nothing more.

    Teardown is stage-aware for the same reason setup is: at stages 1-2 we must
    not touch wlan0's supplicant or ConnMan, or we would drop the SSH session
    that is running the teardown.
    """
    print(CUR_SHOW + CUR_HOME + CLR_SCREEN, end="")
    print("  %s%sTearing down (stage %d)…%s\n" % (C_BOLD, C_CYN, stage, C_RESET))

    def item(msg):
        print("  %s▸%s %s" % (C_CYN, C_RESET, msg))

    if stage >= 3:
        # FIRST. Everything below removes rules or interfaces; with forwarding
        # still enabled, the gap between flushing FORWARD and deleting wlan1
        # is another open window. Killing forwarding up front closes it.
        item("disabling IPv4 forwarding (first, so nothing can transit)")
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:
                fh.write("0")
        except OSError:
            pass

    item("stopping worker threads")
    STATE.stop.set()

    item("killing openvpn")
    if not kill_openvpn():
        print("      %swarning: openvpn still running%s" % (C_YEL, C_RESET))

    item("cleaning up tun0 (routes + device)")
    ok(["ip", "route", "flush", "dev", "tun0"])
    ok(["ip", "link", "delete", "tun0"])

    if stage >= 3:
        item("removing AP NAT + releasing leak guard")
        clear_ap_nat()
        release_leak_guard()

    if stage >= 2:
        item("removing DHCP INPUT rule")
        deny_dhcp_input()

        item("stopping AP wpa_supplicant + removing virtual %s" % AP_IFACE)
        ok(["pkill", "-f", AP_WPA_CONF])
        time.sleep(0.5)
        ok(["ip", "link", "set", AP_IFACE, "down"])
        ok(["iw", "dev", AP_IFACE, "del"])
        # leave no stale socket to block the next run
        try:
            os.unlink(AP_CTRL_SOCK)
        except OSError:
            pass

    if stage >= 3:
        item("restarting %s as a normal client" % WAN_IFACE)
        ok(["pkill", "wpa_supplicant"])
        ok(["ip", "link", "set", WAN_IFACE, "down"])
        ok(["ip", "route", "flush", "dev", WAN_IFACE])
        ok(["ip", "link", "set", WAN_IFACE, "up"])
        ok(["/usr/sbin/wpa_supplicant", "-B", "-u",
            "-c", "/etc/wpa_supplicant/wpa_supplicant.conf",
            "-O", "/var/run/wpa_supplicant",
            "-P", "/var/run/wpa_supplicant.pid", "-i", WAN_IFACE])

        item("toggling ConnMan Wi-Fi")
        for val in ("false", "true"):
            ok(["dbus-send", "--system", "--print-reply",
                "--dest=net.connman", "/net/connman/technology/wifi",
                "net.connman.Technology.SetProperty", "string:Powered",
                "variant:boolean:" + val])
    else:
        item("leaving %s, iptables and ConnMan untouched (stage %d)"
             % (WAN_IFACE, stage))

    item("turning off VPN-health LED")
    led(False)

    for path in (STATUS_FILE, GW_FILE, PID_FILE, STAGE_FILE):
        try:
            os.unlink(path)
        except OSError:
            pass

    print("\n  %s%sTeardown complete.%s" % (C_GRN, C_BOLD, C_RESET))


# =============================================================================
#  DASHBOARD
# =============================================================================
def hr():
    return "  %s────────────────────────────────────────────────────────%s%s" % (
        C_DIM, C_RESET, CLR_EOL)


def row(kind, label, detail):
    dot = {"good": C_GRN + "●" + C_RESET,
           "bad": C_RED + "●" + C_RESET,
           "warn": C_YEL + "●" + C_RESET}.get(kind, C_DIM + "○" + C_RESET)
    return "    %s  %-16s %s%s%s%s" % (dot, label, C_DIM, detail, C_RESET, CLR_EOL)


def render(snap):
    out = [CUR_HOME]
    bar = "══════════════════════════════════════════════════════"
    out.append("  %s%s╔%s╗%s%s" % (C_BOLD, C_CYN, bar, C_RESET, CLR_EOL))
    out.append("  %s%s║%s  %sSAILFISH TRAVEL ROUTER%s  %s· VPN leak-guard AP%s       "
               "%s%s║%s%s" % (C_BOLD, C_CYN, C_RESET, C_BOLD, C_RESET, C_DIM,
                              C_RESET, C_BOLD, C_CYN, C_RESET, CLR_EOL))
    out.append("  %s%s╚%s╝%s%s" % (C_BOLD, C_CYN, bar, C_RESET, CLR_EOL))
    out.append(CLR_EOL)

    vpn = snap["vpn"]
    if vpn == "healthy":
        vpn_txt = "%s%sHEALTHY%s" % (C_GRN, C_BOLD, C_RESET)
    elif vpn == "reconnecting":
        vpn_txt = "%s%sRECONNECTING%s %s(attempt %d)%s" % (
            C_YEL, C_BOLD, C_RESET, C_DIM, snap["attempts"], C_RESET)
    elif vpn == "down":
        vpn_txt = "%s%sDOWN%s" % (C_RED, C_BOLD, C_RESET)
    else:
        vpn_txt = "%sstarting…%s" % (C_DIM, C_RESET)

    out.append("    %sVPN TUNNEL%s   %s   %s(checked %s)%s%s" % (
        C_BOLD, C_RESET, vpn_txt, C_DIM, snap["ts"], C_RESET, CLR_EOL))
    out.append("    %s%s%s%s" % (C_DIM, snap["msg"], C_RESET, CLR_EOL))
    out.append(CLR_EOL)
    out.append(hr())

    if iface_up(WAN_IFACE):
        out.append(row("good", "Upstream Wi-Fi", "%s up · SSID: %s"
                       % (WAN_IFACE, snap["ssid"] or "?")))
    else:
        out.append(row("bad", "Upstream Wi-Fi", "%s down" % WAN_IFACE))

    out.append(row("good", "Tunnel iface", "tun0 up") if tun_up()
               else row("bad", "Tunnel iface", "tun0 absent"))

    stage = snap.get("stage", FULL_STAGE)

    if stage < 2:
        out.append(row("na", "Access Point", "not built at stage %d" % stage))
    elif ap_on_air():
        out.append(row("good", "Access Point", "%s on %s · %s" % (AP_SSID, AP_IFACE, AP_ADDR)))
    elif iface_up(AP_IFACE):
        out.append(row("bad", "Access Point", "%s up but NOT broadcasting" % AP_IFACE))
    else:
        out.append(row("bad", "Access Point", "%s down" % AP_IFACE))

    if stage < 3:
        out.append(row("na", "Leak guard", "not installed at stage %d" % stage))
    elif leak_guard_on():
        out.append(row("good", "Leak guard", "active · non-tun forwards DROP"))
    else:
        out.append(row("bad", "Leak guard", "MISSING — clients could leak!"))

    # Report where packets actually go, not what the `default` route says --
    # see egress_dev() for why those differ on this device.
    dev = egress_dev()
    cdev = client_egress_dev() if stage >= 3 else ""
    if stage < 3:
        out.append(row("na", "Egress path", "not routed at stage %d (phone via %s)"
                       % (stage, dev or "none")))
    elif dev.startswith("tun") and cdev.startswith("tun"):
        out.append(row("good", "Egress path", "phone + clients via %s" % dev))
    elif dev.startswith("tun"):
        out.append(row("warn", "Egress path",
                       "phone via %s, clients via %s" % (dev, cdev or "none")))
    elif not dev:
        out.append(row("bad", "Egress path", "no route"))
    else:
        out.append(row("bad", "Egress path", "via %s — NOT tunnelled" % dev))

    if stage < 2:
        out.append(row("na", "DHCP server", "not started at stage %d" % stage))
    elif not snap["dhcp_alive"]:
        out.append(row("bad", "DHCP server", "not running"))
    elif not dhcp_input_allowed():
        out.append(row("bad", "DHCP server", "bound, but INPUT firewall blocks udp/67"))
    else:
        out.append(row("good", "DHCP server", "leasing on %s · %d lease(s)"
                       % (AP_IFACE, snap["dhcp_leases"])))
    out.append(hr())

    out.append(CLR_EOL)
    out.append("  %sRecent events%s%s" % (C_BOLD, C_RESET, CLR_EOL))
    for line in list(snap["events"])[-6:]:
        out.append("    %s%s%s%s" % (C_DIM, line, C_RESET, CLR_EOL))

    out.append(CLR_EOL)
    out.append(CLR_EOL)
    out.append("  %s[r]%s reconnect now    %s[q]%s tear down & quit    %sstage %d%s%s" % (
        C_BOLD, C_RESET, C_BOLD, C_RESET, C_DIM, stage, C_RESET, CLR_EOL))
    out.append(CLR_DOWN)
    sys.stdout.write("\r\n".join(out))
    sys.stdout.flush()


class RawTerminal:
    """Single-keypress input without curses. Restores the tty on the way out."""

    def __enter__(self):
        self.fd = sys.stdin.fileno()
        self.saved = termios.tcgetattr(self.fd)
        tty.setraw(self.fd)
        sys.stdout.write(CUR_HIDE + CUR_HOME + CLR_SCREEN)
        sys.stdout.flush()
        return self

    def __exit__(self, *exc):
        termios.tcsetattr(self.fd, termios.TCSADRAIN, self.saved)
        sys.stdout.write(CUR_SHOW)
        sys.stdout.flush()

    def key(self, timeout):
        try:
            r, _, _ = select.select([sys.stdin], [], [], timeout)
        except (OSError, ValueError):
            raise TerminalGone()
        if not r:
            return None
        ch = sys.stdin.read(1)
        if ch == "":
            raise TerminalGone()
        return ch


class TerminalGone(Exception):
    """stdin died -- the SSH session dropped or the terminal closed."""


def confirm_teardown(term):
    sys.stdout.write(CUR_SHOW + "\r\n  %sTear down the router and restore normal "
                                "Wi-Fi? [y/N] %s" % (C_YEL, C_RESET))
    sys.stdout.flush()
    ch = term.key(15)
    sys.stdout.write(CUR_HIDE)
    return ch is not None and ch.lower() == "y"


def tui_loop(supervisor):
    with RawTerminal() as term:
        while not STATE.stop.is_set():
            render(STATE.snapshot())
            ch = term.key(UI_REFRESH)
            if ch is None:
                continue
            if ch in ("r", "R"):
                supervisor.reconnect_now.set()
                kill_tunnel()
            elif ch in ("q", "Q", "2"):
                if confirm_teardown(term):
                    return True
            elif ch == "\x03":              # Ctrl-C in raw mode
                return False
    return False


# =============================================================================
#  process bookkeeping
# =============================================================================
def read_pid():
    try:
        with open(PID_FILE) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def running_pid():
    pid = read_pid()
    if pid is None:
        return None
    try:
        os.kill(pid, 0)
    except OSError:
        return None
    return pid


def write_pid(stage=FULL_STAGE):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(PID_FILE, "w") as fh:
        fh.write(str(os.getpid()))
    with open(STAGE_FILE, "w") as fh:
        fh.write(str(stage))


def read_stage(default=FULL_STAGE):
    """Which stage the live router was built to, so --down can undo exactly that."""
    try:
        with open(STAGE_FILE) as fh:
            return max(1, min(FULL_STAGE, int(fh.read().strip())))
    except (OSError, ValueError):
        return default


def cmd_status():
    pid = running_pid()
    if not pid:
        print("router not running")
        return 1
    print("router running (pid %d, stage %d)" % (pid, read_stage()))
    try:
        with open(STATUS_FILE) as fh:
            sys.stdout.write(fh.read())
    except OSError:
        print("(no status published yet)")
    st = read_stage()
    print("access point: %s" % ("on air (%s)" % AP_SSID if ap_on_air()
                                else "NOT broadcasting"))
    print("egress path: phone -> %s, client -> %s"
          % (egress_dev() or "none", client_egress_dev() or "none"))
    if st >= 2:
        print("dhcp INPUT rule: %s" % ("present" if dhcp_input_allowed() else "MISSING"))
        try:
            with open(LEASE_FILE) as fh:
                print("dhcp leases: %d on file" % len(json.load(fh)))
        except (OSError, ValueError):
            pass
    print("leak guard: %s" % ("active" if leak_guard_on() else "MISSING"))
    return 0


def cmd_down(stage=None):
    if stage is None:
        stage = read_stage()
    pid = running_pid()
    if pid:
        print("stopping router (pid %d)…" % pid)
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
        for _ in range(20):
            if not running_pid():
                break
            time.sleep(0.5)
    do_teardown(stage)
    return 0


# =============================================================================
#  main
# =============================================================================
def parse_stage(argv):
    """--stage N or --stage=N; defaults to the full router."""
    items = argv[1:]
    for i, a in enumerate(items):
        raw = None
        if a.startswith("--stage="):
            raw = a.split("=", 1)[1]
        elif a == "--stage" and i + 1 < len(items):
            raw = items[i + 1]
        if raw is not None:
            try:
                n = int(raw)
            except ValueError:
                print("bad --stage %r (expected 1-%d)" % (raw, FULL_STAGE), file=sys.stderr)
                sys.exit(2)
            if n not in STAGE_DESC:
                print("bad --stage %d (expected 1-%d)" % (n, FULL_STAGE), file=sys.stderr)
                sys.exit(2)
            return n
    return FULL_STAGE


def main(argv):
    args = set(argv[1:])

    # When stdout is a pipe rather than a terminal it is block-buffered, so
    # progress output would sit invisible in an 8K buffer while setup blocks
    # for up to INIT_DIAL_TIMEOUT on the first dial. Line buffering makes the
    # steps appear as they happen under `ssh host ./router.py`, tee, or
    # redirection.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    if "--help" in args or "-h" in args:
        print("SailfishOS Travel Router — single file, stdlib only\n")
        print("  ./router.py             bring up + dashboard")
        print("  ./router.py --headless  bring up, no dashboard")
        print("  ./router.py --status    snapshot of a running router")
        print("  ./router.py --down      tear down and restore Wi-Fi")
        print("  ./router.py --stage N   bring up only as far as stage N\n")
        print("Stages (each includes the ones below it):")
        for n in sorted(STAGE_DESC):
            print("  %d  %s" % (n, STAGE_DESC[n]))
        print("\nOver SSH, start at stage 1 and promote once it looks right.")
        print("Use `ssh -t <phone> ...` or you get headless mode with no dashboard.")
        return 0

    if os.geteuid() != 0:
        print("This script must run as root (try: devel-su %s)" % argv[0], file=sys.stderr)
        return 1

    os.makedirs(STATE_DIR, exist_ok=True)

    if "--status" in args:
        return cmd_status()
    if "--down" in args:
        # If --stage was given explicitly, undo that; otherwise undo whatever
        # the running instance recorded when it started.
        return cmd_down(parse_stage(argv) if "--stage" in args
                        or any(a.startswith("--stage=") for a in args) else None)

    # A live router must never have setup re-run against it: do_setup flushes
    # the FORWARD chain, which would drop the leak guard for the seconds until
    # it is reinstalled -- while ip_forward is still 1 and the previous run's
    # MASQUERADE rules are still live. That is exactly the leak window the
    # design promises cannot exist.
    pid = running_pid()
    if pid:
        print("Router already running (pid %d)." % pid)
        print("  ./router.py --status   to inspect it")
        print("  ./router.py --down     to tear it down")
        return 1

    stage = parse_stage(argv)
    STATE.stage = stage

    missing = require_tools()
    if missing:
        print("Missing required tools on PATH: %s" % ", ".join(missing), file=sys.stderr)
        print("PATH=%s" % os.environ.get("PATH", ""), file=sys.stderr)
        return 1

    no_tty = not sys.stdin.isatty()
    headless = "--headless" in args or no_tty
    if no_tty and "--headless" not in args:
        print("No TTY on stdin — starting headless (no dashboard).")
        print("For the live dashboard over SSH, use:  ssh -t <phone> '%s'" % argv[0])

    # An SSH drop must not take the router down with it.
    signal.signal(signal.SIGHUP, signal.SIG_IGN)

    write_pid(stage)
    try:
        open(EVENTS_FILE, "w").close()
    except OSError:
        pass
    STATE.log("session started")

    stopping = {"teardown": False, "signalled": False}

    def on_term(signum, frame):
        # `--down` from another shell signals us, then runs teardown itself.
        stopping["signalled"] = True
        STATE.stop.set()

    signal.signal(signal.SIGTERM, on_term)

    if headless:
        print("Stage %d: %s" % (stage, STAGE_DESC[stage]))
        print("First VPN dial may take up to %ds." % INIT_DIAL_TIMEOUT)
    try:
        do_setup(stage, quiet=headless)
    except SetupFailed as exc:
        # Never leave a half-built router running: the AP may already be on air
        # with forwarding enabled. Undo whatever got built and exit non-zero.
        print("Setup aborted: %s" % exc, file=sys.stderr)
        STATE.log("setup aborted: %s" % exc)
        do_teardown(stage)
        try:
            os.unlink(PID_FILE)
        except OSError:
            pass
        return 1

    dhcp = None
    if stage >= 2:
        dhcp = DHCPServer(STATE)
        dhcp.start()
    else:
        STATE.log("stage %d: DHCP server not started" % stage)
    supervisor = Supervisor(STATE, stage)
    supervisor.start()

    if headless:
        STATE.log("running headless; use --down to tear down")
        print("Router up at stage %d. `%s --down` to stop." % (stage, argv[0]))
        try:
            while not STATE.stop.is_set():
                STATE.stop.wait(1)
        except KeyboardInterrupt:
            pass
    else:
        try:
            stopping["teardown"] = tui_loop(supervisor)
        except TerminalGone:
            # Terminal vanished (SSH dropped). Keep routing; the AP and tunnel
            # stay up and the supervisor keeps healing until --down.
            STATE.log("terminal lost — continuing headless")
            try:
                while not STATE.stop.is_set():
                    STATE.stop.wait(1)
            except KeyboardInterrupt:
                pass
        except KeyboardInterrupt:
            stopping["teardown"] = False

    if stopping["teardown"]:
        do_teardown(stage)
        STATE.log("session ended")
    elif stopping["signalled"]:
        STATE.stop.set()
        STATE.log("session ended (stopped externally)")
    else:
        STATE.stop.set()
        print("\nUI closed — router still running. `%s --down` to tear down." % argv[0])

    try:
        os.unlink(PID_FILE)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

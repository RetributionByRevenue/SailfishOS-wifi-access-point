#!/bin/bash
# =============================================================================
#  SailfishOS Travel Router  ·  slick TUI + self-healing VPN supervisor
# -----------------------------------------------------------------------------
#  Turns the phone into a Wi-Fi AP (test_ap on wlan1) whose clients are routed
#  exclusively through an OpenVPN tunnel (tun0). A stateless, always-on iptables
#  leak guard drops any AP traffic not egressing via tun+, so clients are
#  fail-closed during setup, outages and reconnects.
#
#  NEW in this version:
#    * Full-screen live dashboard (no external deps -- pure bash + ANSI).
#    * A background SUPERVISOR that continuously verifies the tunnel actually
#      passes traffic. When upstream Wi-Fi drops (or the tunnel dies for any
#      reason) it kills openvpn, waits for wlan0 to recover, redials the VPN,
#      and re-points the default route back through tun0 -- untouched by the
#      user. The leak guard means clients never leak while this happens.
#
#  Keys:  [r] force reconnect now   [q] tear down & quit   (2 also quits)
#
#  Run as root (e.g. `devel-su ./main.sh`).
# =============================================================================

# ----------------------------- configuration ---------------------------------
AP_SSID="test_ap"                                   # broadcast network name
AP_PSK="12345678"                                   # AP pre-shared key (WPA2)
AP_IFACE="wlan1"                                    # virtual AP interface
AP_ADDR="10.10.0.1/24"                              # AP gateway address
AP_MAC="12:34:56:78:ab:ce"                          # AP L2 identity
AP_FREQ="2412"                                      # 2412 MHz == channel 1
NAT_SRC="10.10.0.0/16"                              # source range to masquerade
WAN_IFACE="wlan0"                                   # upstream station interface

OVPN_CONFIG="/home/defaultuser/Desktop/mark-home.ovpn"
DHCP_PY="/home/defaultuser/python/wlan1_dhcp_server.py"
VENV_PY="/home/defaultuser/python/venv/bin/python"
LED_PATH="/sys/class/leds/blue/brightness"

PROBE_HOST="8.8.8.8"                                # reachability target
CHECK_INTERVAL=4                                    # supervisor poll cadence (s)
DIAL_TIMEOUT=90                                     # reconnect: wait for tun0 (s)
INIT_DIAL_TIMEOUT=600                               # first boot: wait for tun0 (s)
UI_REFRESH=1                                        # dashboard refresh / key poll (s)

# ------------------------------ runtime state --------------------------------
STATE_DIR="/tmp/travelrouter"
STATUS_FILE="$STATE_DIR/status"                     # key=val, written by supervisor
EVENTS_FILE="$STATE_DIR/events"                     # rolling event log
GW_FILE="$STATE_DIR/wlan0_gw"                       # captured upstream gateway
SUPERVISOR_PID_FILE="$STATE_DIR/supervisor.pid"
STEP=0                                              # setup step counter

# --------------------------------- colours -----------------------------------
ESC=$'\033'
C_RESET="${ESC}[0m";  C_BOLD="${ESC}[1m";  C_DIM="${ESC}[2m"
C_RED="${ESC}[31m";   C_GRN="${ESC}[32m";  C_YEL="${ESC}[33m"
C_BLU="${ESC}[34m";   C_MAG="${ESC}[35m";  C_CYN="${ESC}[36m"
CLR_EOL="${ESC}[K";   CUR_HOME="${ESC}[H"; CLR_DOWN="${ESC}[J"
CUR_HIDE="${ESC}[?25l"; CUR_SHOW="${ESC}[?25h"

# =============================================================================
#  small helpers
# =============================================================================
now()  { date +%H:%M:%S; }

log() {                                             # append one timestamped line
    printf '%s %s\n' "$(now)" "$*" >> "$EVENTS_FILE"
    # keep the log bounded so an all-night supervisor can't fill /tmp
    if [ "$(wc -l < "$EVENTS_FILE" 2>/dev/null || echo 0)" -gt 400 ]; then
        tail -n 200 "$EVENTS_FILE" > "$EVENTS_FILE.tmp" && mv "$EVENTS_FILE.tmp" "$EVENTS_FILE"
    fi
}

led_on()  { echo 255 > "$LED_PATH" 2>/dev/null; }
led_off() { echo 0   > "$LED_PATH" 2>/dev/null; }

step() {                                            # pretty setup step line
    STEP=$((STEP+1))
    printf "  ${C_CYN}▸${C_RESET} ${C_DIM}[%02d]${C_RESET} %s\n" "$STEP" "$1"
    log "setup: $1"
}

# ---- connectivity predicates (all quiet, return 0/1) ------------------------
wlan0_up()     { ip -o link show "$WAN_IFACE" 2>/dev/null | grep -q "state UP"; }
tun_up()       { ip link show tun0 up >/dev/null 2>&1; }
ap_up()        { ip -o link show "$AP_IFACE" 2>/dev/null | grep -q "state UP"; }
dhcp_up()      { pgrep -f "$(basename "$DHCP_PY")" >/dev/null 2>&1; }
leak_guard_on(){ iptables -C FORWARD -i "$AP_IFACE" ! -o tun+ -j DROP 2>/dev/null; }

# Tunnel is healthy only if tun0 is up AND actually passes traffic through itself.
vpn_ok()       { tun_up && ping -I tun0 -c1 -W2 "$PROBE_HOST" >/dev/null 2>&1; }

# Upstream Wi-Fi is usable if wlan0 is UP and reachable out that very interface.
upstream_ok()  { wlan0_up && ping -c1 -W2 -I "$WAN_IFACE" "$PROBE_HOST" >/dev/null 2>&1; }

default_route_dev() { ip route show default 2>/dev/null | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1; }
ssid_now()          { iw dev "$WAN_IFACE" link 2>/dev/null | sed -n 's/^[[:space:]]*SSID: //p' | head -1; }

# ---- route management -------------------------------------------------------
capture_gw() {                                      # remember wlan0's gateway
    local gw
    gw=$(ip route show default 2>/dev/null | awk -v d="$WAN_IFACE" '$0 ~ ("dev " d){for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')
    [ -n "$gw" ] && echo "$gw" > "$GW_FILE"
}

ensure_wlan0_route() {                              # need a path to reach the VPN server
    ip route show default 2>/dev/null | grep -q "dev $WAN_IFACE" && return 0
    local gw; gw=$(cat "$GW_FILE" 2>/dev/null)
    [ -n "$gw" ] && ip route add default via "$gw" dev "$WAN_IFACE" 2>/dev/null
}

route_via_tun() {                                   # all phone traffic -> tun0
    while ip route show default 2>/dev/null | grep -q .; do
        ip route del default 2>/dev/null || break
    done
    ip route add default dev tun0 2>/dev/null
}

vpn_dial() {                                        # (re)launch openvpn detached
    log "dialing OpenVPN ($OVPN_CONFIG)"
    nohup openvpn --dev tun --config "$OVPN_CONFIG" >/dev/null 2>&1 &
}

wait_tun() {                                        # $1 = timeout seconds
    local t="${1:-$DIAL_TIMEOUT}" i
    for i in $(seq 1 "$t"); do
        vpn_ok && return 0
        sleep 1
    done
    return 1
}

kill_tunnel() {                                     # tear down openvpn + tun0
    pkill openvpn 2>/dev/null
    ip route flush dev tun0 2>/dev/null
    ip link delete tun0 2>/dev/null
}

# =============================================================================
#  SUPERVISOR  --  the self-healing core
# =============================================================================
# Runs detached in the background. Every CHECK_INTERVAL it verifies the tunnel
# passes real traffic. If not, it assumes upstream Wi-Fi bounced (or the tunnel
# otherwise died), kills openvpn, waits for wlan0 to recover, redials, and puts
# the default route back on tun0. State is published to $STATUS_FILE for the UI.
# Publish supervisor state for the UI. Reads the $vpn/$wan/... locals of its
# caller via shell dynamic scoping (works under both bash and busybox ash).
# Values are single-line, so a plain KEY=VALUE file stays trivially parseable.
write_status() {
    {
        echo "VPN=$vpn"
        echo "WAN=$wan"
        echo "SSID=$ssid"
        echo "ATTEMPTS=$attempts"
        echo "LASTMSG=$msg"
        echo "TS=$(now)"
    } > "$STATUS_FILE.tmp" && mv "$STATUS_FILE.tmp" "$STATUS_FILE"
}

supervisor_loop() {
    trap '' HUP INT                                  # survive terminal hangup / Ctrl-C
    local vpn=healthy wan=up ssid="" attempts=0 msg="monitoring"

    led_on
    while :; do
        ssid="$(ssid_now)"

        if vpn_ok; then
            vpn=healthy; wan=up; attempts=0; msg="tunnel healthy"
            led_on; write_status
            sleep "$CHECK_INTERVAL"
            continue
        fi

        # ---- tunnel is NOT passing traffic -> begin recovery -----------------
        led_off
        vpn=down; msg="tunnel down — recovering"
        log "supervisor: tunnel not passing traffic; starting recovery"
        write_status

        attempts=$((attempts+1))
        vpn=reconnecting; msg="killing OpenVPN (attempt #$attempts)"
        write_status
        kill_tunnel

        # wait until upstream Wi-Fi is genuinely back before we bother redialing
        msg="waiting for Wi-Fi ($WAN_IFACE)"
        write_status
        until ensure_wlan0_route; upstream_ok; do
            wan=down; ssid="$(ssid_now)"; msg="Wi-Fi down — waiting"
            led_off; write_status
            sleep 2
        done
        wan=up; ssid="$(ssid_now)"
        log "supervisor: upstream Wi-Fi reachable, redialing VPN"
        msg="Wi-Fi back — redialing VPN"
        write_status

        vpn_dial
        msg="waiting for tunnel (${DIAL_TIMEOUT}s)"
        write_status
        if wait_tun "$DIAL_TIMEOUT"; then
            route_via_tun
            vpn=healthy; attempts=0; msg="VPN reconnected"
            led_on
            log "supervisor: VPN reconnected; default route restored via tun0"
            write_status
        else
            vpn=down; msg="tunnel didn't come up — retrying"
            led_off
            log "supervisor: tunnel failed to come up; will retry"
            write_status
            sleep 2
        fi
    done
}

start_supervisor() {
    ( supervisor_loop ) &                              # subshell so traps are isolated
    local pid=$!
    echo "$pid" > "$SUPERVISOR_PID_FILE"
    log "supervisor started (pid $pid)"
}

stop_supervisor() {
    local pid; pid=$(cat "$SUPERVISOR_PID_FILE" 2>/dev/null)
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
    rm -f "$SUPERVISOR_PID_FILE"
}

manual_reconnect() {                                 # user pressed [r]
    log "manual reconnect requested"
    kill_tunnel                                      # supervisor notices next cycle
}

# =============================================================================
#  SETUP  --  build the AP + leak guard + first VPN dial
# =============================================================================
do_setup() {
    printf "%b" "${CUR_HOME}${ESC}[2J"
    printf "  ${C_BOLD}${C_CYN}Bringing up the travel router…${C_RESET}\n\n"

    step "writing AP wpa_supplicant config to /tmp"
    rm -f /tmp/wpa_supplicant_ap.conf
    cat > /tmp/wpa_supplicant_ap.conf <<EOF
ctrl_interface=/var/run/wpa_supplicant
ctrl_interface_group=0
update_config=1

network={
    mode=2
    ssid="$AP_SSID"
    frequency=$AP_FREQ
    key_mgmt=WPA-PSK
    psk="$AP_PSK"
}
EOF

    step "sanitising FORWARD chain (clean baseline)"
    iptables -F FORWARD
    iptables -P FORWARD ACCEPT

    step "killing existing wpa_supplicant instances"
    pkill wpa_supplicant
    sleep 1

    step "creating virtual $AP_IFACE (AP) on top of $WAN_IFACE"
    iw dev "$WAN_IFACE" interface add "$AP_IFACE" type __ap addr "$AP_MAC"
    ip addr add "$AP_ADDR" dev "$AP_IFACE"
    ip link set "$AP_IFACE" up

    step "enabling IPv4 forwarding"
    echo 1 > /proc/sys/net/ipv4/ip_forward

    step "starting AP wpa_supplicant on $AP_IFACE ($AP_SSID goes on air)"
    /usr/sbin/wpa_supplicant -B -c /tmp/wpa_supplicant_ap.conf -O /var/run/wpa_supplicant -i "$AP_IFACE"

    step "starting client wpa_supplicant on $WAN_IFACE"
    /usr/sbin/wpa_supplicant -B -u -c /etc/wpa_supplicant/wpa_supplicant.conf -O /var/run/wpa_supplicant -P /var/run/wpa_supplicant.pid -i "$WAN_IFACE"

    step "toggling ConnMan Wi-Fi to rebind $WAN_IFACE"
    dbus-send --system --print-reply --dest=net.connman /net/connman/technology/wifi net.connman.Technology.SetProperty string:"Powered" variant:boolean:false >/dev/null 2>&1
    dbus-send --system --print-reply --dest=net.connman /net/connman/technology/wifi net.connman.Technology.SetProperty string:"Powered" variant:boolean:true  >/dev/null 2>&1

    step "installing permanent leak guard ($AP_IFACE ↛ non-tun DROP)"
    iptables -D FORWARD -i "$AP_IFACE" ! -o tun+ -j DROP 2>/dev/null
    iptables -A FORWARD -i "$AP_IFACE" ! -o tun+ -j DROP

    step "waiting for upstream Wi-Fi + capturing gateway"
    for i in $(seq 1 20); do
        if wlan0_up; then capture_gw; fi
        [ -s "$GW_FILE" ] && break
        sleep 1
    done

    step "dialing OpenVPN + probing tun0 (timeout ${INIT_DIAL_TIMEOUT}s)"
    vpn_dial
    if wait_tun "$INIT_DIAL_TIMEOUT"; then
        route_via_tun
        printf "      ${C_GRN}tunnel up — default route now via tun0${C_RESET}\n"
        log "setup: tunnel up, default route via tun0"
    else
        printf "      ${C_YEL}tunnel not up yet — supervisor will keep trying (clients stay blocked)${C_RESET}\n"
        log "setup: tunnel not up within timeout; handing off to supervisor"
    fi

    step "installing NAT MASQUERADE for AP subnet"
    for iface in $(ifconfig 2>/dev/null | grep "Link encap" | awk '{print $1}' | grep -vE "^(lo|rmnet_ipa0|rndis0|${AP_IFACE})$"); do
        iptables -t nat -C POSTROUTING -s "$NAT_SRC" -o "$iface" -j MASQUERADE 2>/dev/null \
            || iptables -t nat -A POSTROUTING -s "$NAT_SRC" -o "$iface" -j MASQUERADE
        printf "      ${C_DIM}masquerade via %s${C_RESET}\n" "$iface"
    done

    step "starting DHCP server for AP clients"
    pkill udhcpd 2>/dev/null
    pkill -f "$(basename "$DHCP_PY")" 2>/dev/null
    nohup "$VENV_PY" "$DHCP_PY" >/dev/null 2>&1 &
    log "setup: dhcp server started (pid $!)"

    printf "\n  ${C_GRN}${C_BOLD}Setup complete.${C_RESET} Starting live dashboard…\n"
    sleep 1
}

# =============================================================================
#  TEARDOWN  --  undo everything
# =============================================================================
do_teardown() {
    printf "%b" "${CUR_SHOW}${CUR_HOME}${ESC}[2J"
    printf "  ${C_BOLD}${C_CYN}Tearing everything down…${C_RESET}\n\n"

    printf "  ${C_CYN}▸${C_RESET} stopping supervisor\n";              stop_supervisor
    printf "  ${C_CYN}▸${C_RESET} killing background processes\n"
    pkill -f "$(basename "$DHCP_PY")" 2>/dev/null
    pkill wpa_supplicant 2>/dev/null
    pkill openvpn 2>/dev/null

    printf "  ${C_CYN}▸${C_RESET} flushing iptables (NAT + FORWARD)\n"
    iptables -t nat -F POSTROUTING
    iptables -F FORWARD
    iptables -P FORWARD ACCEPT

    printf "  ${C_CYN}▸${C_RESET} cleaning up tun0 (routes + device)\n"
    ip route flush dev tun0 2>/dev/null
    ip link delete tun0 2>/dev/null

    printf "  ${C_CYN}▸${C_RESET} bringing down %s + %s\n" "$AP_IFACE" "$WAN_IFACE"
    ip link set "$AP_IFACE" down 2>/dev/null
    ip link set "$WAN_IFACE" down 2>/dev/null
    iw dev "$AP_IFACE" del 2>/dev/null

    printf "  ${C_CYN}▸${C_RESET} flushing %s routes\n" "$WAN_IFACE"
    ip route flush dev "$WAN_IFACE" 2>/dev/null

    printf "  ${C_CYN}▸${C_RESET} disabling IPv4 forwarding\n"
    echo 0 > /proc/sys/net/ipv4/ip_forward

    printf "  ${C_CYN}▸${C_RESET} bringing %s back up as client\n" "$WAN_IFACE"
    ip link set "$WAN_IFACE" up
    /usr/sbin/wpa_supplicant -B -u -c /etc/wpa_supplicant/wpa_supplicant.conf -O /var/run/wpa_supplicant -P /var/run/wpa_supplicant.pid -i "$WAN_IFACE"

    printf "  ${C_CYN}▸${C_RESET} toggling ConnMan Wi-Fi\n"
    dbus-send --system --print-reply --dest=net.connman /net/connman/technology/wifi net.connman.Technology.SetProperty string:"Powered" variant:boolean:false >/dev/null 2>&1
    dbus-send --system --print-reply --dest=net.connman /net/connman/technology/wifi net.connman.Technology.SetProperty string:"Powered" variant:boolean:true  >/dev/null 2>&1

    printf "  ${C_CYN}▸${C_RESET} turning off VPN-health LED\n"
    led_off

    rm -f "$STATUS_FILE" "$GW_FILE"
    printf "\n  ${C_GRN}${C_BOLD}Networking reset complete.${C_RESET}\n"
}

# =============================================================================
#  DASHBOARD  --  full-screen live UI
# =============================================================================
hr() { printf "  ${C_DIM}────────────────────────────────────────────────────────${C_RESET}%b\n" "$CLR_EOL"; }

# row  <good|bad|warn>  <label>  <detail>
row() {
    local dot
    case "$1" in
        good) dot="${C_GRN}●${C_RESET}" ;;
        bad)  dot="${C_RED}●${C_RESET}" ;;
        warn) dot="${C_YEL}●${C_RESET}" ;;
        *)    dot="${C_DIM}○${C_RESET}" ;;
    esac
    printf "    %b  %-16s ${C_DIM}%s${C_RESET}%b\n" "$dot" "$2" "$3" "$CLR_EOL"
}

sget() { sed -n "s/^$1=//p" "$STATUS_FILE" 2>/dev/null | head -1; }

render() {
    # published supervisor state (defaults until first cycle lands)
    local VPN WAN SSID ATTEMPTS LASTMSG TS droute
    VPN=$(sget VPN);           [ -z "$VPN" ]      && VPN=unknown
    WAN=$(sget WAN)
    SSID=$(sget SSID)
    ATTEMPTS=$(sget ATTEMPTS); [ -z "$ATTEMPTS" ] && ATTEMPTS=0
    LASTMSG=$(sget LASTMSG);   [ -z "$LASTMSG" ]  && LASTMSG="starting…"
    TS=$(sget TS);             [ -z "$TS" ]       && TS="--:--:--"

    droute="$(default_route_dev)"

    printf "%b" "$CUR_HOME"
    printf "  ${C_BOLD}${C_CYN}╔══════════════════════════════════════════════════════╗${C_RESET}%b\n" "$CLR_EOL"
    printf "  ${C_BOLD}${C_CYN}║${C_RESET}  ${C_BOLD}SAILFISH TRAVEL ROUTER${C_RESET}  ${C_DIM}· VPN leak-guard AP${C_RESET}       ${C_BOLD}${C_CYN}║${C_RESET}%b\n" "$CLR_EOL"
    printf "  ${C_BOLD}${C_CYN}╚══════════════════════════════════════════════════════╝${C_RESET}%b\n" "$CLR_EOL"
    printf "%b\n" "$CLR_EOL"

    # ---- big VPN banner ----
    local vpn_dot vpn_txt
    case "$VPN" in
        healthy)      vpn_dot=good; vpn_txt="${C_GRN}${C_BOLD}HEALTHY${C_RESET}" ;;
        reconnecting) vpn_dot=warn; vpn_txt="${C_YEL}${C_BOLD}RECONNECTING${C_RESET} ${C_DIM}(attempt ${ATTEMPTS})${C_RESET}" ;;
        down)         vpn_dot=bad;  vpn_txt="${C_RED}${C_BOLD}DOWN${C_RESET}" ;;
        *)            vpn_dot=warn; vpn_txt="${C_DIM}starting…${C_RESET}" ;;
    esac
    printf "    ${C_BOLD}VPN TUNNEL${C_RESET}   %b   ${C_DIM}(checked %s)${C_RESET}%b\n" "$vpn_txt" "$TS" "$CLR_EOL"
    printf "    ${C_DIM}%s${C_RESET}%b\n\n" "$LASTMSG" "$CLR_EOL"

    hr
    # ---- subsystem rows ----
    if wlan0_up; then row good "Upstream Wi-Fi" "$WAN_IFACE up · SSID: ${SSID:-?}"
    else                 row bad  "Upstream Wi-Fi" "$WAN_IFACE down"; fi

    if tun_up; then      row good "Tunnel iface"   "tun0 up"
    else                 row bad  "Tunnel iface"   "tun0 absent"; fi

    if ap_up; then       row good "Access Point"   "$AP_SSID on $AP_IFACE · ${AP_ADDR%/*}"
    else                 row bad  "Access Point"   "$AP_IFACE down"; fi

    if leak_guard_on; then row good "Leak guard"  "active · non-tun forwards DROP"
    else                   row bad  "Leak guard"  "MISSING — clients could leak!"; fi

    case "$droute" in
        tun0)  row good "Default route"  "via tun0 (clients reach net)" ;;
        "")    row bad  "Default route"  "none" ;;
        *)     row warn "Default route"  "via $droute (not tunnelled)" ;;
    esac

    if dhcp_up; then     row good "DHCP server"    "leasing on $AP_IFACE"
    else                 row bad  "DHCP server"    "not running"; fi
    hr

    # ---- recent events ----
    printf "\n  ${C_BOLD}Recent events${C_RESET}%b\n" "$CLR_EOL"
    if [ -f "$EVENTS_FILE" ]; then
        tail -n 6 "$EVENTS_FILE" | while IFS= read -r line; do
            printf "    ${C_DIM}%s${C_RESET}%b\n" "$line" "$CLR_EOL"
        done
    fi

    # pad a couple blank lines so short logs don't leave stale text
    printf "%b\n%b\n" "$CLR_EOL" "$CLR_EOL"

    printf "  ${C_BOLD}[r]${C_RESET} reconnect now    ${C_BOLD}[q]${C_RESET} tear down & quit%b\n" "$CLR_EOL"
    printf "%b" "$CLR_DOWN"
}

confirm_teardown() {                                 # returns 0 to proceed
    printf "%b" "$CUR_SHOW"
    printf "\n  ${C_YEL}Tear down the router and restore normal Wi-Fi? [y/N] ${C_RESET}"
    local ans; read -r ans
    printf "%b" "$CUR_HIDE"
    case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

tui_loop() {
    printf "%b" "$CUR_HIDE"
    printf "%b" "${CUR_HOME}${ESC}[2J"
    local key
    while :; do
        render
        if read -r -s -n 1 -t "$UI_REFRESH" key; then
            case "$key" in
                r|R) manual_reconnect ;;
                q|Q|2) if confirm_teardown; then printf "%b" "$CUR_SHOW"; return 0; fi ;;
                *) : ;;
            esac
        fi
    done
}

# =============================================================================
#  main
# =============================================================================
main() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must run as root (try: devel-su $0)" >&2
        exit 1
    fi

    mkdir -p "$STATE_DIR"
    : > "$EVENTS_FILE"
    rm -f "$STATUS_FILE"
    log "session started"

    # restore terminal if the user kills the UI process abruptly
    trap 'printf "%b" "$CUR_SHOW"; echo; echo "UI closed — router + supervisor still running. Re-run to reattach, or press q there to tear down."; exit 0' INT TERM

    do_setup
    start_supervisor

    trap - INT TERM                                  # inside the UI, keys drive everything
    tui_loop

    do_teardown
    log "session ended"
}

main "$@"

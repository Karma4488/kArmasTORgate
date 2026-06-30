#!/usr/bin/env python3
"""
kArmasTORgate - Transparent Tor traffic redirector for Kali Linux
We Are Legion

Routes all TCP traffic + DNS through Tor using iptables + the system tor daemon.
NOTE: This does NOT anonymize UDP (besides DNS) or ICMP (ping) by default -
those are dropped to prevent leaks unless you explicitly allow them.

Requires: tor, iptables (run as root)
Install tor:  sudo apt install tor -y
"""

import os
import subprocess
import sys
import shutil

TOR_UID = None  # auto-detected below
TRANS_PORT = 9040
DNS_PORT = 5353
VIRT_ADDR = "10.192.0.0/10"
NON_TOR = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

TORRC_PATH = "/etc/tor/torrc"
TORRC_BACKUP = "/etc/tor/torrc.kArmas.bak"
RESOLV_PATH = "/etc/resolv.conf"
RESOLV_BACKUP = "/etc/resolv.conf.kArmas.bak"

BANNER = r"""
   _    _   _                      _____ ____  ____           _
  | | _/ \ | |_ __ _    __ _ ___  |_   _/ ___||  _ \ __ _ _ __| | __
  | |/ / _ \| __/ _` |  / _` / __|   | || |  _ | |_) / _` | '_ \ |/ /
  |   < ___ \ || (_| | | (_| \__ \   | || |_| ||  _ < (_| | |_) |   <
  |_|\_\_| \_\__\__,_|  \__,_|___/   |_| \____||_| \_\__,_| .__/|_|\_\
                                                            |_|
        [ We Are Legion ]  Transparent Tor Traffic Gateway
"""

def run(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check)

def require_root():
    if os.geteuid() != 0:
        print("[!] This must be run as root (sudo).")
        sys.exit(1)

def get_tor_uid():
    try:
        out = subprocess.check_output("id -u debian-tor", shell=True).decode().strip()
        return out
    except Exception:
        try:
            out = subprocess.check_output("id -u tor", shell=True).decode().strip()
            return out
        except Exception:
            print("[!] Could not find tor user (debian-tor/tor). Is tor installed?")
            sys.exit(1)

def check_tor_installed():
    if shutil.which("tor") is None:
        print("[!] tor is not installed. Run: sudo apt install tor -y")
        sys.exit(1)

def write_torrc():
    config = f"""
## --- kArmasTORgate config block ---
VirtualAddrNetworkIPv4 {VIRT_ADDR}
AutomapHostsOnResolve 1
TransPort {TRANS_PORT}
DNSPort {DNS_PORT}
## --- end kArmasTORgate config block ---
"""
    if os.path.exists(TORRC_PATH) and not os.path.exists(TORRC_BACKUP):
        shutil.copy(TORRC_PATH, TORRC_BACKUP)
        print(f"[+] Backed up original torrc to {TORRC_BACKUP}")

    with open(TORRC_PATH, "a") as f:
        f.write(config)
    print("[+] torrc updated with transparent proxy settings")

def restore_torrc():
    if os.path.exists(TORRC_BACKUP):
        shutil.copy(TORRC_BACKUP, TORRC_PATH)
        print("[+] torrc restored from backup")
    else:
        print("[!] No torrc backup found, leaving as-is")

def flush_iptables():
    run("iptables -F")
    run("iptables -t nat -F")

def set_iptables(tor_uid):
    flush_iptables()

    # Don't redirect traffic FROM tor itself (avoid loops)
    run(f"iptables -t nat -A OUTPUT -m owner --uid-owner {tor_uid} -j RETURN")

    # Redirect DNS
    run(f"iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports {DNS_PORT}")

    # Allow local/private nets to pass untouched
    for net in NON_TOR:
        run(f"iptables -t nat -A OUTPUT -d {net} -j RETURN")

    # Redirect all other TCP to Tor's TransPort
    run(f"iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports {TRANS_PORT}")

    # Block everything else to prevent leaks (UDP non-DNS, ICMP, etc.)
    run("iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
    for net in NON_TOR:
        run(f"iptables -A OUTPUT -d {net} -j ACCEPT")
    run(f"iptables -A OUTPUT -m owner --uid-owner {tor_uid} -j ACCEPT")
    run("iptables -A OUTPUT -j REJECT")

    print("[+] iptables rules applied — all TCP + DNS routed through Tor")
    print("[!] UDP (non-DNS) and ICMP are now BLOCKED to prevent leaks")

def lock_dns(dns_port=DNS_PORT):
    """Force system DNS resolution to 127.0.0.1 (Tor's DNSPort) and
    make resolv.conf immutable so apps/NetworkManager/VPN clients can't
    silently overwrite it with a real-world resolver (the #1 DNS leak cause)."""
    if os.path.exists(RESOLV_PATH) and not os.path.exists(RESOLV_BACKUP):
        try:
            shutil.copy(RESOLV_PATH, RESOLV_BACKUP)
            print(f"[+] Backed up resolv.conf to {RESOLV_BACKUP}")
        except Exception as e:
            print(f"[!] Could not back up resolv.conf: {e}")

    # Remove immutable bit if previously set, so we can edit
    run(f"chattr -i {RESOLV_PATH}", check=False)

    with open(RESOLV_PATH, "w") as f:
        f.write("# Locked by kArmasTORgate - all DNS via local Tor DNSPort\nnameserver 127.0.0.1\n")

    # Make it immutable: even root processes/daemons can't rewrite it
    # without first running 'chattr -i' (which only this tool's stop() does)
    run(f"chattr +i {RESOLV_PATH}", check=False)
    print("[+] resolv.conf locked to 127.0.0.1 and made immutable")

def unlock_dns():
    run(f"chattr -i {RESOLV_PATH}", check=False)
    if os.path.exists(RESOLV_BACKUP):
        shutil.copy(RESOLV_BACKUP, RESOLV_PATH)
        print("[+] resolv.conf restored from backup")
    else:
        print("[!] No resolv.conf backup found, leaving as locked-DNS version")
        with open(RESOLV_PATH, "w") as f:
            f.write("nameserver 1.1.1.1\n")

def block_ipv6():
    """Tor doesn't carry IPv6 by default in this config, so any IPv6-capable
    app/site will bypass Tor entirely over IPv6 unless we kill it outright."""
    run("ip6tables -F", check=False)
    run("ip6tables -t nat -F", check=False)
    run("ip6tables -P INPUT DROP", check=False)
    run("ip6tables -P OUTPUT DROP", check=False)
    run("ip6tables -P FORWARD DROP", check=False)
    run("ip6tables -A INPUT -i lo -j ACCEPT", check=False)
    run("ip6tables -A OUTPUT -o lo -j ACCEPT", check=False)
    print("[+] IPv6 fully blocked (prevents IPv6 leak bypassing Tor)")

def restore_ipv6():
    run("ip6tables -F", check=False)
    run("ip6tables -t nat -F", check=False)
    run("ip6tables -P INPUT ACCEPT", check=False)
    run("ip6tables -P OUTPUT ACCEPT", check=False)
    run("ip6tables -P FORWARD ACCEPT", check=False)
    print("[+] IPv6 rules restored to normal")


    flush_iptables()
    run("iptables -P OUTPUT ACCEPT", check=False)
    print("[+] iptables rules cleared, normal traffic restored")

def restart_tor():
    run("systemctl restart tor")
    print("[+] tor service restarted")

def stop_tor():
    run("systemctl stop tor", check=False)

def status():
    print("[*] Checking current public IP via Tor (curl through transparent proxy)...")
    try:
        out = subprocess.check_output(
            "curl -s --max-time 15 https://check.torproject.org/api/ip", shell=True
        ).decode()
        print(out)
    except Exception as e:
        print(f"[!] Check failed: {e}")

    print("\n[*] DNS resolver currently in use:")
    try:
        with open(RESOLV_PATH) as f:
            print(f.read().strip())
    except Exception as e:
        print(f"[!] Could not read resolv.conf: {e}")

    print("\n[*] DNS leak test (resolving via local resolver, should hit Tor exit, not your ISP):")
    try:
        out = subprocess.check_output(
            "curl -s --max-time 15 https://check.torproject.org/api/ip?get_extra_info=1", shell=True
        ).decode()
        print(out)
    except Exception as e:
        print(f"[!] DNS leak check failed: {e}")
    print("\n[i] For a thorough check, also visit dnsleaktest.com from a real browser.")

def start():
    require_root()
    check_tor_installed()
    tor_uid = get_tor_uid()
    write_torrc()
    restart_tor()
    set_iptables(tor_uid)
    lock_dns()
    block_ipv6()
    print("\n[+] kArmasTORgate ACTIVE — all traffic + DNS routed through Tor.")
    print("[+] resolv.conf is locked (immutable) and IPv6 is blocked.")
    print("[!] Browser-level leaks (WebRTC, browser fingerprint, plugins) are")
    print("    NOT covered by network-layer tooling. Run:")
    print("      python3 kArmasTORgate.py browserhelp")
    print("    for fixes.")
    print("[+] Verify with: python3 kArmasTORgate.py status")

def stop():
    require_root()
    restore_iptables()
    restore_ipv6()
    unlock_dns()
    restore_torrc()
    stop_tor()
    print("\n[+] kArmasTORgate DISABLED — traffic, DNS, and IPv6 restored to normal.")

def browser_help():
    print("""
[*] Application-layer leak notes (NOT fixable via iptables/DNS):

  WebRTC leaks:
    Browsers can leak your real local/public IP via WebRTC STUN requests
    even when all OS-level traffic is forced through Tor, because WebRTC
    can open its own UDP sockets outside the browser's proxy settings.

    Fixes:
      - Use Tor Browser (WebRTC disabled by default) instead of Chrome/Firefox.
      - Firefox: set media.peerconnection.enabled = false in about:config
      - Chrome/Chromium: install an extension like "WebRTC Leak Prevent"
        (no built-in toggle exists in stock Chrome)

  Browser fingerprinting:
    Screen size, fonts, installed plugins, timezone, canvas/WebGL output
    can deanonymize you regardless of IP. Network-layer tooling (this
    script) cannot fix this — only a hardened browser (Tor Browser) can,
    since it normalizes these values across all users.

  DNS-over-HTTPS (DoH) bypass:
    Some browsers (Firefox, Chrome) ship a hardcoded DoH resolver that
    ignores /etc/resolv.conf entirely, bypassing the DNS lock in this tool.
      - Firefox: about:preferences -> Network Settings -> disable
        "Enable DNS over HTTPS"
      - Chrome: chrome://settings/security -> disable "Use secure DNS"

  Other apps:
    Any app with its own proxy/DNS settings (Discord, Slack, custom
    HTTP clients) may bypass system-wide iptables redirection if it
    binds directly or uses a hardcoded resolver. Check app-specific
    proxy settings individually.
""")


def main():
    print(BANNER)
    if len(sys.argv) < 2 or sys.argv[1] not in ("start", "stop", "status", "browserhelp"):
        print("Usage:")
        print("  sudo python3 kArmasTORgate.py start        # route all traffic through Tor")
        print("  sudo python3 kArmasTORgate.py stop         # restore normal traffic")
        print("  python3 kArmasTORgate.py status            # check current exit IP + DNS leak test")
        print("  python3 kArmasTORgate.py browserhelp        # app-layer leak fixes (WebRTC, DoH, fingerprinting)")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "start":
        start()
    elif cmd == "stop":
        stop()
    elif cmd == "status":
        status()
    elif cmd == "browserhelp":
        browser_help()

if __name__ == "__main__":
    main()

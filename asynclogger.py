#!/usr/bin/env python3
"""
Passive, Read-Only AV Rack Black-Box Logger
Designed for aging Extron, Biamp, Switch, Sennheiser ew G4, and Dante systems.
Uses Python 3 standard library only (zero external dependencies).
"""

import asyncio
import json
import logging
from logging.handlers import RotatingFileHandler
import socket
import struct
import time

# ==============================================================================
# 1. CONFIGURATION (Edit these IPs to match your AV subnet)
# ==============================================================================
LOG_FILE = "/var/log/av_blackbox.log"

DEVICES = {
    "Extron_CrossPoint": "192.168.1.10",
    "Extron_TouchPanel": "192.168.1.11",
    "Biamp_Tesira":      "192.168.1.20",
    "AV_Network_Switch": "192.168.1.1",
    "Sennheiser_Rx1":    "192.168.1.30",
    "Sennheiser_Rx2":    "192.168.1.31",
}

SENNHEISER_RECEIVERS = {
    "Sennheiser_Rx1": "192.168.1.30",
    "Sennheiser_Rx2": "192.168.1.31",
}

PING_INTERVAL_SEC = 5          # How often to check if devices are alive
SENNHEISER_POLL_SEC = 15       # Gentle polling interval for Sennheiser UDP
SYSLOG_PORT = 514              # Standard Syslog UDP port (requires root/sudo)
ENABLE_DANTE_MDNS_SNIFF = True # Passively watch Dante mDNS announcements

# ==============================================================================
# 2. LOGGING SETUP (Auto-rotates at 10MB, keeps 10 backup files)
# ==============================================================================
logger = logging.getLogger("AVBlackBox")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s", "%Y-%m-%d %H:%M:%S")

file_handler = RotatingFileHandler(LOG_FILE, maxBytes=10_000_000, backupCount=10)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# ==============================================================================
# 3. TASK 1: ICMP PING UPTIME & DROPOUT MONITOR
# ==============================================================================
async def ping_host(ip: str) -> bool:
    proc = await asyncio.create_subprocess_exec(
        "ping", "-c", "1", "-W", "1", ip,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL
    )
    await proc.communicate()
    return proc.returncode == 0

async def monitor_pings():
    device_state = {name: True for name in DEVICES}
    down_since = {}

    logger.info(f"[PING] Started uptime monitoring for {len(DEVICES)} devices.")
    while True:
        tasks = [ping_host(ip) for ip in DEVICES.values()]
        results = await asyncio.gather(*tasks)

        for (name, ip), is_up in zip(DEVICES.items(), results):
            was_up = device_state[name]
            if was_up and not is_up:
                device_state[name] = False
                down_since[name] = time.time()
                logger.error(f"[PING] {name} ({ip}) WENT OFFLINE!")
            elif not was_up and is_up:
                device_state[name] = True
                downtime = round(time.time() - down_since.get(name, time.time()), 1)
                logger.warning(f"[PING] {name} ({ip}) CAME BACK ONLINE (Downtime: {downtime}s)")

        await asyncio.sleep(PING_INTERVAL_SEC)

# ==============================================================================
# 4. TASK 2: SWITCH SYSLOG LISTENER (UDP 514)
# ==============================================================================
class SyslogProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        msg = data.decode("utf-8", errors="replace").strip()
        logger.info(f"[SYSLOG:{addr[0]}] {msg}")

async def start_syslog_server():
    loop = asyncio.get_running_loop()
    try:
        await loop.create_datagram_endpoint(
            lambda: SyslogProtocol(),
            local_addr=("0.0.0.0", SYSLOG_PORT)
        )
        logger.info(f"[SYSLOG] Listening for network switch logs on UDP port {SYSLOG_PORT}.")
    except PermissionError:
        logger.error(f"[SYSLOG] Permission denied on UDP {SYSLOG_PORT}. Run script with sudo/systemd.")
    except Exception as e:
        logger.error(f"[SYSLOG] Failed to bind UDP {SYSLOG_PORT}: {e}")

# ==============================================================================
# 5. TASK 3: SENNHEISER EW G4 (300/500) SSC UDP POLLER
# ==============================================================================
def query_sennheiser_udp(ip: str) -> dict | None:
    """Sends a lightweight SSC JSON query to Sennheiser EM 300-500 G4 on UDP 45."""
    query = json.dumps({
        "rx1": {"rf_level": None, "af_level": None, "mute": None},
        "tx1": {"bat_level": None, "warnings": None}
    }).encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.5)
    try:
        sock.sendto(query, (ip, 45))
        data, _ = sock.recvfrom(2048)
        return json.loads(data.decode("utf-8", errors="ignore"))
    except Exception:
        return None
    finally:
        sock.close()

async def monitor_sennheiser():
    if not SENNHEISER_RECEIVERS:
        return
    last_state = {}
    logger.info(f"[SENNHEISER] Polling {len(SENNHEISER_RECEIVERS)} receivers every {SENNHEISER_POLL_SEC}s.")

    while True:
        for name, ip in SENNHEISER_RECEIVERS.items():
            resp = await asyncio.to_thread(query_sennheiser_udp, ip)
            if not resp:
                continue

            bat = resp.get("tx1", {}).get("bat_level")
            warn = resp.get("tx1", {}).get("warnings")
            mute = resp.get("rx1", {}).get("mute")

            prev = last_state.get(name, {})
            if prev.get("bat") != bat or prev.get("warn") != warn or prev.get("mute") != mute:
                logger.info(f"[SENNHEISER] {name} ({ip}) | Battery: {bat}% | Mute: {mute} | Warnings: {warn}")
                last_state[name] = {"bat": bat, "warn": warn, "mute": mute}

        await asyncio.sleep(SENNHEISER_POLL_SEC)

# ==============================================================================
# 6. TASK 4: PASSIVE DANTE mDNS MULTICAST SNIFFER
# ==============================================================================
async def monitor_dante_mdns():
    if not ENABLE_DANTE_MDNS_SNIFF:
        return

    MCAST_GRP = "224.0.0.251"
    MCAST_PORT = 5353
    seen_dante_hosts = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", MCAST_PORT))
        mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setblocking(False)
        logger.info("[DANTE] Passively listening for Dante mDNS announcements on 224.0.0.251:5353.")
    except Exception as e:
        logger.error(f"[DANTE] Could not start mDNS listener: {e}")
        return

    loop = asyncio.get_running_loop()
    while True:
        try:
            data, addr = await loop.sock_recvfrom(sock, 4096)
            if b"_netaudio" in data:
                ip = addr[0]
                now = time.time()
                if ip not in seen_dante_hosts:
                    logger.info(f"[DANTE] Discovered/Registered Dante endpoint at {ip}")
                elif now - seen_dante_hosts[ip] > 90:
                    gap = round(now - seen_dante_hosts[ip], 1)
                    logger.warning(f"[DANTE] Dante endpoint {ip} re-announced after {gap}s silence!")
                seen_dante_hosts[ip] = now
        except Exception:
            await asyncio.sleep(1)

# ==============================================================================
# MAIN RUNNER
# ==============================================================================
async def main():
    logger.info("=== AV Black-Box Passive Logger Starting ===")
    await start_syslog_server()
    await asyncio.gather(
        monitor_pings(),
        monitor_sennheiser(),
        monitor_dante_mdns(),
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("=== AV Black-Box Logger Stopped Manually ===")

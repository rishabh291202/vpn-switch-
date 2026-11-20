import argparse
import datetime as dt
import json
import msvcrt
import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

import requests

API_URL = "https://api.mullvad.net/www/relays/wireguard/"
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOCK_PATH = BASE_DIR / "mullvadSwitch.lock"
MULLVAD_FALLBACK = Path(r"C:\Program Files\Mullvad VPN\resources\mullvad.exe")


def find_mullvad():
    executable = shutil.which("mullvad")
    if executable:
        return executable
    if MULLVAD_FALLBACK.exists():
        return str(MULLVAD_FALLBACK)
    raise FileNotFoundError(
        "Mullvad CLI was not found. Install Mullvad VPN or add mullvad.exe to PATH."
    )


def run_mullvad(args, check=True):
    command = [MULLVAD, *args]
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=90,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    output = (result.stdout or "") + (result.stderr or "")
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(command)}\n{output.strip()}"
        )
    return output.strip()


def acquire_lock():
    # Windows byte-range lock: automatically released if this process exits.
    handle = open(LOCK_PATH, "a+b")
    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write(b"0")
        handle.flush()
    handle.seek(0)
    try:
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:
        handle.close()
        raise RuntimeError("Another MullvadSwitch instance appears to be running.")
    return handle


def log(message):
    now = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    line = f"{now} | {message}"
    print(line, flush=True)
    LOG_DIR.mkdir(exist_ok=True)
    week_start = dt.datetime.now().date()
    week_start -= dt.timedelta(days=week_start.weekday())
    log_file = LOG_DIR / f"Week_{week_start.strftime('%d-%m-%Y')}.log"
    with log_file.open("a", encoding="utf-8") as stream:
        stream.write(line + "\n")


def collect_server_records(data, inherited_country=None):
    """Support both the flat relay-list format and nested country/city JSON."""
    records = []
    if isinstance(data, list):
        for item in data:
            records.extend(collect_server_records(item, inherited_country))
    elif isinstance(data, dict):
        country = (
            data.get("country_code")
            or data.get("country")
            or inherited_country
        )
        # A relay record has a hostname. Keep its own country_code when present.
        if data.get("hostname"):
            records.append({
                "hostname": str(data["hostname"]),
                "country_code": str(country or "").lower(),
                "active": data.get("active", True),
            })
        else:
            # Nested API formats may store the country code on a country object.
            nested_country = data.get("code") if "cities" in data else country
            for value in data.values():
                if isinstance(value, (dict, list)):
                    records.extend(collect_server_records(value, nested_country))
    return records


def get_usa_wireguard_servers():
    response = requests.get(API_URL, timeout=25)
    response.raise_for_status()
    data = response.json()

    records = collect_server_records(data)
    # Only explicitly USA records; if API provides active status, skip inactive relays.
    servers = sorted({
        item["hostname"] for item in records
        if item["country_code"] == "us"
        and item["hostname"].lower().startswith("us-")
        and item["active"] is not False
    })

    if not servers:
        raise RuntimeError(
            "The Mullvad relay API returned no active USA WireGuard servers. "
            "No connection change was attempted."
        )
    return servers


def current_status():
    return run_mullvad(["status"], check=False)


def connect_to_server(hostname):
    # Set WireGuard and an exact USA hostname, then reconnect.
    run_mullvad(["relay", "set", "location", hostname])
    run_mullvad(["disconnect"], check=False)
    time.sleep(2)
    run_mullvad(["connect"])

    # Wait up to 45 seconds for the tunnel to become connected.
    for _ in range(15):
        status = current_status()
        if "Connected" in status and hostname.lower() in status.lower():
            return status
        time.sleep(3)

    raise RuntimeError(
        f"Could not confirm connection to {hostname}. Current status:\n"
        f"{current_status()}"
    )


def public_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=15)
        response.raise_for_status()
        return response.json().get("ip", "Unknown")
    except requests.RequestException as exc:
        return f"Unavailable ({exc})"


def main(interval_seconds, disconnect_on_exit):
    global MULLVAD
    MULLVAD = find_mullvad()
    lock_handle = acquire_lock()
    previous = None

    try:
        # Keep the app-level country constraint on USA throughout the run.
        run_mullvad(["relay", "set", "location", "us"])
        servers = get_usa_wireguard_servers()
        log(f"Loaded {len(servers)} active USA WireGuard servers.")
        log(f"Rotation interval: {interval_seconds} seconds.")

        while True:
            candidates = [server for server in servers if server != previous]
            if not candidates:
                candidates = servers[:]
            hostname = random.choice(candidates)

            log(f"Switching to USA relay: {hostname}")
            status = connect_to_server(hostname)
            ip = public_ip()
            log(f"Connected | Relay: {hostname} | IP: {ip}")
            log(f"Status: {status.replace(chr(10), ' | ')}")
            previous = hostname

            log(f"Waiting {interval_seconds} seconds before next switch.")
            time.sleep(interval_seconds)

    finally:
        if disconnect_on_exit:
            log("Stopping: disconnecting Mullvad VPN as requested.")
            run_mullvad(["disconnect"], check=False)
        try:
            lock_handle.seek(0)
            msvcrt.locking(lock_handle.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            lock_handle.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Rotate Mullvad WireGuard relays using USA servers only."
    )
    parser.add_argument(
        "--duration", type=int, default=300,
        help="Seconds between server changes (default: 300 = 5 minutes)."
    )
    parser.add_argument(
        "--keep-connected-on-exit", action="store_true",
        help="Do not disconnect the VPN when Ctrl+C is pressed."
    )
    args = parser.parse_args()

    if args.duration < 60:
        parser.error("Please use an interval of at least 60 seconds.")

    try:
        main(args.duration, disconnect_on_exit=not args.keep_connected_on_exit)
    except KeyboardInterrupt:
        print("\nCtrl+C received. Stopping the rotation.", flush=True)
        sys.exit(0)
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)

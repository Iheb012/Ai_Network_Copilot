#!/usr/bin/env python3
"""AI Network Copilot — Updater

Checks for updates and applies them.
Can be called by the launcher or run standalone.
"""

import os
import sys
import json
import shutil
import zipfile
import tempfile
import urllib.request
import urllib.error
from pathlib import Path

VERSION_FILE = "version.txt"
UPDATE_URL = "https://api.github.com/repos/Iheb012/Ai_Network_Copilot/releases/latest"
PROJECT_DIR = Path(__file__).parent.resolve()


def get_current_version():
    vf = PROJECT_DIR / VERSION_FILE
    if vf.exists():
        return vf.read_text(encoding="utf-8").strip()
    return "0.0.0"


def check_latest():
    try:
        req = urllib.request.Request(UPDATE_URL, headers={"User-Agent": "AI-Network-Copilot"})
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode())
        latest = data.get("tag_name", "").lstrip("v")
        download_url = None
        for asset in data.get("assets", []):
            if asset.get("name", "").endswith(".zip"):
                download_url = asset.get("browser_download_url")
                break
        return latest, download_url, data.get("html_url", "")
    except Exception as e:
        return None, None, str(e)


def apply_update(zip_path, target_dir):
    with zipfile.ZipFile(zip_path, "r") as zf:
        target_dir = Path(target_dir).resolve()
        for member in zf.infolist():
            member_path = (target_dir / member.filename).resolve()
            if target_dir not in member_path.parents and member_path != target_dir:
                raise ValueError(f"Unsafe archive path detected: {member.filename}")
        zf.extractall(target_dir)
    return True


def main():
    current = get_current_version()
    print(f"Current version: v{current}")

    latest, download_url, info = check_latest()
    if not latest:
        print(f"Could not check for updates: {info}")
        return

    print(f"Latest version:  v{latest}")

    if latest == current:
        print("You are up to date!")
        return

    print(f"Update available: v{current} → v{latest}")

    if not download_url:
        print("No downloadable asset found. Visit the release page:")
        print(f"  {info}")
        return

    print("Downloading update...")
    try:
        req = urllib.request.Request(download_url, headers={"User-Agent": "AI-Network-Copilot"})
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            with urllib.request.urlopen(req, timeout=60) as resp:
                tmp.write(resp.read())
            tmp_path = tmp.name

        target = PROJECT_DIR
        apply_update(tmp_path, target)
        os.unlink(tmp_path)

        # Update version file
        (target / VERSION_FILE).write_text(latest, encoding="utf-8")
        print(f"Updated to v{latest}! Please restart the application.")
    except Exception as e:
        print(f"Update failed: {e}")


if __name__ == "__main__":
    main()

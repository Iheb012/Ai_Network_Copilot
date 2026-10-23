#!/usr/bin/env python3
"""AI Network Copilot — Launcher

Orchestrates the three services (collector, API, dashboard)
and provides a simple terminal UI with status and update support.
"""

import os
import sys
import time
import json
import shutil
import threading
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

# Console encoding: the → arrow in the status menu raises UnicodeEncodeError
# under the default cp1252 pipe encoding (redirected stdout). Force UTF-8 with
# replacement errors so the launcher never dies printing a character.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

VERSION_FILE = "version.txt"
UPDATE_URL = "https://api.github.com/repos/Iheb012/Ai_Network_Copilot/releases/latest"
MAX_OUTPUT_LINES = 300

# Find the project root by looking for the api/ directory (walk up from exe/script location)
_PROJECT_CANDIDATE = Path(sys.executable).parent.resolve() if getattr(sys, 'frozen', False) else Path(__file__).parent.resolve()
PROJECT_DIR = _PROJECT_CANDIDATE
for _ in range(5):  # walk up max 5 levels
    if (PROJECT_DIR / "api").is_dir():
        break
    PROJECT_DIR = PROJECT_DIR.parent

VENV_PYTHON = PROJECT_DIR / "venv" / "Scripts" / "python.exe"


def get_venv_python():
    p = VENV_PYTHON
    return str(p) if p.exists() else sys.executable


class Service:
    def __init__(self, name, args, cwd, color=96):
        self.name = name
        self.args = args
        self.cwd = cwd
        self.color = color
        self.process = None
        self.running = False
        self.output = []

    def start(self):
        try:
            self.process = subprocess.Popen(
                self.args,
                cwd=str(self.cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=False,
            )
            self.running = True
            threading.Thread(target=self._read_output, daemon=True).start()
            return True
        except Exception as e:
            print(f"  [!] Failed to start {self.name}: {e}")
            return False

    def _read_output(self):
        while self.process and self.process.poll() is None:
            line = self.process.stdout.readline()
            if line:
                self.output.append(line.decode("utf-8", errors="replace").rstrip())
                if len(self.output) > MAX_OUTPUT_LINES:
                    self.output = self.output[-MAX_OUTPUT_LINES:]
        self.running = False

    def stop(self):
        if not self.process:
            return
        if self.process.poll() is not None:
            self.running = False
            return
        if sys.platform == "win32":
            # /T kills the whole process tree — uvicorn/streamlit can spawn
            # children that survive a plain terminate(). /F is forceful.
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                    capture_output=True, timeout=10,
                )
            except subprocess.TimeoutExpired:
                pass
        else:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.running = False

    def status_line(self):
        symbol = "[OK]" if self.running else "[!!]"
        return f"  {symbol} {self.name}"


def print_header():
    os.system("cls" if sys.platform == "win32" else "clear")
    print("=" * 56)
    print("   AI NETWORK COPILOT  v" + get_local_version())
    print("   Network Monitoring & Anomaly Detection")
    print("=" * 56)
    print()
    print()


def get_local_version():
    version_path = PROJECT_DIR / VERSION_FILE
    try:
        if version_path.exists():
            return version_path.read_text(encoding="utf-8").strip() or "0.0.0"
    except Exception:
        pass
    return "0.0.0"


def check_for_update():
    try:
        current_version = get_local_version()
        req = urllib.request.Request(UPDATE_URL, headers={"User-Agent": "AI-Network-Copilot"})
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read().decode())
        latest = data.get("tag_name", "").lstrip("v")
        if latest and latest != current_version:
            return latest, data.get("html_url", "")
    except Exception:
        pass
    return None, None


def run_update_sequence():
    current_version = get_local_version()
    latest, url = check_for_update()
    if latest:
        print(f"\n  [UPDATE] v{current_version} -> v{latest}")
        print(f"     {url}")
        print("  Download the latest release and extract it over this folder.")
    else:
        print("\n  [OK] You have the latest version.")
    input("\n  Press Enter to continue...")


def main():
    python = get_venv_python()
    services = [
        Service("Collector",
                [python, "-u", str(PROJECT_DIR / "collector" / "simulator_v2.py")],
                PROJECT_DIR, 92),
        Service("API",
                [python, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"],
                PROJECT_DIR / "api", 94),
        Service("Dashboard",
                [python, "-m", "streamlit", "run", str(PROJECT_DIR / "dashboard" / "app.py"),
                 "--server.port", "8501"],
                PROJECT_DIR, 96),
    ]

    try:
        print_header()
        print("  Starting services...\n")

        for s in services:
            if s.start():
                print(f"  [OK] {s.name} started")
            else:
                print(f"  [!!] {s.name} FAILED")
            time.sleep(1.5)

        print("\n" + "=" * 56)
        for s in services:
            print(s.status_line())
        print()
        print("  [Dashboard]  →  http://localhost:8501")
        print("  [API Docs]   →  http://localhost:8000/docs")
        print("  [API Health] →  http://localhost:8000/health")
        print()
        print("  Commands: [S]tatus  [U]pdate check  [Q]uit")
        print("=" * 56)

        while True:
            try:
                cmd = input("\n  > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                break

            if cmd in ("q", "quit", "exit"):
                break
            elif cmd in ("s", "status"):
                print()
                for s in services:
                    print(s.status_line())
                    if s.output:
                        for line in s.output[-12:]:
                            print(f"     {line}")
            elif cmd in ("u", "update"):
                run_update_sequence()
            elif cmd:
                print(f"  Unknown command: {cmd}")

    finally:
        print("\n  Shutting down services...")
        for s in services:
            s.stop()
            print(f"  [STOP] {s.name} stopped")
        print("\n  Goodbye!")


if __name__ == "__main__":
    main()

"""
CYBERTRACE - Server Launcher
Starts the local CyberTrace Security Incident Detection & Investigation System.
Provides a clear console banner and direct access URL for students and examiners.
"""

import sys
import uvicorn
from pathlib import Path

def print_banner():
    banner = r"""
================================================================================
   ______ ____  ___  ______ ____ _____  ____  ___   ______ ______
  / ____/ \ \ \/ / |/ / __// __ \_  __/ / __ \/   | / ____// ____/
 / /       \ \  /  ' / _/ / /_/ // /   / /_/ / /| |/ /    / _/    
/ /___     / / / /| / /__/ _, _// /   / _, _/ ___ / /___ / /___   
\____/    /_/ /_/ |/____/_/ |_|/_/   /_/ |_/_/  |_\____//_____/   

   SECURITY INCIDENT DETECTION & INVESTIGATION SYSTEM
   Third-Year BSc Cybersecurity Demonstration Project
================================================================================
[*] Pipeline: Log Parser -> Normalization -> Rule Engine -> Correlation -> Risk Scoring -> Report
[*] SQLite Database initialized at: data/cybertrace.db
[*] Access URL: http://127.0.0.1:8000
================================================================================
    """
    print(banner)

def main():
    print_banner()
    print("[+] Starting CyberTrace SOC server on http://127.0.0.1:8000 ...")
    print("[+] Press Ctrl+C to stop the server.\n")

    try:
        uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False, log_level="info")
    except KeyboardInterrupt:
        print("\n[!] CyberTrace server shut down gracefully.")
    except Exception as e:
        print(f"\n[!] Startup error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

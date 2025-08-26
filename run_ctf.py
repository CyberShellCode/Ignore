#!/usr/bin/env python3
import sys
import os
import subprocess

def main():
    if len(sys.argv) < 2:
        print("""
CTF Solver - Quick Start
========================

Usage:
  python ctf.py <url>              # Full scan
  python ctf.py <url> SQLI         # Test SQLi only
  python ctf.py <url> XSS          # Test XSS only
  python ctf.py <url> RCE          # Test RCE only

Examples:
  python ctf.py http://ctf.local:8080
  python ctf.py http://challenge.ctf.com SQLI
  python ctf.py http://10.10.10.10:1337 RCE

Available vulnerability types:
  SQLI, XSS, RCE, IDOR, SSRF, XXE, SSTI, LFI, 
  AUTH, JWT, UPLOAD, DESERIAL, RACE, LOGIC
""")
        sys.exit(1)
    
    url = sys.argv[1]
    
    # Build command
    cmd = [sys.executable, "__main__.py", "ctf", url]
    
    # Add vulnerability type if specified
    if len(sys.argv) > 2:
        vuln_type = sys.argv[2].upper()
        cmd.extend(["--vuln", vuln_type])
        print(f"🎯 Testing {vuln_type} on {url}\n")
    else:
        print(f"🔍 Full CTF scan on {url}\n")
    
    # Add default CTF options
    cmd.extend([
        "--llm", "ollama",
        "--planner", "aggressive",
        "--scorer", "weighted_signal",
        "--llm-steps", "5"
    ])
    
    # Run the command
    print(f"Running: {' '.join(cmd)}\n")
    print("-" * 60)
    
    result = subprocess.run(cmd, cwd=os.path.dirname(os.path.abspath(__file__)))
    
    return result.returncode

if __name__ == "__main__":
    main()

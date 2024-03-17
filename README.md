# DataProbe

**DataProbe** is a Python script designed for reconnaissance and information gathering purposes. It provides various functionalities to gather information about a target domain, including Google Dorking, DNS checking, subdomain discovery, technology identification, WHOIS lookup, VirusTotal checking, Shodan checking, OS detection, port scanning, and version detection.

## Features
- Google Dorking : *Search for specific information using Google Dorks and save the results to a file.*
- DNS Checking : *Retrieve DNS records such as NS, A, AAAA, and MX records for the target domain.*
- Subdomain Discovery : *Discover subdomains of the target domain using a provided list of subdomains.*
- Technology Finder : *Identify the technologies used by the target domain.*
- WHOIS Lookup : *Retrieve WHOIS information for the target domain.*
- VirusTotal Checking : *Check the security status of the target domain using VirusTotal.*
- Shodan Checking : *Gather information about the target domain from Shodan, including open ports and organization details.*
- OS Detection : *Detect the operating system of the target using Nmap.*
- Port Scanning : *Scan the top ports of the target domain using Nmap.*
- Version Detection : *Detect software versions running on the target using Nmap.*

### Usage

### Clone the repository:
    git clone https://github.com/Symbolexe/DataProbe.git

### Navigate to the project directory:
    cd DataProbe

### Run the script:
    python3 DataProbe.py

**Follow the on-screen prompts to select the desired tool and provide necessary inputs.**

## Requirements
- Python 3.x
## Required Python packages:
#### install 
    pip install -r requirements.txt
- dns-python
- builtwith
- python-whois
- google
- colorama
- nmap
- shodan

## Disclaimer

*This script is provided for educational and informational purposes only. Users are solely responsible for their actions and should use this script responsibly and ethically.*

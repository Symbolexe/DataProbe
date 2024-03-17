import dns.resolver
import builtwith
import whois
from googlesearch import search
from colorama import Fore
import nmap3
import socket
import requests
import shodan
import os

def clear_page():
    os.system("cls" if os.name == "nt" else "clear")

def print_banner():
    print(Fore.BLUE + """
    https://GitHub.com/Symbolexe/DataProbe/
    https://T.Me/Symbolexe
""")
    
def print_menu():
    print(Fore.BLUE + "[1]" + Fore.WHITE + " Google Dork")
    print(Fore.BLUE + "[2]" + Fore.WHITE + " DNS Checking")
    print(Fore.BLUE + "[3]" + Fore.WHITE + " Subdomain Discovery")
    print(Fore.BLUE + "[4]" + Fore.WHITE + " Technology Finder")
    print(Fore.BLUE + "[5]" + Fore.WHITE + " Whois")
    print(Fore.BLUE + "[6]" + Fore.WHITE + " VirusTotal Checking")
    print(Fore.BLUE + "[7]" + Fore.WHITE + " Shodan Checking")
    print(Fore.BLUE + "[8]" + Fore.WHITE + " OS Detection")
    print(Fore.BLUE + "[9]" + Fore.WHITE + " Port Scanning")
    print(Fore.BLUE + "[10]" + Fore.WHITE + " Version Detection")

def get_target():
    target = input(Fore.GREEN + "[+] " + Fore.WHITE + "[TARGET] : ")
    target = target.replace(".www", "").replace("https://", "").replace("http://", "")
    return target

def google_dork():
    query = input(Fore.GREEN + "[+]" + Fore.WHITE + "[Your Dork] : ")
    number = int(input(Fore.GREEN + "[+]" + Fore.WHITE + "[How Much Site? Maximum is 100] : "))
    results = search(query, tld="co.in", num=number, stop=number, pause=10)
    with open("DataProbe-DorkSearch.txt", "w") as text_file:
        text_file.write("\n".join(results))
    print(Fore.GREEN + "[+]" + Fore.WHITE + "Results Saved : " + Fore.YELLOW + "DataProbe-DorkSearch.txt")

def dns_checking(target):
    record_types = ["NS", "A", "AAAA", "MX"]
    for record_type in record_types:
        records = dns.resolver.resolve(target, record_type)
        print(Fore.GREEN + "[+]" + Fore.WHITE + f"{record_type} Records for {target}:")
        for record in records:
            print(Fore.BLUE + "[*]" + Fore.WHITE + str(record))

def subdomain_discovery(target):
    def check_subdomains(domain, subdomain_list):
        for subdomain in subdomain_list:
            subdomain = subdomain.strip()
            full_domain = f"{subdomain}.{domain}"
            try:
                ip_address = socket.gethostbyname(full_domain)
                print(Fore.GREEN + f"Subdomain {full_domain} exists with IP address: {ip_address}")
            except socket.gaierror:
                print(Fore.RED + f"Subdomain {full_domain} does not exist")

    domain_to_check = target
    subdomain_file_path = input(Fore.GREEN + "[+]" + Fore.WHITE + "[Subdomain File] : ")
    try:
        with open(subdomain_file_path, "r") as subdomain_file:
            subdomains = subdomain_file.readlines()
            check_subdomains(domain_to_check, subdomains)
    except FileNotFoundError:
        print(f"Error: File '{subdomain_file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def technology_finder(target):
    url = "https://" + target
    technologies = builtwith.builtwith(url)
    print(Fore.GREEN + "[+]" + Fore.WHITE + f"\nTechnologies used by {url}:")
    for category, tech_list in technologies.items():
        print(f"{category}:")
        for tech in tech_list:
            print(Fore.BLUE + "[*]" + Fore.WHITE + f"  - {tech}")

def whois_lookup(target):
    domain_to_check = "https://" + target
    try:
        domain_info = whois.whois(domain_to_check)
        print(Fore.GREEN + "[+]" + Fore.WHITE + "WHOIS Information:")
        print(Fore.BLUE + "[*]" + Fore.WHITE + f"Domain Name: {domain_info.domain_name}")
        print(Fore.BLUE + "[*]" + Fore.WHITE + f"Registrar: {domain_info.registrar}")
        print(Fore.BLUE + "[*]" + Fore.WHITE + f"Creation Date: {domain_info.creation_date}")
        print(Fore.BLUE + "[*]" + Fore.WHITE + f"Expiration Date: {domain_info.expiration_date}")
        print(Fore.BLUE + "[*]" + Fore.WHITE + f"Name Servers: {domain_info.name_servers}")
    except whois.parser.PywhoisError as e:
        print(Fore.RED + "[-]" + Fore.WHITE + f"Error while retrieving WHOIS information: {e}")
    except Exception as e:
        print(Fore.RED + "[-]" + Fore.WHITE + f"An unexpected error occurred: {e}")

def virus_total_checking(target):
    api_key = input(Fore.GREEN + "[+]" + Fore.WHITE + "[VirusTotal API Key] : ")
    url_to_check = "https://" + target
    try:
        url_scan_endpoint = "https://www.virustotal.com/vtapi/v2/url/report"
        params = {"apikey": api_key, "resource": url_to_check}
        response = requests.get(url_scan_endpoint, params=params)
        result = response.json()
        if response.status_code == 200:
            if result["response_code"] == 1:
                print(Fore.GREEN + "[+]" + Fore.WHITE + f"\nURL: {url_to_check}")
                print(Fore.BLUE + "[*]" + Fore.WHITE + f"Scan Date: {result['scan_date']}")
                print(Fore.BLUE + "[*]" + Fore.WHITE + f"Positives / Total: {result['positives']} / {result['total']}")
                print(Fore.GREEN + "[+]" + Fore.WHITE + "Scan Results:")
                for scan, result in result["scans"].items():
                    print(Fore.BLUE + "[*]" + Fore.WHITE + f"  {scan}: {result['result']}")
            else:
                print(Fore.GREEN + "[+]" + Fore.WHITE + f"\nURL: {url_to_check}")
                print(Fore.BLUE + "[*]" + Fore.WHITE + f"Response Code: {result['response_code']}")
                print(Fore.BLUE + "[*]" + Fore.WHITE + f"Verbose Message: {result['verbose_msg']}")
        else:
            print(Fore.RED + "[-]" + Fore.WHITE + f"Error: {response.status_code}, {response.text}")
    except Exception as e:
        print(Fore.RED + "[-]" + Fore.WHITE + f"An unexpected error occurred: {e}")

def shodan_checking(target):
    SHODAN_API = input(Fore.GREEN + "[+]" + Fore.WHITE + "[SHODAN API Key] : ")

    def check_shodan_info(api_key, host):
        try:
            api = shodan.Shodan(api_key)
            host_info = api.host(host)
            print(f"\nHost: {host}")
            print(f"IP Address: {host_info['ip_str']}")
            print(f"Country: {host_info['country_name']}")
            print(f"Organization: {host_info.get('org', 'N/A')}")
            print("Open Ports:")
            for item in host_info["data"]:
                print(f"  Port {item['port']} - {item['transport']}")
        except shodan.APIError as e:
            print(f"Error: {e}")

    api_key = SHODAN_API
    host_to_check = target
    check_shodan_info(api_key, host_to_check)

def os_detection(target):
    try:
        nmap = nmap3.Nmap()
        os_results = nmap.nmap_os_detection(target)
        print(os_results)
    except:
        print(Fore.RED + "[-]" + Fore.WHITE + "ERROR.")

def port_scanning(target):
    try:
        nmap = nmap3.Nmap()
        results_top = nmap.scan_top_ports(target)
        print(results_top)
    except:
        print(Fore.RED + "[-]" + Fore.WHITE + "ERROR.")

def version_detection(target):
    try:
        nmap = nmap3.Nmap()
        version_result = nmap.nmap_version_detection(target)
        print(version_result)
    except:
        print(Fore.RED + "[-]" + Fore.WHITE + "ERROR.")

if __name__ == "__main__":
    clear_page()
    print_banner()
    print_menu()
    TARGET = get_target()
    Tools_Menu = int(input(Fore.GREEN + "[+]" + Fore.WHITE + "[Menu] : "))
    print(Fore.GREEN + "[+]" + Fore.WHITE + "TARGET SET => " + Fore.YELLOW + str(TARGET))

    if Tools_Menu == 1:
        google_dork()
    elif Tools_Menu == 2:
        dns_checking(TARGET)
    elif Tools_Menu == 3:
        subdomain_discovery(TARGET)
    elif Tools_Menu == 4:
        technology_finder(TARGET)
    elif Tools_Menu == 5:
        whois_lookup(TARGET)
    elif Tools_Menu == 6:
        virus_total_checking(TARGET)
    elif Tools_Menu == 7:
        shodan_checking(TARGET)
    elif Tools_Menu == 8:
        os_detection(TARGET)
    elif Tools_Menu == 9:
        port_scanning(TARGET)
    elif Tools_Menu == 10:
        version_detection(TARGET)
    else:
        print(Fore.RED + "[-]" + Fore.WHITE + "Bye...")
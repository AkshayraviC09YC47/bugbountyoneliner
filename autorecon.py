import os
import hashlib
import requests
import subprocess
import sys
from urllib.parse import urlparse

# Function to download the raw file from GitHub
def download_file(url, local_file_path):
    response = requests.get(url)
    if response.status_code == 200:
        with open(local_file_path, 'wb') as f:
            f.write(response.content)
        print(f"[+] File {local_file_path} updated successfully!")
        return True
    else:
        print("[!] Error downloading file from GitHub.")
        return False

# Function to compute the MD5 checksum of a file
def get_file_checksum(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Function to check if local file is up-to-date
def check_for_update(local_file_path, remote_url):
    print("[+] Checking for updates...")

    # Get remote file checksum
    response = requests.get(remote_url)
    if response.status_code == 200:
        remote_checksum = hashlib.md5(response.content).hexdigest()

        # Check if the local file exists
        if os.path.exists(local_file_path):
            local_checksum = get_file_checksum(local_file_path)

            if local_checksum != remote_checksum:
                print("[!] Update available. Downloading new version...")
                if download_file(remote_url, local_file_path):
                    return True  # Indicating the script was updated
            else:
                print("[+] Local file is up-to-date.")
                os.system('clear')
        else:
            print("[!] Local file does not exist. Downloading...")
            if download_file(remote_url, local_file_path):
                return True  # Indicating the script was downloaded
    else:
        print("[!] Error fetching remote file.")
        sys.exit(1)
    return False

# Function to run commands and show live results
def run_command_live(command):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, universal_newlines=True)
        for line in process.stdout:
            print(line, end='')  # Print live output as it happens
        process.stdout.close()
        process.wait()
    except KeyboardInterrupt:
        print("\n[!] Process interrupted by user. Exiting...")
        sys.exit(0)  # Exit cleanly when Ctrl+C is pressed
    except Exception as e:
        print(f"Error running command {command}: {e}")
        sys.exit(1)

# Function to filter out subdomains that are not part of the target domain
def filter_subdomains(subdomains_file, target_domain):
    filtered_subdomains = []
    with open(subdomains_file, 'r') as f:
        for line in f:
            subdomain = line.strip()
            if target_domain in subdomain:
                filtered_subdomains.append(subdomain)
    return filtered_subdomains

# Function to display banner
def print_banner():
    banner = """
    *********************************************
    *            Auto-Recon Tool                *
    *      Bug Bounty Reconnaissance Tool       *
    *         Automated Subdomain Recon         *
    *********************************************
    """
    print(banner)

# Main function to start the bug bounty reconnaissance process
def main():
    # Path to the local script file
    local_script_path = "/home/bug-hunting/autorecon.py"
    github_script_url = "https://raw.githubusercontent.com/AkshayraviC09YC47/bugbountyoneliner/refs/heads/main/autorecon.py"

    # Check and update script if needed
    if check_for_update(local_script_path, github_script_url):
        print("[+] Script has been updated to the latest version.")
        print("[+] Please re-run the script.")
        sys.exit(0)

    # Print banner
    print_banner()

    # Ask for target domain
    try:
        target_url = input("[+] Target URL: ").strip()
    except KeyboardInterrupt:
        print("\n[!] Process interrupted by user. Exiting...")
        sys.exit(0)  # Exit cleanly when Ctrl+C is pressed
    
    # Extract domain from URL
    domain = urlparse(target_url).netloc
    if not domain:
        print("Invalid URL. Please provide a valid URL with protocol (e.g., https://example.com).")
        sys.exit(1)

    # Define the directory path
    base_path = "/home/bug-hunting"
    target_folder = os.path.join(base_path, domain)

    # Check if the folder already exists
    if os.path.exists(target_folder):
        print(f"[!] Error: Folder {target_folder} already exists.")
        sys.exit(1)

    # Create the folder
    try:
        os.makedirs(target_folder)
        print(f"[+] Folder created: {target_folder}")
    except Exception as e:
        print(f"Error creating folder: {e}")
        sys.exit(1)

    # Run subfinder for subdomain enumeration and show results live
    print("[+] Running Subfinder...")
    subfinder_command = f"subfinder -d {domain} -o {os.path.join(target_folder, 'subdomains.txt')}"
    run_command_live(subfinder_command)

    # Filter subdomains to keep only those belonging to the target domain
    filtered_subdomains = filter_subdomains(os.path.join(target_folder, 'subdomains.txt'), domain)
    
    # Save filtered subdomains back to file
    with open(os.path.join(target_folder, 'subdomains_filtered.txt'), 'w') as f:
        for subdomain in filtered_subdomains:
            f.write(f"{subdomain}\n")
    print(f"[+] Filtered subdomains saved to {os.path.join(target_folder, 'subdomains_filtered.txt')}")

    # Run httpx to filter live subdomains and show results live
    print("[+] Running HTTPX to filter live domains...")
    httpx_command = f"httpx -l {os.path.join(target_folder, 'subdomains_filtered.txt')} -o {os.path.join(target_folder, 'httpx_live_domains.txt')}"
    run_command_live(httpx_command)

    # Run gau to fetch URLs from Wayback Machine
    print("[+] Running GAU for fetching URLs...")
    gau_command = f"gau {domain} | tee {os.path.join(target_folder, 'gau_results.txt')}"
    run_command_live(gau_command)

    # Run Katana for further enumeration and show live results
    print("[+] Running Katana for enumeration...")
    katana_command = f"katana -list {os.path.join(target_folder, 'httpx_live_domains.txt')} | tee {os.path.join(target_folder, 'katana_results.txt')}"
    run_command_live(katana_command)

    # Combine GAU and Katana results into a single file
    combined_file = os.path.join(target_folder, 'Gau_and_katana.txt')
    print(f"[+] Combining GAU and Katana results into {combined_file}...")
    with open(os.path.join(target_folder, 'gau_results.txt'), 'r') as gau_file, \
         open(os.path.join(target_folder, 'katana_results.txt'), 'r') as katana_file, \
         open(combined_file, 'w') as output_file:
        combined_urls = set(gau_file.read().splitlines() + katana_file.read().splitlines())
        sorted_urls = sorted(combined_urls)
        output_file.write('\n'.join(sorted_urls))
    print(f"[+] Combined and sorted results saved to {combined_file}.")

    # Run nuclei for vulnerability scanning with live results
    print("[+] Running Nuclei for vulnerability scanning...")
    nuclei_command = f"nuclei -l {os.path.join(target_folder, 'httpx_live_domains.txt')} -t /root/nuclei-templates/ -es info,unknown -o {os.path.join(target_folder, 'nuclei_results.txt')}"
    run_command_live(nuclei_command)

    print("[+] Bug bounty recon process completed.")

if __name__ == "__main__":
    main()

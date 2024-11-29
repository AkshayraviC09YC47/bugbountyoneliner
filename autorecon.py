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
    else:
        print("[!] Error downloading file from GitHub.")
        sys.exit(1)

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
                download_file(remote_url, local_file_path)
            else:
                print("[+] Local file is up-to-date.")
        else:
            print("[!] Local file does not exist. Downloading...")
            download_file(remote_url, local_file_path)
    else:
        print("[!] Error fetching remote file.")
        sys.exit(1)

# Function to run commands and capture the output
def run_command(command, output_file):
    try:
        with open(output_file, 'w') as f:
            subprocess.run(command, shell=True, stdout=f, stderr=subprocess.STDOUT)
        print(f"Results saved to {output_file}")
    except Exception as e:
        print(f"Error running command {command}: {e}")
        sys.exit(1)

# Main function to start the bug bounty reconnaissance process
def main():
    # Path to the local script file
    local_script_path = "/home/bug-hunting/autorecon.py"
    github_script_url = "https://raw.githubusercontent.com/AkshayraviC09YC47/bugbountyoneliner/refs/heads/main/autorecon.py"

    # Check and update script if needed
    check_for_update(local_script_path, github_script_url)

    # Ask for target URL
    target_url = input("[+] Target URL: ").strip()
    
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

    # Run subfinder for subdomain enumeration
    print("[+] Running Subfinder...")
    subfinder_command = f"subfinder -d {domain} -o {os.path.join(target_folder, 'subdomains.txt')}"
    run_command(subfinder_command, os.path.join(target_folder, 'subdomains.txt'))

    # Run nuclei for vulnerability scanning (exclude ssl, info, and unknown issues)
    print("[+] Running Nuclei...")
    nuclei_command = f"nuclei -u {target_url} -t /path/to/nuclei-templates/ -es info,unknown -o {os.path.join(target_folder, 'nuclei_results.txt')}"
    run_command(nuclei_command, os.path.join(target_folder, 'nuclei_results.txt'))

    # Run httpx for checking headers, status codes, etc.
    print("[+] Running HTTPX...")
    httpx_command = f"httpx -l {os.path.join(target_folder, 'subdomains.txt')} -o {os.path.join(target_folder, 'httpx_results.txt')}"
    run_command(httpx_command, os.path.join(target_folder, 'httpx_results.txt'))

    # Run katana for web scanning
    print("[+] Running Katana...")
    katana_command = f"katana -u {target_url} -o {os.path.join(target_folder, 'katana_results.txt')}"
    run_command(katana_command, os.path.join(target_folder, 'katana_results.txt'))

    # Run subzy for subdomain enumeration
    print("[+] Running Subzy...")
    subzy_command = f"subzy -d {domain} -o {os.path.join(target_folder, 'subzy_results.txt')}"
    run_command(subzy_command, os.path.join(target_folder, 'subzy_results.txt'))

    print("[+] Bug bounty recon process completed.")

if __name__ == "__main__":
    main()

import os
import hashlib
import requests
import subprocess
import sys
from urllib.parse import urlparse

# Path to the version file
version_file = "/home/bug-hunting/version.txt"

# Function to get the current version from version.txt
def get_current_version():
    if os.path.exists(version_file):
        with open(version_file, 'r') as file:
            version = file.read().strip()
            return version
    else:
        # Default version if no version file is found
        return "1.0.0"

# Function to increment the version
def increment_version(version):
    major, minor, patch = map(int, version.split('.'))
    patch += 1  # Increment the patch version
    return f"{major}.{minor}.{patch}"

# Function to update the version in version.txt
def update_version(version):
    with open(version_file, 'w') as file:
        file.write(version)

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
        else:
            print("[!] Local file does not exist. Downloading...")
            if download_file(remote_url, local_file_path):
                return True  # Indicating the script was downloaded
    else:
        print("[!] Error fetching remote file.")
        sys.exit(1)
    return False

# Function to run commands and capture the output
def run_command(command, output_file):
    try:
        with open(output_file, 'w') as f:
            subprocess.run(command, shell=True, stdout=f, stderr=subprocess.STDOUT)
        print(f"Results saved to {output_file}")
    except Exception as e:
        print(f"Error running command {command}: {e}")
        sys.exit(1)

# Function to display banner
def print_banner():
    banner = """
    *********************************************
    *             Auto-Recon Tool               *
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

    # Get current version
    current_version = get_current_version()
    print(f"[+] Current Version: {current_version}")

    # Check and update script if needed
    if check_for_update(local_script_path, github_script_url):
        print("[+] Script has been updated to the latest version.")

        # Increment the version
        new_version = increment_version(current_version)
        print(f"[+] New Version: {new_version}")

        # Update version in the version.txt file
        update_version(new_version)

        # Rename the script file based on the version
        new_script_name = f"/home/bug-hunting/autorecon-{new_version.replace('.', '-')}.py"
        os.rename(local_script_path, new_script_name)
        print(f"[+] Script renamed to: {new_script_name}")

        # Exit after update and notify the user to re-run the script
        print("[+] Please re-run the script to start using the latest version.")
        sys.exit(0)

    os.system('clear')

    print_banner()
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

    # Run subfinder for subdomain enumeration and show results
    print("[+] Running Subfinder...")
    subfinder_command = f"subfinder -d {domain} -o {os.path.join(target_folder, 'subdomains.txt')}"
    run_command(subfinder_command, os.path.join(target_folder, 'subdomains.txt'))

    # Show Subfinder results
    with open(os.path.join(target_folder, 'subdomains.txt'), 'r') as f:
        print("\n[+] Subfinder Results:")
        print(f.read())

    # Run httpx to filter live subdomains
    print("[+] Running HTTPX to filter live domains...")
    httpx_command = f"httpx -l {os.path.join(target_folder, 'subdomains.txt')} -o {os.path.join(target_folder, 'httpx_live_domains.txt')}"
    run_command(httpx_command, os.path.join(target_folder, 'httpx_live_domains.txt'))

    # Show filtered live domains
    with open(os.path.join(target_folder, 'httpx_live_domains.txt'), 'r') as f:
        print("\n[+] Live Domains from HTTPX:")
        print(f.read())

    # Run subzy for additional subdomains using live domains from HTTPX
    print("[+] Running Subzy for more subdomains...")
    subzy_command = f"subzy -l {os.path.join(target_folder, 'httpx_live_domains.txt')} -o {os.path.join(target_folder, 'subzy_results.txt')}"
    run_command(subzy_command, os.path.join(target_folder, 'subzy_results.txt'))

    # Show Subzy results
    with open(os.path.join(target_folder, 'subzy_results.txt'), 'r') as f:
        print("\n[+] Subzy Results:")
        print(f.read())

    # Run nuclei for vulnerability scanning (exclude ssl, info, and unknown issues)
    print("[+] Running Nuclei for vulnerability scanning...")
    nuclei_command = f"nuclei -l {os.path.join(target_folder, 'httpx_live_domains.txt')} -t /path/to/nuclei-templates/ -es info,unknown -o {os.path.join(target_folder, 'nuclei_results.txt')}"
    run_command(nuclei_command, os.path.join(target_folder, 'nuclei_results.txt'))

    # Show Nuclei results
    with open(os.path.join(target_folder, 'nuclei_results.txt'), 'r') as f:
        print("\n[+] Nuclei Results:")
        print(f.read())

    print("[+] Bug bounty recon process completed.")

if __name__ == "__main__":
    main()

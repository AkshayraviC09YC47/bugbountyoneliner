import os,hashlib,requests,subprocess,sys
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

# Function to run commands and capture the output
def run_command(command, output_file):
    try:
        with open(output_file, 'w') as f:
            subprocess.run(command, shell=True, stdout=f, stderr=subprocess.STDOUT)
        print(f"Results saved to {output_file}")
    except Exception as e:
        print(f"Error running command {command}: {e}")
        sys.exit(1)

# Function to run command and show live output in the terminal
def run_command_live(command):
    try:
        subprocess.run(command, shell=True, stdout=sys.stdout, stderr=sys.stderr)
    except KeyboardInterrupt:
        print("\n[!] Process interrupted. Exiting...")
        sys.exit(0)

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

    # Show filtered live domains (live output)
    run_command_live(f"httpx -l {os.path.join(target_folder, 'subdomains.txt')} -o {os.path.join(target_folder, 'httpx_live_domains.txt')}")

    # Run subzy for additional subdomains using live domains from HTTPX
    print("[+] Running Subzy for more subdomains...")
    subzy_command = f"subzy run --targets {os.path.join(target_folder, 'httpx_live_domains.txt')} | tee {os.path.join(target_folder, 'subzy_results.txt')}"
    run_command(subzy_command, os.path.join(target_folder, 'subzy_results.txt'))

    # Run dirsearch after subzy process
    print("[+] Running Dirsearch for directory and file enumeration...")

    dirsearch_command = f"dirsearch --url-file $(pwd)/{target_folder}/httpx_live_domains.txt -i 200 -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json --output $(pwd)/{target_folder}/dirsearch_result.txt"
    run_command(dirsearch_command, os.path.join(target_folder, 'dirsearch_result.txt'))

    # Run katana on live domains from HTTPX
    print("[+] Running Katana on live domains...")
    katana_command = f"katana -list {os.path.join(target_folder, 'httpx_live_domains.txt')} | tee {os.path.join(target_folder, 'katana_result.txt')}"
    run_command(katana_command, os.path.join(target_folder, 'katana_result.txt'))

    # Run nuclei for vulnerability scanning (exclude ssl, info, and unknown issues)
    print("[+] Running Nuclei for vulnerability scanning...")
    nuclei_command = f"nuclei -l {os.path.join(target_folder, 'httpx_live_domains.txt')} -t /root/nuclei-templates/ -es info,unknown -o {os.path.join(target_folder, 'nuclei_results.txt')}"
    run_command(nuclei_command, os.path.join(target_folder, 'nuclei_results.txt'))

    # Show Nuclei results live output
    run_command_live(f"nuclei -l {os.path.join(target_folder, 'httpx_live_domains.txt')} -t /root/nuclei-templates/ -es info,unknown -o {os.path.join(target_folder, 'nuclei_results.txt')}")

    print("[+] Bug bounty recon process completed.")

if __name__ == "__main__":
    main()

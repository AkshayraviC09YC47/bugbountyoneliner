import os
import subprocess
import sys
from urllib.parse import urlparse

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

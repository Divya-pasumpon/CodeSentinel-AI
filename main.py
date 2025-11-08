# main.py
import requests
import time
from datetime import datetime, timezone
from colorama import Fore, Style, init
import re
import tarfile  # New import for handling .tar.gz files
import io       # New import for handling in-memory files

def parse_requirements(filepath):
    """
    Reads a requirements.txt file and returns a clean list of package
    names.
    """
    packages = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            line = line.split('#')[0].strip()
            if not line: continue
            package_name = line.split('==')[0].split('>=')[0].split('<=')[0].strip()
            if package_name:
                packages.append(package_name)
    return packages

def get_package_data(package_name):
    """
    Fetches package data from the PyPI API.
    """
    print(f"-> Gathering intelligence for '{package_name}'...")
    api_url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            return response.json() 
        else:
            print(f"  [Error] Could not find package: {package_name}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"  [Error] Network error: {e}")
        return None

def extract_github_username(pypi_data):
    """Searches project URLs to find a GitHub username."""
    info = pypi_data.get('info', {})
    if not info:
        return None
    home_page = info.get('home_page') 
    if isinstance(home_page, str) and "github.com/" in home_page:
        match = re.search(r"github\.com/([^/]+)", home_page)
        if match:
            return match.group(1) 
    project_urls = info.get('project_urls') 
    if isinstance(project_urls, dict):
        for url in project_urls.values():
            if isinstance(url, str) and "github.com/" in url:
                match = re.search(r"github\.com/([^/]+)", url)
                if match:
                    return match.group(1) 
    return None 

def get_github_user_info(username):
    """Fetches user or organization data from the GitHub API."""
    print(f"  -> Running background check on GitHub user: '{username}'...")
    api_url = f"https://api.github.com/users/{username}"
    headers = {"User-Agent": "CodeSentinel-App"} 
    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"  [Warning] Could not get GitHub info for {username}.")
            return None
    except requests.exceptions.RequestException:
        return None

# --- NEW FUNCTION: The Source Code Scanner ---
def analyze_source_code(package_name, version):
    """
    Downloads, decompresses, and scans package source code for dangerous
    patterns.
    """
    print(f"  -> Performing static code analysis for '{package_name} v{version}'...")
    
    # 1. Find the download URL for the source distribution (.tar.gz)
    package_info = get_package_data(package_name)
    if not package_info or not package_info.get('releases', {}).get(version):
        return ["Could not find package info to scan source code."]
        
    source_url = None
    for file_info in package_info['releases'][version]:
        if file_info['packagetype'] == 'sdist': # 'sdist' = Source Distribution
            source_url = file_info['url']
            break
            
    if not source_url:
        return ["Could not find source code download URL (.tar.gz) to scan."]

    # 2. Define the "smoking guns" we're looking for
    DANGEROUS_PATTERNS = {
        "os.system": "High-risk OS command execution",
        "subprocess.run": "Potential for arbitrary command execution",
        "subprocess.call": "Potential for arbitrary command execution",
        "eval(": "Execution of arbitrary strings as code",
        "exec(": "Execution of arbitrary strings as code",
        "pickle.load": "Potential for code execution during deserialization",
        "requests.post": "Potential data exfiltration (HTTP POST)",
        "socket.socket": "Low-level networking, potential for backdoors"
    }
    
    findings = []
    
    try:
        # 3. Download the .tar.gz file into memory
        response = requests.get(source_url, stream=True)
        response.raise_for_status() # Raise error if download fails
        
        # 4. Decompress the file in memory
        tar_file_object = io.BytesIO(response.content)
        tar = tarfile.open(fileobj=tar_file_object, mode="r:gz")
        
        # 5. Read every file in the tarball
        for member in tar.getmembers():
            # Only read files, and only .py files (ignore images, docs, etc.)
            if member.isfile() and member.name.endswith('.py'):
                try:
                    # Extract and read the file content
                    file_content = tar.extractfile(member).read().decode('utf-8', errors='ignore')
                    
                    # 6. Scan line by line for our dangerous patterns
                    for line_num, line in enumerate(file_content.splitlines(), 1):
                        for pattern, description in DANGEROUS_PATTERNS.items():
                            if pattern in line:
                                # Found one!
                                finding = f"'{pattern}' found in {member.name} (line {line_num}): {description}"
                                findings.append(finding)
                except Exception:
                    # Ignore errors for single files (e.g., encoding issues)
                    continue
        
        return findings
        
    except Exception as e:
        return [f"Failed to download or analyze source code: {e}"]

# --- UPDATED SCORING FUNCTION ---
def calculate_trust_score(package_data, latest_version): # Added new argument
    """
    Analyzes package data and calculates a trust score based on a set of rules.
    """
    score = 100
    risk_factors = []
    
    info = package_data.get('info', {})
    package_name = info.get('name', 'unknown') # Get package name for scanner
    releases = package_data.get('releases', {})

    # (Rules 1-6 are the same)
    if not info.get('author'):
        score -= 5 
        risk_factors.append("Missing author name in PyPI metadata.")
    if not info.get('home_page'):
        score -= 10 
        risk_factors.append("No project homepage listed.")
    if releases:
        all_upload_times = []
        for version_files in releases.values():
            for file_info in version_files:
                upload_time_str = file_info.get('upload_time_iso_8601')
                if upload_time_str:
                    all_upload_times.append(datetime.fromisoformat(upload_time_str))
        if all_upload_times:
            first_release_date = min(all_upload_times)
            days_since_first_release = (datetime.now(timezone.utc) - first_release_date).days
            if days_since_first_release < 180: 
                score -= 25
                risk_factors.append(f"Package is new (created {days_since_first_release} days ago).")
        else:
            score -= 10
            risk_factors.append("No release history found.")
    else:
        score -= 10
        risk_factors.append("No release information available.")
    if len(releases) <= 2: 
        score -= 5
        risk_factors.append("Very few versions have been published.")
    github_username = extract_github_username(package_data)
    if github_username:
        github_info = get_github_user_info(github_username)
        if github_info:
            followers = github_info.get('followers', 0)
            if followers < 20:
                score -= 20
                risk_factors.append(f"GitHub account ({github_username}) has few followers ({followers}).")
            created_at_str = github_info.get('created_at')
            created_at_date = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
            days_since_creation = (datetime.now(timezone.utc) - created_at_date).days
            if days_since_creation < 365: 
                score -= 25
                risk_factors.append(f"GitHub account ({github_username}) is new ({days_since_creation} days old).")
        else:
            score -= 10 
            risk_factors.append(f"Could not verify GitHub username: {github_username}.")
    else:
        score -= 20
        risk_factors.append("No associated GitHub repository found.")

    # (Rule 7 is the same)
    dependencies = info.get('requires_dist', []) 
    if dependencies:
        SUSPICIOUS_KEYWORDS = ['socket', 'os', 'subprocess', 'ctypes', 'eval']
        for dep in dependencies:
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in dep.lower():
                    score -= 30 
                    risk_factors.append(f"Requires a potentially suspicious dependency: '{dep}'")
                    break 

    # --- NEW RULE 8: STATIC CODE ANALYSIS ---
    if latest_version:
        code_findings = analyze_source_code(package_name, latest_version)
        if code_findings:
            # This is a HUGE red flag.
            score -= 60 # Massive penalty
            risk_factors.append("!! STATIC CODE ANALYSIS FAILED !!")
            risk_factors.extend(code_findings) # Add all findings to the report
    else:
        risk_factors.append("Could not determine version to scan source code.")


    return max(0, score), risk_factors

# --- (display_report function is UNCHANGED) ---
def display_report(results):
    """
    Displays the analysis results in a color-coded format in the terminal.
    """
    init(autoreset=True) 
    print("\n" + "="*40)
    print(" === CodeSentinel AI: Final Report ===")
    print("="*40 + "\n")
    results.sort(key=lambda x: x['score'])
    
    for result in results:
        score = result['score']
        name = result['name']
        factors = result['factors']
        
        color = Fore.GREEN
        if score < 50:
            color = Fore.RED
        elif score < 80:
            color = Fore.YELLOW
            
        print(f"Package: {Style.BRIGHT}{name}")
        print(f"  Trust Score: {color}{Style.BRIGHT}{score}/100")
        
        if factors:
            print(f"  {Fore.RED}Identified Risk Factors:")
            for factor in factors:
                print(f"    - {factor}")
        else:
            print(f"  {Fore.GREEN}No major risk factors identified.")
        print("-" * 30)
    print("\n--- End of Report ---")

# --- UPDATED MAIN BLOCK ---
if __name__ == "__main__":
    print("--- CodeSentinel AI: Starting Full Analysis ---")
    
    filepath = 'requirements.txt'
    dependencies = parse_requirements(filepath)
    
    print(f"Found {len(dependencies)} packages to analyze: {dependencies}\n")
    
    analysis_results = []
    
    for package in dependencies:
        data = get_package_data(package)
        if data:
            # Get the latest version to pass to the scanner
            latest_version = data.get('info', {}).get('version')
            
            score, factors = calculate_trust_score(data, latest_version) # Pass version in
            result = {
                "name": package,
                "score": score,
                "factors": factors
            }
            analysis_results.append(result)
        
        time.sleep(0.5) 
        
    display_report(analysis_results)
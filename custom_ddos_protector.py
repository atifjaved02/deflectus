import re
import time
import requests
from collections import defaultdict, deque
from threading import Thread
from datetime import datetime

# Configuration
RATE_LIMIT = 100  # Max requests per IP per minute
TIME_WINDOW = 60  # Time window in seconds (1 minute)
BLOCK_TIME = 600  # Block time for IPs (in seconds)
LOG_FILE_PATH = "/var/log/nginx/access.log"  # Change to your web server log path
CLOUDFLARE_ZONE_ID = "your_cloudflare_zone_id"  # Your Cloudflare zone ID
CLOUDFLARE_API_TOKEN = "your_cloudflare_api_token"  # Your Cloudflare API token

# Cloudflare API Endpoint
CLOUDFLARE_API_URL = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/firewall/access_rules/rules"

# Data structures to track requests
ip_requests = defaultdict(deque)  # IP -> List of timestamps
blacklist = set()  # Set of blacklisted IPs

# Helper Functions
def clean_old_requests(ip):
    """Remove requests older than the time window."""
    current_time = time.time()
    ip_requests[ip] = deque([timestamp for timestamp in ip_requests[ip] if current_time - timestamp < TIME_WINDOW])

def log_request(ip):
    """Log a request for a given IP."""
    current_time = time.time()
    ip_requests[ip].append(current_time)
    clean_old_requests(ip)

def check_rate_limit(ip):
    """Check if an IP exceeds the rate limit."""
    clean_old_requests(ip)
    return len(ip_requests[ip]) > RATE_LIMIT

def blacklist_ip(ip):
    """Blacklist an IP for a certain period using Cloudflare API."""
    print(f"Blocking IP {ip} using Cloudflare API...")
    headers = {
        'Authorization': f'Bearer {CLOUDFLARE_API_TOKEN}',
        'Content-Type': 'application/json',
    }
    data = {
        "mode": "block",  # Block the IP
        "configuration": {
            "target": "ip",
            "value": ip,
        },
        "notes": f"Automated DDoS protection: Blocking IP {ip}"
    }
    response = requests.post(CLOUDFLARE_API_URL, headers=headers, json=data)
    
    if response.status_code == 200:
        print(f"Successfully blocked IP {ip}.")
        blacklist.add(ip)
        time.sleep(BLOCK_TIME)  # Block for a certain amount of time
        blacklist.remove(ip)
    else:
        print(f"Failed to block IP {ip}. Error: {response.text}")

def is_ip_blocked(ip):
    """Check if the IP is blacklisted."""
    return ip in blacklist

def process_log_entry(log_entry):
    """Process a single log entry and track the request."""
    # Regular expression pattern
    pattern = r'(?P<ip>((.*?) ))(.*?)(GET|POST|PUT|HEAD|PATCH|OPTIONS|DELETE)(?P<url>(.+?(?= )))(?P<useragent>((.*)))'
    
    match = re.search(pattern, log_entry)
    if match:
        ip = match.group('ip').strip()
        if is_ip_blocked(ip):
            print(f"Blocked request from {ip}")
            return
        log_request(ip)
        if check_rate_limit(ip):
            print(f"Rate limit exceeded for IP: {ip}. Blocking it.")
            blacklist_ip(ip)
            return

def tail_f(log_file):
    """Tail the log file to read new lines as they are added."""
    with open(log_file, "r") as file:
        file.seek(0, 2)  # Move to the end of the file
        while True:
            line = file.readline()
            if line:
                process_log_entry(line)
            else:
                time.sleep(0.1)  # Sleep briefly to avoid CPU overload

def start_log_monitoring():
    """Start monitoring the log file in a separate thread."""
    log_thread = Thread(target=tail_f, args=(LOG_FILE_PATH,))
    log_thread.daemon = True
    log_thread.start()

if __name__ == "__main__":
    print("Starting DDoS protection...")
    start_log_monitoring()
    
    # Keep the program running to monitor logs
    while True:
        time.sleep(1)

import re
import csv
from collections import defaultdict, Counter

# Configuration
FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"

def parse_log_file(log_file):
    """Parses the log file and extracts relevant data."""
    ip_requests = defaultdict(int)
    endpoints = Counter()
    failed_logins = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            if not ip_match:
                continue
            ip_address = ip_match.group(1)

            # Extract endpoint and HTTP status
            endpoint_match = re.search(r"\"(?:GET|POST) (.*?) HTTP", line)
            status_match = re.search(r"\" (\d{3}) ", line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoints[endpoint] += 1

            # Count requests per IP
            ip_requests[ip_address] += 1

            # Detect failed logins
            if status_match and status_match.group(1) == "401":
                failed_logins[ip_address] += 1
    return ip_requests, endpoints, failed_logins

def save_to_csv(ip_requests, endpoints, failed_logins, output_file):
    """Saves the results to a CSV file."""
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        most_accessed = endpoints.most_common(1)
        if most_accessed:
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow([most_accessed[0][0], most_accessed[0][1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])

def main():
    # Parse the log file
    ip_requests, endpoints, failed_logins = parse_log_file(LOG_FILE)

    # Display Requests per IP
    print("Requests per IP:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count:<15}")
        
    # Display Most Accessed Endpoint
    most_accessed = endpoints.most_common(1)
    if most_accessed:
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed[0][0]} (Accessed {most_accessed[0][1]} times)")
        
    # Display Suspicious Activity
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<15}")
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20} {count:<15}")
            
    # Save results to CSV
    save_to_csv(ip_requests, endpoints, failed_logins, OUTPUT_FILE)
    print(f"\nResults saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

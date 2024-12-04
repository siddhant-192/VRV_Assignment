import csv
from collections import defaultdict, Counter

def process_log_file(log_file, threshold=10):
    """
    Processes the log file and generates analysis for:
    1. Requests per IP address
    2. Most accessed endpoint
    3. Suspicious activity detection (failed login attempts)
    """
    ip_request_count = defaultdict(int)
    endpoint_counter = Counter()
    failed_login_attempts = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            # Strip leading/trailing whitespace
            line = line.strip()

            # Split into parts and ensure valid format
            parts = line.split()
            if len(parts) < 9:
                continue  # Skip malformed log entries

            # Extract IP, endpoint, and HTTP status code
            ip_address = parts[0]
            endpoint = parts[6].strip()  # Clean any extra whitespace
            status_code = parts[8]

            # Increment IP request count
            ip_request_count[ip_address] += 1

            # Increment endpoint count
            if endpoint:  # Ensure endpoint is not empty
                endpoint_counter[endpoint] += 1

            # Track failed login attempts (HTTP 401 or specific message)
            if status_code == "401" or "Invalid credentials" in line:
                failed_login_attempts[ip_address] += 1

    # Identify suspicious IPs based on threshold
    flagged_ips = {ip: count for ip, count in failed_login_attempts.items() if count > threshold}
    return ip_request_count, endpoint_counter, flagged_ips


def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips):
    """
    Saves analysis results to a CSV file.
    """
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write IP Requests
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        
        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)
        
        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])


def display_results(ip_requests, most_accessed_endpoint, suspicious_ips):
    """
    Prints the results in a user-friendly format.
    """
    print("\nRequests Per IP Address:")
    print(f"{'IP Address':<20}{'Request Count':<15}")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20}{count:<15}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20}{'Failed Login Attempts':<15}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count:<15}")
    else:
        print("No suspicious activity detected.")


if __name__ == "__main__":
    log_file_path = "sample.log"
    
    # Process the log file
    ip_requests, endpoints, suspicious_ips = process_log_file(log_file_path)
    
    # Identify most accessed endpoint
    most_accessed = endpoints.most_common(1)[0]
    
    # Display the results in the terminal
    display_results(ip_requests, most_accessed, suspicious_ips)
    
    # Save results to CSV
    save_to_csv(ip_requests, most_accessed, suspicious_ips)


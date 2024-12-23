import psutil
import time
import os
import re
from datetime import datetime

# Default suspicious keywords for analysis
DEFAULT_SUSPICIOUS_KEYWORDS = ["Failed login", "Unauthorized", "Secure Boot", "Error"]

# Default log format pattern: assumes timestamp followed by a message
DEFAULT_LOG_ENTRY_PATTERN = r"^(\d{2}:\d{2}:\d{2}\.\d{6}|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(.*)"

def alert_suspicious_activity(entry):
    """Alert the user about suspicious activity."""
    print("\n[ALERT] Suspicious Activity Detected!")
    print(f"Time: {entry['Time']}")
    print(f"Message: {entry['Message']}\n")

def parse_log_file(file_path, log_pattern):
    """Parse the log file and return a list of log entries."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    logs = []
    with open(file_path, "r") as file:
        for line in file:
            match = re.match(log_pattern, line)
            if match:
                logs.append({
                    "Time": match.group(1).strip(),
                    "Message": match.group(2).strip(),
                })
    return logs

def analyze_logs(logs, suspicious_keywords):
    """Analyze logs and alert on suspicious activities."""
    for log in logs:
        if any(keyword in log["Message"] for keyword in suspicious_keywords):
            alert_suspicious_activity(log)

# Function to monitor system performance
def monitor_performance(interval=1):
    try:
        print("--- Performance Monitoring Started ---")
        while True:
            # Read CPU usage
            cpu_usage = psutil.cpu_percent(interval=0.1)

            # Read memory usage
            memory_info = psutil.virtual_memory()
            memory_usage = memory_info.percent

            # Create notes based on performance
            notes = []
            if cpu_usage > 85:
                notes.append("High CPU usage detected!")
            if memory_usage > 85:
                notes.append("High memory usage detected!")

            # Print results to the screen
            log_entry = f"CPU Usage: {cpu_usage}% | Memory Usage: {memory_usage}%"
            if notes:
                log_entry += " | Notes: " + ", ".join(notes)
            print(log_entry.strip())

            # Wait between updates
            time.sleep(interval)
    except KeyboardInterrupt:
        print("--- Performance Monitoring Stopped ---")

# Main function
def main():
    print("Choose an option:")
    print("1. Monitor system performance")
    print("2. Analyze log file")

    choice = input("Enter your choice (1/2): ").strip()

    if choice == "1":
        try:
            interval = int(input("Enter the monitoring interval in seconds (default 1): ") or 1)
            monitor_performance(interval=interval)
        except ValueError:
            print("[ERROR] Invalid interval. Using default interval of 1 second.")
            monitor_performance(interval=1)

    elif choice == "2":
        log_file_path = input("Enter the path to the log file: ").strip()
        custom_pattern = input("Enter a custom log pattern (or press Enter to use the default): ").strip()
        suspicious_keywords = input("Enter suspicious keywords separated by commas (or press Enter for defaults): ").strip()

        # Use custom or default pattern
        log_pattern = custom_pattern if custom_pattern else DEFAULT_LOG_ENTRY_PATTERN

        # Use custom or default suspicious keywords
        keywords = [kw.strip() for kw in suspicious_keywords.split(",") if kw.strip()]
        if not keywords:
            keywords = DEFAULT_SUSPICIOUS_KEYWORDS

        try:
            print("Reading log file...")
            logs = parse_log_file(log_file_path, log_pattern)
            print(f"Total logs read: {len(logs)}")

            print("Analyzing logs...")
            analyze_logs(logs, keywords)

            print("Analysis complete.")
        except Exception as e:
            print(f"[ERROR] {e}")

    else:
        print("[ERROR] Invalid choice. Please restart the program.")

if __name__ == "__main__":
    main()
    input("Press Enter to exit...")

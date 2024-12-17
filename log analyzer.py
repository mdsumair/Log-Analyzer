import re
from datetime import datetime
import pandas as pd

# Load log file
def load_log_file(file_path):
    """Load the log file and return as a list of lines."""
    with open(file_path, 'r') as file:
        return file.readlines()

# parse logs
def parse_logs(logs):
    """Parse log lines and return structured log data."""
    parsed_logs = []
    log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\d+|-)')

   #Parsing each log lines 
    for log in logs:
        match = log_pattern.search(log)
        if match:
            log_data = match.groupdict()
            log_data['datetime'] = datetime.strptime(log_data['date'], '%d/%b/%Y:%H:%M:%S %z')
            parsed_logs.append(log_data)
    
    return pd.DataFrame(parsed_logs)

# Detect anomalies based on conditions
def detect_anomalies(logs_df):
    """Detect anomalies in log data."""
    alerts = []
    
    # 1. Check for unusual status codes (4xx and 5xx)
    for _, log in logs_df[logs_df['status'].astype(int) >= 400].iterrows():
        alerts.append(f"Alert: Suspicious HTTP status code {log['status']} from IP {log['ip']} on {log['datetime']}")
        
    # 2. Check for large file size requests
    for _, log in logs_df[logs_df['size'].astype(int) > 100000].iterrows():
        alerts.append(f"Alert: Large data transfer of {log['size']} bytes from IP {log['ip']} on {log['datetime']}")

    # 3. Multiple requests from a single IP within a short time
    logs_df['datetime'] = pd.to_datetime(logs_df['datetime'])
    grouped = logs_df.groupby('ip').size()
    for ip, count in grouped.items():
        if count > 100:  # Adjust threshold as needed
            alerts.append(f"Alert: High request frequency from IP {ip} with {count} requests.")

    return alerts

# main function to run the log analyzer
def run_log_analyzer(log_file_path):
    logs = load_log_file(log_file_path)
    parsed_logs = parse_logs(logs)
    alerts = detect_anomalies(parsed_logs)
    
    print("Log Analysis Complete.")
    if alerts:
        print("\nAlerts:")
        for alert in alerts:
            print(alert)
    else:
        print("No anomalies detected.")

# Run the analyzer
log_file_path = r'C:\Users\mohammed sumair khan\Dropbox\PC\Desktop\python projects\4.log analyzer\logfile.log'  # Path to your log file
run_log_analyzer(log_file_path)

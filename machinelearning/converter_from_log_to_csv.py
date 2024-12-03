import csv
import argparse

def process_log_file(log_file, http_csv):
    """
    Process the honeypot log file, filter for GET requests, and save them to a CSV file.

    Args:
        log_file (str): Path to the honeypot log file.
        http_csv (str): Path to save the filtered HTTP GET requests as CSV.
    """
    with open(log_file, 'r') as f:
        lines = f.readlines()

    http_data = []

    current_log = None
    for line in lines:
        line = line.strip()

        # Determine the type of log based on its header
        if line == "HTTP SERVER LOG":
            current_log = "HTTP"
        elif current_log == "HTTP" and line:
            if line.startswith("Time:"):
                http_entry = {"time": safe_split(line, ": ", 1)}
            elif line.startswith("Source IP:"):
                http_entry["source_ip"], http_entry["source_port"] = parse_ip_port(line)
            elif line.startswith("Request:"):
                request_parts = safe_split(line, ": ", 1).split(" ", 1)
                method = request_parts[0]
                if method.upper() == "GET":  # Only process GET requests
                    http_entry["method"] = method
                    http_entry["path"] = request_parts[1] if len(request_parts) > 1 else ""
            elif line.startswith("Response Code:"):
                response_parts = line.split(", ")
                http_entry["response_code"] = safe_split(response_parts[0], ": ", 1)
                response_size = safe_split(response_parts[1], ": ", 1)
                http_entry["response_size"] = response_size
            elif line.startswith("Host:"):
                http_entry["host"] = safe_split(line, ": ", 1)
            elif line.startswith("User-Agent:"):
                http_entry["user_agent"] = safe_split(line, ": ", 1)
            elif line == "-" * 50:
                if http_entry.get("method") == "GET":
                    http_data.append(http_entry)

    # Write HTTP Server Logs to CSV
    if http_data:
        with open(http_csv, 'w', newline='') as csvfile:
            fieldnames = ["time", "source_ip", "source_port", "method", "path", "response_code", "response_size", "host", "user_agent"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(http_data)

def parse_ip_port(line):
    """
    Helper function to parse IP and port from log lines.
    """
    parts = line.split(", ")
    ip = safe_split(parts[0], ": ", 1)
    port = safe_split(parts[1], ": ", 1)
    return ip, port

def safe_split(line, delimiter, maxsplit):
    """
    Helper function to safely split a string and avoid index errors.
    """
    parts = line.split(delimiter, maxsplit)
    return parts[1] if len(parts) > 1 else ""

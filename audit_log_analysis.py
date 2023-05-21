import os
import sys
import datetime
import re
import time
from collections import Counter

# Use it like this for example: 
# python ldap_audit_log_analysis.py
# or like this:
# python ldap_audit_log_analysis.py 'example.log' 
# or like this:
# python ldap_audit_log_analysis.py 'example.log' -performance
#
# Calling just the python file defaults to analysing 'logfile.txt' in the script's folder.
#
# The -performance switch displays data on how long the script ran and how many lines it processed.
#
# As a general rule of thumb every ~500.000 line increases the runtime of the analysis by about
# 1.5 second, and the time it takes to analyze a logfile increases linearly with the number of lines. 
# (Tested on 5800X 8C16T 4.6 GHZ and 32 GB of RAM)
# 
# Examples:
# Total Runtime: 1.33 seconds
# Number of Processed Lines: 560.374
# Total Runtime: 55.97 seconds
# Number of Processed Lines: 22.414.880
# Total Runtime: 119.87 seconds
# Number of Processed Lines: 44.829.760

# Execution time thresholds for the summary
thresholds = [10, 50, 100, 200, 500, 1000, 2000, 5000, 10000]
# Set the threshold for the maximum number of lines allowed. 
# Memory usage grows with each parsed line, setting this is a good idea on machines with low amounts of RAM (below 16 GB).
line_threshold = 500000

def read_and_modify_log_file(file_path, modified_file_path):
    """
    Read the log file and modify its content by replacing '--' with new lines,
    then write the modified content to a new file.
    """
    with open(file_path, 'r') as file:
        content = file.read()
    modified_content = content.replace('--', '\n')
    with open(modified_file_path, 'w') as file:
        file.write(modified_content)


def parse_log_file(file_path):
    """
    Parse the modified log file and extract events with their attributes.
    """
    try:
        with open(file_path, 'r') as file:
            logfile = file.read()

        events = []
        current_event = {}

        lines = logfile.strip().split("\n")

        i = 0
        while i < len(lines):
            if lines[i] == "AuditV3":
                # Start of a new event
                current_event = {}
                current_event["timestamp"] = lines[i + 1]
                current_event["operation_type"] = lines[i + 2]
                i += 3
            else:
                # Attribute line within an event
                parts = lines[i].split(": ", 1)
                if len(parts) == 2:
                    key, value = parts
                    if key in current_event:
                        # Attribute already exists, so convert it to a list if necessary
                        if isinstance(current_event[key], list):
                            current_event[key].append(value)
                        else:
                            current_event[key] = [current_event[key], value]
                    else:
                        # New attribute
                        current_event[key] = value
                i += 1

            if i == len(lines) or lines[i] == "AuditV3":
                # Calculate the execution time for the current event
                timestamp = datetime.datetime.strptime(current_event["timestamp"], "%Y-%m-%d-%H:%M:%S.%f%z")
                received = datetime.datetime.strptime(current_event["received"], "%Y-%m-%d-%H:%M:%S.%f%z")
                execution_time = (received - timestamp).total_seconds() * 1000
                current_event["ExecutionTime"] = int(abs(execution_time))
                events.append(current_event)

        return events
    except IOError as e:
        print(f"Error reading file: {e}")
        return []


def calculate_average_execution_time(events):
    """
    Calculate the average execution time per operation type and the overall average execution time.
    """
    operation_type_counts = {}
    execution_time_sums = {}
    total_execution_time = 0
    total_operations = 0

    for event in events:
        operation_type = event["operation_type"]
        execution_time = event["ExecutionTime"]

        if operation_type in operation_type_counts:
            operation_type_counts[operation_type] += 1
            execution_time_sums[operation_type] += execution_time
        else:
            operation_type_counts[operation_type] = 1
            execution_time_sums[operation_type] = execution_time

        total_execution_time += execution_time
        total_operations += 1

    average_execution_times = {}
    for operation_type, count in operation_type_counts.items():
        average_execution_time = execution_time_sums[operation_type] / count
        average_execution_times[operation_type] = int(average_execution_time)

    overall_average_execution_time = int(total_execution_time / total_operations)

    return average_execution_times, operation_type_counts, overall_average_execution_time


def get_events_with_highest_execution_times(events, how_many_events_to_return):
    """
    Get the events with the highest execution times.
    """
    sorted_events = sorted(events, key=lambda x: x['ExecutionTime'], reverse=True)
    top_events = sorted_events[:how_many_events_to_return]

    return top_events


def extract_filter_attributes(events):
    """
    Extract filter attributes and count their occurrences.
    """
    attribute_counts = {}

    for event in events:
        if 'filter' in event:
            filter_str = event['filter']
            attributes = re.findall(r'\((\w+)=', filter_str)
            for attribute in attributes:
                if attribute in attribute_counts:
                    attribute_counts[attribute] += 1
                else:
                    attribute_counts[attribute] = 1

    sorted_attributes = sorted(attribute_counts.items(), key=lambda x: x[1], reverse=True)

    return sorted_attributes


def extract_client_ips(events):
    """
    Extract client IPs from events.
    """
    client_ips = []

    for event in events:
        if 'client' in event:
            client_ip = re.findall(r'(\d+\.\d+\.\d+\.\d+)', event['client'])
            if client_ip:
                client_ips.append(client_ip[0])

    return client_ips


def extract_client_ip_ports(events):
    """
    Extract client IPs and ports from events.
    """
    client_ip_ports = []

    for event in events:
        if 'client' in event:
            client_ip_port = re.findall(r'(\d+\.\d+\.\d+\.\d+:\d+)', event['client'])
            if client_ip_port:
                client_ip_ports.append(client_ip_port[0])

    return client_ip_ports


def calculate_client_ip_counts(client_ips, how_many_clients_to_return):
    """
    Calculate the counts of client IPs and return the top clients with the highest number of events.
    """
    client_ip_counts = Counter(client_ips)
    top_clients = client_ip_counts.most_common(how_many_clients_to_return)

    return top_clients


def calculate_client_ip_port_counts(client_ip_ports, how_many_clients_to_return):
    """
    Calculate the counts of client IPs and ports and return the top clients with the highest number of events.
    """
    client_ip_port_counts = Counter(client_ip_ports)
    top_clients = client_ip_port_counts.most_common(how_many_clients_to_return)

    return top_clients


def calculate_execution_time_distribution(events, thresholds):
    """
    Calculate the distribution of execution times for different operation types based on thresholds.
    """
    operation_type_distribution = {}

    for event in events:
        operation_type = event["operation_type"]
        execution_time = event["ExecutionTime"]

        if operation_type not in operation_type_distribution:
            operation_type_distribution[operation_type] = {threshold: 0 for threshold in thresholds}

        for threshold in thresholds:
            if execution_time <= threshold:
                operation_type_distribution[operation_type][threshold] += 1
                break

    return operation_type_distribution


def print_summary(title, items):
    """
    Print a summary with a given title and items.
    """
    print(title)
    for item in items:
        print(f"{item[0]}: {item[1]}")
    print()


def print_execution_time_distribution(execution_time_distribution):
    """
    Print the execution time distribution in a formatted table.
    """
    headers = ["Operation Type"] + [f"{threshold} ms" for threshold in thresholds]
    row_format = "{:<20}" + "{:<10}" * len(headers[1:])

    print("Execution Time Distribution:")
    print(row_format.format(*headers))
    print("-" * (20 + 10 * len(headers)))

    for operation_type, counts in execution_time_distribution.items():
        counts_str = [str(counts.get(threshold, 0)) for threshold in thresholds]
        print(row_format.format(operation_type, *counts_str))
    print()


def wait_for_enter():
    """
    Wait for the user to press Enter before exiting the program.
    """
    input("Press Enter to exit...")


def main():
    """
    Main function that orchestrates the log file analysis.
    """
    # Get the path of the Python script
    script_path = os.path.abspath(__file__)
    # Get the directory path of the script
    script_dir = os.path.dirname(script_path)

    if len(sys.argv) < 2:
        log_file = "logfile.txt"
        file_path = os.path.join(script_dir, log_file)
        if not os.path.isfile(file_path):
            print("No argument given, default logfile is missing!")
            wait_for_enter()
            return
    else:
        log_file = sys.argv[1]
        file_path = os.path.join(script_dir, log_file)

    modified_file_path = os.path.join(script_dir, f"modified_{log_file}")

    # Start timing the script execution
    start_time = time.time()

    # Read and modify the log file
    read_and_modify_log_file(file_path, modified_file_path)

    # Parse the log file and extract events
    events = parse_log_file(modified_file_path)

    # Calculate the number of processed lines
    num_lines = sum(1 for line in open(modified_file_path))
    # Calculate the number of processed lines in the original file
    num_lines_original = sum(1 for line in open(file_path))

    if num_lines_original > line_threshold:
        print("File length exceeds the set threshold. Please divide the file into smaller chunks.")
        print("This is required because the amount of memory needed to work with files this big is too much.")
        wait_for_enter()
        return
    
    if len(events) == 0:
        print("No events found in the log file.")
        wait_for_enter()
        return

    # Calculate average execution times
    average_execution_times, operation_type_counts, overall_average_execution_time = calculate_average_execution_time(
        events
    )

    # Print average execution times
    print("--------------------------------------------------")
    print_summary("Average Execution Times per Operation Type:", average_execution_times.items())
    # Print total operation counts
    print("--------------------------------------------------")
    print_summary("Total Operation Counts per Operation Type:", operation_type_counts.items())
    # Print overall average execution time
    print("--------------------------------------------------")
    print(f"Overall Average Execution Time: {overall_average_execution_time} ms\n")

    # Get events with the highest execution times
    top_events = get_events_with_highest_execution_times(events, 5)
    # Print events with the highest execution times
    print("--------------------------------------------------")
    print_summary(
        "Events with Highest Execution Times:",
        [(event["operation_type"], event["ExecutionTime"]) for event in top_events],
    )
    for event in top_events:
        print("--------------------")
        for key, value in event.items():
            print(f"{key}: {value}")

    # Extract and count filter attributes
    sorted_attributes = extract_filter_attributes(events)
    # Print filter attributes and their occurrences
    print("--------------------------------------------------")
    print_summary("Filter Attributes and Occurrences:", sorted_attributes)

    # Extract client IPs
    client_ips = extract_client_ips(events)
    # Calculate client IP counts
    top_client_ips = calculate_client_ip_counts(client_ips, 5)
    # Print client IPs with the highest number of events
    print("--------------------------------------------------")
    print_summary("Top Client IPs:", top_client_ips)

    # Extract client IPs and ports
    client_ip_ports = extract_client_ip_ports(events)
    # Calculate client IP and port counts
    top_client_ip_ports = calculate_client_ip_port_counts(client_ip_ports, 5)
    # Print client IPs and ports with the highest number of events
    print("--------------------------------------------------")
    print_summary("Top Client IPs with Ports:", top_client_ip_ports)

    # Calculate execution time distribution
    execution_time_distribution = calculate_execution_time_distribution(events, thresholds)
    # Print execution time distribution
    print("--------------------------------------------------")
    print_execution_time_distribution(execution_time_distribution)

    # End timing the script execution
    end_time = time.time()
    total_runtime = end_time - start_time

    # Check if the '-performance' argument is used
    if "-performance" in sys.argv:
        print("--------------------------------------------------")
        print(f"Total Runtime: {total_runtime:.2f} seconds")
        print(f"Number of Processed Lines: {num_lines}")

    # Wait for user input before exiting
    wait_for_enter()


if __name__ == "__main__":
    main()

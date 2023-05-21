import os
import datetime
import re

# Execution time thresholds for the summary
thresholds = [10, 50, 100, 200, 500, 1000, 2000, 5000, 10000]
# Get the path of the Python script
script_path = os.path.abspath(__file__)
# Get the directory path of the script
script_dir = os.path.dirname(script_path)
# Construct the file path
file_path = os.path.join(script_dir, 'logfile.txt')
# Construct the file path
modified_file_path = os.path.join(script_dir, 'modified_logfile.txt')

def read_and_modify_log_file(file_path):
    # Read the log file and modify its content by replacing '--' with new lines
    with open(file_path, 'r') as file:
        content = file.read()
    modified_content = content.replace('--', '\n')
    with open(modified_file_path, 'w') as file:
        file.write(modified_content)

def parse_log_file(file_path):
    # Parse the modified log file and extract events with their attributes
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
            current_event["timestamp"] = lines[i+1]
            current_event["operation_type"] = lines[i+2]
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

def calculate_average_execution_time(events):
    # Calculate the average execution time per operation type and the overall average execution time
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
    # Get the events with the highest execution times
    sorted_events = sorted(events, key=lambda x: x['ExecutionTime'], reverse=True)
    top_events = sorted_events[:how_many_events_to_return]

    return top_events

def extract_filter_attributes(events):
    # Extract filter attributes and count their occurrences
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

def print_summary(title, items):
    # Print a summary with a given title and items
    print(title)
    for item in items:
        print(f"{item[0]}: {item[1]}")
    print()

def calculate_execution_time_distribution(events, thresholds):
    # Calculate the distribution of execution times for different operation types based on thresholds
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

def print_execution_time_distribution(execution_time_distribution):
    # Print the execution time distribution in a formatted table
    headers = ["Operation Type"] + [f"{threshold} ms" for threshold in thresholds]
    row_format = "{:<20}" + "{:<10}" * len(headers[1:])

    print("Execution Time Distribution:")
    print(row_format.format(*headers))
    print("-" * (20 + 10 * len(headers)))

    for operation_type, counts in execution_time_distribution.items():
        counts_str = [str(counts.get(threshold, 0)) for threshold in thresholds]
        print(row_format.format(operation_type, *counts_str))
    print()

def main():
    # Read and modify the log file
    read_and_modify_log_file(file_path)

    # Parse the log file and extract events
    events = parse_log_file(modified_file_path)

    # Calculate average execution times
    average_execution_times, operation_type_counts, overall_average_execution_time = calculate_average_execution_time(events)

    # Print average execution times per operation type
    print("--------------------------------------------------")
    print_summary("Average Execution Time per Operation Type:", average_execution_times.items())

    # Print number of occurrences per operation type
    print("--------------------------------------------------")
    print_summary("Number of Occurrences per Operation Type:", operation_type_counts.items())

    # Print overall average execution time
    print("--------------------------------------------------")
    print("Overall Average Execution Time:")
    print(f"All Operations: {overall_average_execution_time} ms\n")

    # Get the events with the highest execution times
    how_many_events_to_return = 1
    top_events = get_events_with_highest_execution_times(events, how_many_events_to_return)

    # Print the events with the highest execution times
    print("--------------------------------------------------")
    print(f"Top {how_many_events_to_return} Events with Highest Execution Times:")
    for event in top_events:
        print("--------------------")
        for key, value in event.items():
            print(f"{key}: {value}")

    # Extract and print filter attribute summary
    filter_attributes = extract_filter_attributes(events)
    print("--------------------------------------------------")
    print_summary("Filter Attribute Summary:", filter_attributes)

    # After parsing the log file and extracting the events
    execution_time_distribution = calculate_execution_time_distribution(events, thresholds)
    # After calculating the execution time distribution
    print("--------------------------------------------------")
    print_execution_time_distribution(execution_time_distribution)

if __name__ == '__main__':
    main()

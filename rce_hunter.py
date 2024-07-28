import requests
import threading
import argparse
import time
from queue import Queue
from colorama import init, Fore, Style
from rich.console import Console
from rich.table import Table
from datetime import datetime
import os

# Initialize colorama and rich
init()
console = Console()

# Logo and loading banner
LOGO = """
  _____   _____ ______   _    _             _            
 |  __ \ / ____|  ____| | |  | |           | |           
 | |__) | |    | |__    | |__| |_   _ _ __ | |_ ___ _ __ 
 |  _  /| |    |  __|   |  __  | | | | '_ \| __/ _ \ '__|
 | | \ \| |____| |____  | |  | | |_| | | | | ||  __/ |   
 |_|  \_\\_____|______| |_|  |_|\__,_|_| |_|\__\___|_|   
                                                         
"""
COPYRIGHT = """
Developed by NullC0d3
"""

# Function to read target URLs from a file
def load_urls(file_path):
    with open(file_path, 'r') as file:
        urls = file.readlines()
    return [url.strip() for url in urls]

# Function to load payloads from a file
def load_payloads(file_path):
    with open(file_path, 'r') as file:
        payloads = file.readlines()
    return [payload.strip() for payload in payloads]

# Function to convert payload string to dictionary
def convert_payload_to_dict(payload):
    payload_dict = {}
    for item in payload.split("&"):
        if "=" in item:
            key, value = item.split("=", 1)
            if key in payload_dict:
                if isinstance(payload_dict[key], list):
                    payload_dict[key].append(value)
                else:
                    payload_dict[key] = [payload_dict[key], value]
            else:
                payload_dict[key] = value
        else:
            raise ValueError(f"Invalid payload item: {item}")
    return payload_dict

# Lock for file operations to ensure thread safety
file_lock = threading.Lock()

# Function to log successful payloads and responses in table format
def log_successful_payload(url, payload, response, explanation, try_info, report_file):
    success_table = Table(show_header=True, header_style="bold magenta")
    success_table.add_column("URL", style="dim", width=30)
    success_table.add_column("Response Code", justify="right", width=15)
    success_table.add_column("Response", width=50)
    success_table.add_column("Payload", width=50)
    success_table.add_column("Time", width=25)
    success_table.add_column("Thread", width=10)
    success_table.add_column("Try", width=5)

    success_table.add_row(
        url, str(response.status_code), response.text[:50] + "...", payload,
        try_info['time'], str(try_info['thread_num']), str(try_info['try_num'])
    )

    with file_lock:
        with open(report_file, 'a') as file:
            file.write(f"{explanation}\n")
            file.write(f"{success_table}\n")
            file.write("-------------------------\n")

    console.print(Fore.GREEN + explanation + Style.RESET_ALL)
    console.print(success_table)
    console.print("-------------------------")

# Function to log invalid payloads and errors on the terminal
def log_invalid_payload(payload, error, try_info):
    invalid_table = Table(show_header=True, header_style="bold red")
    invalid_table.add_column("Invalid Payload", width=50)
    invalid_table.add_column("Error", width=50)
    invalid_table.add_column("Time", width=25)
    invalid_table.add_column("Thread", width=10)
    invalid_table.add_column("Try", width=5)

    invalid_table.add_row(
        payload, str(error), try_info['time'],
        str(try_info['thread_num']), str(try_info['try_num'])
    )

    console.print(Fore.RED + "Invalid payload encountered:" + Style.RESET_ALL)
    console.print(invalid_table)
    console.print("-------------------------")

# Function to send payloads to a single URL
def send_payloads(url_queue, payloads, thread_num, methods, delay, open_redirect_payloads, report_file):
    try_num = 1
    while not url_queue.empty():
        url = url_queue.get()
        try:
            for payload in payloads:
                for method in methods:
                    try_info = {
                        'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'thread_num': thread_num,
                        'try_num': try_num
                    }
                    try:
                        if "?" not in url.split('.php')[1]:
                            url_with_payload = url + "?" + payload
                        else:
                            url_with_payload = url + payload
                        
                        payload_dict = convert_payload_to_dict(payload)
                        response = requests.request(method, url_with_payload, data=payload_dict)

                        explanation = f"Payload succeeded on URL: {url}. The payload: {payload} caused the response code: {response.status_code} with response: {response.text[:50]}..."
                        log_successful_payload(url, payload, response, explanation, try_info, report_file)

                        if response.status_code in [403, 500, 502, 429, 404, 400, 405]:
                            for redirect_payload in open_redirect_payloads:
                                redirect_response = requests.get(url + redirect_payload)
                                if redirect_response.status_code == 200:
                                    explanation = f"Open redirect bypass succeeded on URL: {url}. The redirect payload: {redirect_payload} caused the response code: {redirect_response.status_code} with response: {redirect_response.text[:50]}..."
                                    log_successful_payload(url, redirect_payload, redirect_response, explanation, try_info, report_file)
                                    break
                    except ValueError as e:
                        log_invalid_payload(payload, e, try_info)
                    except requests.RequestException as e:
                        log_invalid_payload(payload, e, try_info)
                    try_num += 1
                    time.sleep(delay)
        finally:
            url_queue.task_done()

# Main function to parse arguments and start the process
def main():
    parser = argparse.ArgumentParser(description="RCE Hunter: A tool for testing RCE vulnerabilities.")
    parser.add_argument('-u', '--url', help='Single target URL')
    parser.add_argument('-f', '--file', help='File containing multiple target URLs')
    parser.add_argument('-p', '--payloads', required=True, help='File containing payloads')
    parser.add_argument('-o', '--open-redirect', required=True, help='File containing open redirect payloads')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-r', '--report', default='report.txt', help='Report file name (default: report.txt)')
    parser.add_argument('-d', '--delay', type=float, default=1.0, help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('-m', '--methods', default='auto', help='HTTP methods to use (default: auto)')
    parser.add_argument('-l', '--log', default='log.txt', help='Log file name (default: log.txt)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')

    args = parser.parse_args()

    # Display logo and loading banner
    console.print(LOGO, style="bold green")
    console.print(COPYRIGHT, style="bold cyan")
    console.print("Loading...", style="bold yellow")
    time.sleep(10)  # Sleep for 10 seconds to show the loading banner

    urls = []
    if args.url:
        urls.append(args.url)
    elif args.file:
        urls = load_urls(args.file)
    else:
        console.print("Error: Either a single URL or a file containing URLs must be provided.", style="bold red")
        return

    payloads = load_payloads(args.payloads)
    open_redirect_payloads = load_payloads(args.open_redirect)
    
    # Determine methods to use
    methods = args.methods.split(',') if args.methods != 'auto' else ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
    
    # Create a queue for URLs
    url_queue = Queue()
    for url in urls:
        url_queue.put(url)

    # Determine the number of threads to use
    num_threads = max(5, min(10, args.threads))

    # Create and start threads
    threads = []
    for thread_num in range(1, num_threads + 1):
        thread = threading.Thread(target=send_payloads, args=(url_queue, payloads, thread_num, methods, args.delay, open_redirect_payloads, args.report))
        thread.start()
        threads.append(thread)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Ensure the queue is empty
    url_queue.join()

    console.print("Testing complete. Check the report and log files for details.", style="bold green")

if __name__ == "__main__":
    main()

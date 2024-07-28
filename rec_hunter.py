#!/usr/bin/env python3

"""
RCE Hunter
Developed by NullC0d3

Description:
This script tests payloads against URLs. It supports multithreading and provides options for single target and multiple targets from a file.
"""

import requests
import threading
from queue import Queue
from colorama import init, Fore, Style
from tabulate import tabulate
from datetime import datetime
import argparse
import time
import re

# Initialize colorama
init()

# Logo and Copy Right
def print_header():
    print(r"""
  _____   _____ ______   _    _             _            
 |  __ \ / ____|  ____| | |  | |           | |           
 | |__) | |    | |__    | |__| |_   _ _ __ | |_ ___ _ __ 
 |  _  /| |    |  __|   |  __  | | | | '_ \| __/ _ \ '__|
 | | \ \| |____| |____  | |  | | |_| | | | | ||  __/ |   
 |_|  \_\\_____|______| |_|  |_|\__,_|_| |_|\__\___|_|   
                                                         
Developed by NullC0d3
---------------------------------------------------------
""")
    print(Fore.YELLOW + "Loading..." + Style.RESET_ALL)
    time.sleep(10)  # Sleep for 10 seconds to show the loading banner

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

# Function to load open redirect payloads from a file
def load_open_redirect_payloads(file_path):
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

# Function to ensure URL ends with `?` after `.php` if not already present
def ensure_php_extension(url):
    if re.search(r'\.php$', url) and not re.search(r'\.php\?', url):
        return url + '?'
    return url

# Lock for file operations to ensure thread safety
file_lock = threading.Lock()

# Function to log successful payloads and responses in table format
def log_successful_payload(url, payload, response, explanation, try_info):
    success_table = [
        ["URL", url],
        ["Response Code", response.status_code],
        ["Response", response.text[:50] + '...'],
        ["Payload", payload],
        ["Time", try_info['time']],
        ["Thread", try_info['thread_num']],
        ["Try", try_info['try_num']]
    ]
    
    with file_lock:
        with open('successful_payloads.txt', 'a') as file:
            file.write(f"{explanation}\n")
            file.write(f"{tabulate(success_table, tablefmt='grid')}\n")
            file.write("-------------------------\n")
    
    print(Fore.GREEN + explanation + Style.RESET_ALL)
    print(tabulate(success_table, tablefmt='grid'))
    print("-------------------------")

    # Log PoC
    with file_lock:
        with open('POC.txt', 'a') as poc_file:
            poc_file.write("---------------------------------------------------------\n")
            poc_file.write("Proof of Concept (PoC):\n")
            poc_file.write(f"URL: {url}\n")
            poc_file.write(f"Payload: {payload}\n")
            poc_file.write(f"Response Code: {response.status_code}\n")
            poc_file.write(f"Response:\n{response.text}\n")
            poc_file.write(f"Time: {try_info['time']}\n")
            poc_file.write(f"Thread: {try_info['thread_num']}\n")
            poc_file.write(f"Try: {try_info['try_num']}\n")
            poc_file.write("---------------------------------------------------------\n")

# Function to log invalid payloads and errors on the terminal
def log_invalid_payload(payload, error, try_info):
    invalid_table = [
        ["Invalid Payload", payload],
        ["Error", str(error)],
        ["Time", try_info['time']],
        ["Thread", try_info['thread_num']],
        ["Try", try_info['try_num']]
    ]
    
    print(Fore.RED + "Invalid payload encountered:" + Style.RESET_ALL)
    print(tabulate(invalid_table, tablefmt='grid'))
    print("-------------------------")

# Function to handle specific status codes with open redirect payloads
def handle_open_redirects(url, response_code, open_redirect_payloads):
    for redirect_payload in open_redirect_payloads:
        redirect_url = url + redirect_payload
        try:
            response = requests.get(redirect_url)
            if response.status_code == 200:
                return redirect_url, response, True
        except requests.RequestException:
            continue
    return None, None, False

# Function to send payloads to a single URL
def send_payloads(url_queue, payload_queue, open_redirect_payloads, thread_num):
    try_num = 1
    while not url_queue.empty():
        url = url_queue.get()
        url = ensure_php_extension(url)
        try:
            while not payload_queue.empty():
                payload = payload_queue.get()
                try_info = {
                    'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'thread_num': thread_num,
                    'try_num': try_num
                }
                try:
                    payload_dict = convert_payload_to_dict(payload)
                    response = requests.post(url, data=payload_dict)
                    explanation = f"Payload succeeded on URL: {url}. The payload: {payload} caused the response code: {response.status_code} with response: {response.text[:50]}..."
                    log_successful_payload(url, payload, response, explanation, try_info)
                    
                    # Handle specific status codes with open redirects
                    if response.status_code in [403, 500, 502, 429, 404, 400, 405]:
                        redirect_url, redirect_response, bypassed = handle_open_redirects(url, response.status_code, open_redirect_payloads)
                        if bypassed:
                            explanation = f"Open redirect bypass succeeded on URL: {redirect_url}. The payload: {payload} caused the response code: {redirect_response.status_code} with response: {redirect_response.text[:50]}..."
                            log_successful_payload(redirect_url, payload, redirect_response, explanation, try_info)
                        else:
                            explanation = f"Open redirect bypass failed for URL: {url}. The payload: {payload} did not bypass the response code: {response.status_code}"
                            log_successful_payload(url, payload, response, explanation, try_info)
                
                except ValueError as e:
                    log_invalid_payload(payload, e, try_info)
                except requests.RequestException as e:
                    log_invalid_payload(payload, e, try_info)
                try_num += 1
                payload_queue.task_done()
                time.sleep(4)  # Sleep for 4 seconds to slow down the scrolling
        finally:
            url_queue.task_done()

def main():
    parser = argparse.ArgumentParser(description="RCE Hunter by NullC0d3")
    parser.add_argument('-u', '--url', type=str, help='Single target URL')
    parser.add_argument('-f', '--file', type=str, help='File containing multiple target URLs')
    parser.add_argument('-p', '--payloads', type=str, required=True, help='File containing payloads')
    parser.add_argument('-o', '--open-redirect', type=str, required=True, help='File containing open redirect payloads')
    args = parser.parse_args()

    print_header()

    if args.url:
        urls = [args.url]
    elif args.file:
        urls = load_urls(args.file)
    else:
        parser.print_help()
        exit(1)

    payloads = load_payloads(args.payloads)
    open_redirect_payloads = load_open_redirect_payloads(args.open_redirect)

    url_queue = Queue()
    payload_queue = Queue()

    for url in urls:
        url_queue.put(url)

    for payload in payloads:
        payload_queue.put(payload)

    num_threads = max(5, min(10, len(urls)))

    threads = []
    for thread_num in range(1, num_threads + 1):
        thread = threading.Thread(target=send_payloads, args=(url_queue, payload_queue, open_redirect_payloads, thread_num))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    url_queue.join()
    payload_queue.join()

if __name__ == "__main__":
    main()

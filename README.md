# RCE Hunter

  _____   _____ ______   _    _             _            
 |  __ \ / ____|  ____| | |  | |           | |           
 | |__) | |    | |__    | |__| |_   _ _ __ | |_ ___ _ __ 
 |  _  /| |    |  __|   |  __  | | | | '_ \| __/ _ \ '__|
 | | \ \| |____| |____  | |  | | |_| | | | | ||  __/ |   
 |_|  \_\\_____|______| |_|  |_|\__,_|_| |_|\__\___|_|   
                                                         




Developed by NullC0d3

RCE Hunter is a Python-based tool developed by NullC0d3 for automated testing of Remote Code Execution (RCE) vulnerabilities. It supports multithreading, payload management, and includes open redirect handling for bypassing certain HTTP status codes.

## Features
- Professional PoC generation for bug bounty programs
- Multithreaded payload testing
- Open redirect payload handling
- Customizable payloads and target URLs


## Requirements
- Python 3.9+
- Docker (optional)

## Installation
### Using Docker
1. Build the Docker image:
    ```sh
    docker build -t rce-hunter .
    ```
2. Run the container:
    ```sh
    docker run --rm -v $(pwd):/app rce-hunter -u <URL> -p <PAYLOAD_FILE> -o <OPEN_REDIRECT_PAYLOAD_FILE>
    ```

### Manual Setup
1. Clone the repository:
    ```sh
    git clone https://github.com/Z3r0H0ur666/RCE-Hunter.git
    cd RCE-Hunter
    ```
2. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```
3. Run the script:
    ```sh
    python myscript.py -u <URL> -p <PAYLOAD_FILE> -o <OPEN_REDIRECT_PAYLOAD_FILE>
    ```

## Usage
### Command Line Options
- `-u` / `--url` : Single target URL
- `-f` / `--file` : File containing multiple target URLs
- `-p` / `--payloads` : File containing payloads (required)
- `-o` / `--open-redirect` : File containing open redirect payloads (required)
- `-t` / `--threads` : Number of threads (default: 10)
- `-r` / `--report` : Report file name (default: report.txt)
- `-d` / `--delay` : Delay between requests in seconds (default: 1.0)
- `-m` / `--methods` : HTTP methods to use (default: auto, which uses GET, POST, PUT, DELETE, PATCH)
- `-l` / `--log` : Log file name (default: log.txt)
- `-v` / `--verbose` : Enable verbose mode

  ![Screenshot 2024-07-29 103900](https://github.com/user-attachments/assets/79466b04-7918-4143-a246-930a3a88365e)


### Example
```sh
python myscript.py -u http://example.com/vulnerable.php -p payloads/commandexc.txt -o payloads/openredirect.txt

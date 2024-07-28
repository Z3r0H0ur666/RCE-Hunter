# RCE Hunter

  _____   _____ ______   _    _             _            
 |  __ \ / ____|  ____| | |  | |           | |           
 | |__) | |    | |__    | |__| |_   _ _ __ | |_ ___ _ __ 
 |  _  /| |    |  __|   |  __  | | | | '_ \| __/ _ \ '__|
 | | \ \| |____| |____  | |  | | |_| | | | | ||  __/ |   
 |_|  \_\\_____|______| |_|  |_|\__,_|_| |_|\__\___|_|   
                                                         




RCE Hunter is a Python-based tool developed by NullC0d3 for automated testing of Remote Code Execution (RCE) vulnerabilities. It supports multithreading, payload management, and includes open redirect handling for bypassing certain HTTP status codes.

## Features
- Multithreaded payload testing
- Open redirect payload handling
- Customizable payloads and target URLs
- Professional PoC generation for bug bounty programs

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
    git clone https://github.com/yourusername/RCE-Hunter.git
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

### Example
```sh
python myscript.py -u http://example.com/vulnerable.php -p payloads/commandexc.txt -o payloads/openredirect.txt

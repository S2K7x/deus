import requests
import argparse
import re
import asyncio
import aiohttp
import time
import signal
from urllib.parse import urlencode
from pathlib import Path
from colorama import Fore, Style, init  # For colored output

# Initialize colorama for colored output
init(autoreset=True)

# Define common payloads for vulnerabilities (extendable with --custom-payloads)
PAYLOADS = {
    "SQLi": ["'", "\"", " OR 1=1 --", "' OR '1'='1", "admin' --"],
    "XSS": ["<script>alert(1)</script>", "\";alert(1);//", "<img src=x onerror=alert(1)>"],
    "SSRF": ["http://169.254.169.254/latest/meta-data/", "file:///etc/passwd", "http://localhost:80"],
    "IDOR": ["../", "/admin", "/user?role=admin", "/user?id=1", "/user?id=2"]
}

# Error patterns for each vulnerability type
ERROR_PATTERNS = {
    "SQLi": r"(syntax error|unclosed quotation mark|incorrect syntax near|SQL syntax)",
    "XSS": r"<script>alert|onerror=alert",
    "SSRF": r"(internal server error|connection refused|localhost|169\.254\.169\.254)",
    "IDOR": r"(access denied|not authorized|permission denied)"
}

async def analyze_response(response, payload, vuln_type, response_time, save_responses, verbose):
    """
    Analyze HTTP response for signs of vulnerability, such as error messages or unusual response times.
    """
    response_text = await response.text()  # Retrieve response text asynchronously

    # Check if vuln_type has an error pattern defined
    if response.status >= 400 or (vuln_type in ERROR_PATTERNS and re.search(ERROR_PATTERNS[vuln_type], response_text, re.IGNORECASE)):
        print(f"{Fore.RED}[!] Possible {vuln_type} vulnerability detected!")
        print(f"Payload: {payload}")
        print(f"Status Code: {response.status}")
        print(f"Response Time: {response_time:.2f}s")
        print(f"Response Snippet: {response_text[:200]}\n")

        # Save response if enabled
        if save_responses:
            filename = f"{vuln_type}_response_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write(response_text)
            print(f"{Fore.GREEN}[+] Saved full response to {filename}")

    elif verbose:
        print(f"{Fore.YELLOW}[DEBUG] Status Code: {response.status}, Response Time: {response_time:.2f}s")


async def send_fuzzed_request(session, url, method, headers, data, param_type, payload, vuln_type, save_responses, verbose):
    """
    Sends a single fuzzed request with the specified payload and logs any anomalies.
    """
    if param_type == "query":
        fuzzed_params = {key: payload for key in data.keys()}
        fuzzed_url = f"{url}?{urlencode(fuzzed_params)}"
        
        start_time = time.monotonic()  # Start timing
        async with session.request(method, fuzzed_url, headers=headers) as response:
            response_time = time.monotonic() - start_time  # Calculate elapsed time
            await analyze_response(response, payload, vuln_type, response_time, save_responses, verbose)
    
    elif param_type == "json":
        fuzzed_data = {key: payload for key in data.keys()}
        
        start_time = time.monotonic()
        async with session.request(method, url, headers=headers, json=fuzzed_data) as response:
            response_time = time.monotonic() - start_time
            await analyze_response(response, payload, vuln_type, response_time, save_responses, verbose)
    
    else:
        print(f"{Fore.RED}[!] Invalid parameter type specified.")

async def fuzz_endpoint(url, method, headers, data, param_type, rate_limit, save_responses, verbose):
    """
    Main fuzzing function that sends asynchronous requests with various payloads.
    """
    print(f"{Fore.CYAN}[*] Fuzzing {url} with method {method}")

    # Initialize asynchronous session
    async with aiohttp.ClientSession() as session:
        for vuln_type, payloads in PAYLOADS.items():
            tasks = []
            for payload in payloads:
                task = send_fuzzed_request(session, url, method, headers, data, param_type, payload, vuln_type, save_responses, verbose)
                tasks.append(task)
                # Rate limit requests
                if len(tasks) >= rate_limit:
                    await asyncio.gather(*tasks)
                    tasks.clear()
            # Await remaining tasks
            if tasks:
                await asyncio.gather(*tasks)

def load_custom_payloads(file_path):
    """
    Load custom payloads from a file and add them to the PAYLOADS dictionary.
    """
    custom_payloads = Path(file_path).read_text().splitlines()
    PAYLOADS["Custom"] = custom_payloads
    print(f"{Fore.GREEN}[+] Loaded {len(custom_payloads)} custom payloads from {file_path}")

def main():
    parser = argparse.ArgumentParser(description="Enhanced Parameter-Based Endpoint Fuzzer")
    parser.add_argument("url", help="URL to target for fuzzing (e.g., http://example.com/api/test)")
    parser.add_argument("-m", "--method", choices=["GET", "POST"], default="GET", help="HTTP method to use")
    parser.add_argument("-t", "--type", choices=["query", "json"], default="query", help="Parameter type (query or json)")
    parser.add_argument("-d", "--data", type=str, help="Parameter data as key=value pairs (e.g., 'id=1&name=test')")
    parser.add_argument("--headers", type=str, help="Custom headers as key=value pairs (e.g., 'Authorization=Bearer token')")
    parser.add_argument("--custom-payloads", type=str, help="Path to a custom payloads file")
    parser.add_argument("--rate-limit", type=int, default=5, help="Rate limit requests per second")
    parser.add_argument("--save-responses", action="store_true", help="Save full responses for analysis")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose mode for debugging")

    args = parser.parse_args()

    # Parse data and headers
    data = dict(param.split('=') for param in args.data.split('&')) if args.data else {}
    headers = dict(header.split('=') for header in args.headers.split('&')) if args.headers else {}

    # Load custom payloads if specified
    if args.custom_payloads:
        load_custom_payloads(args.custom_payloads)

    # Register signal handler for graceful exit on Ctrl+C
    signal.signal(signal.SIGINT, lambda sig, frame: print(f"\n{Fore.RED}[!] Fuzzing aborted by user."))

    # Run the asynchronous fuzzing process
    try:
        asyncio.run(fuzz_endpoint(args.url, args.method, headers, data, args.type, args.rate_limit, args.save_responses, args.verbose))
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Fuzzing interrupted.")

if __name__ == "__main__":
    main()

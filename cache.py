import requests
import uuid
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
from termcolor import colored
import re
import logging

logging.basicConfig(
    filename='request_logs.txt', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_request(url, headers, response):
    logging.info(f"Request sent to URL: {url}")
    logging.info(f"Request headers: {headers}")
    logging.info(f"Response status code: {response.status_code}")
    logging.info(f"Response headers: {response.headers}")
    logging.info("-----")

def check_href_reflection(html_content, domain):
    href_pattern = re.compile(r'href=["\'](.*' + re.escape(domain) + r'.*?)["\']', re.IGNORECASE)
    matches = href_pattern.findall(html_content)
    if matches:
        print(colored(f"[+] Vulnerability found! Domain '{domain}' reflected in href attribute(s): {matches}", 'green'))
        return True
    return False

def check_header_reflection(headers, domain):
    reflected_headers = []
    for header, value in headers.items():
        if domain in value:
            reflected_headers.append((header, value))
    if reflected_headers:
        print(colored(f"[!] Warning! Domain '{domain}' reflected in the following response header(s):", 'yellow'))
        print(colored(f"[+] Headers used in the original request: {headers}", 'yellow'))
        for header, value in reflected_headers:
            print(colored(f"[!] {header}: {value}", 'yellow'))
        return True
    return False

def check_vulnerability(url, headers, domain):
    try:
        unique_id = str(uuid.uuid4())
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        query_params[unique_id] = "051"
        encoded_query = urlencode(query_params, doseq=True)
        modified_url = urlunparse(parsed_url._replace(query=encoded_query))

        response = requests.get(modified_url, headers=headers, allow_redirects=False)
        log_request(modified_url, headers, response)

        if 'Location' in response.headers and domain in response.headers['Location']:
            second_response = requests.get(modified_url, allow_redirects=False)
            print(colored(f"[+] Domain '{domain}' First Reflection Location ", 'green'))
            if 'Location' in second_response.headers and domain in second_response.headers['Location']:
                print(colored(f"[+] Domain '{domain}' still reflected in Location header after second request without headers to {modified_url}", 'green'))
                print(colored(f"[+] Headers used in the original request: {headers}", 'yellow'))
            else:
                print(f"[-] No further reflection found in second request without headers to {modified_url}")
        else:
            print(f"[-] No vulnerability detected for {modified_url}")

        if response.status_code == 200 and "text/html" in response.headers.get('Content-Type', ''):
            if check_href_reflection(response.text, domain):
                print(colored("[!] Warning: Reflection detected in href tags. Investigate further!", 'yellow'))
        else:
            print(f"[-] No vulnerability detected for {modified_url}")

        if check_header_reflection(response.headers, domain):
            print(colored("[!] Warning: Reflection detected in response headers. Investigate further!", 'yellow'))

    except requests.exceptions.RequestException as e:
        print(f"[!] Error requesting {url}: {e}")

def load_urls():
    with open('urls.txt', 'r') as file:
        urls = [line.strip() for line in file]
    return urls

def load_headers():
    headers = []
    with open('headers.txt', 'r') as file:
        for line in file:
            header_name = line.strip()
            if header_name:
                headers.append(header_name)
    return headers

def main():
    urls = load_urls()
    header_names = load_headers()
    domain = 'itaik.com'
    header_chunks = [header_names[i:i + 10] for i in range(0, len(header_names), 10)]
    for url in urls:
        for header_chunk in header_chunks:
            headers = {header: domain for header in header_chunk}
            check_vulnerability(url, headers, domain)

if __name__ == "__main__":
    main()

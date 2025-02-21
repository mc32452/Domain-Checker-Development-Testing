# Domain Checker

## Overview
Domain Checker is an asynchronous domain analysis tool designed to perform a comprehensive set of domain checks. 
It provides multiple functionalities including HTTP status checks, DNS lookups, WHOIS queries, TLS/SSL certificate validations, subdomain discovery via certificate transparency logs (crt.sh), and an advanced mode that combines all checks into one report. 
The tool leverages Python's asynchronous programming features (using `asyncio` and `aiohttp`) to handle multiple domains concurrently, ensuring efficient and speedy execution.

## Features
- **HTTP Check:**  
  Retrieve HTTP status codes, response snippets, response times, and redirection details for a given domain.
  
- **DNS Lookup:**  
  Perform DNS record lookups for various types (A, AAAA, CNAME, MX, NS, SOA, TXT) and generate recursive DNS resolution chains to trace CNAME and A/AAAA records.

- **WHOIS Check:**  
  Obtain domain registration details such as registrar, creation and expiration dates, and name servers, with built-in caching to minimize repeated lookups.

- **TLS/SSL Certificate Check:**  
  Connect via SSL to retrieve certificate details, including the expiry date and the number of days until the certificate expires.

- **Subdomain Finder:**  
  Query crt.sh for subdomains associated with a domain, then perform HTTP checks on the discovered subdomains to determine their availability.

- **Advanced Check:**  
  Combine HTTP, DNS, WHOIS, TLS/SSL certificate, and wildcard DNS checks into one comprehensive report for a list of domains.

## Dependencies
The program relies on several Python libraries. Ensure that you have Python 3.7 or later installed, then install the following packages:

- [asyncio](https://docs.python.org/3/library/asyncio.html) (built-in)
- [aiohttp](https://docs.aiohttp.org/)
- [dnspython](https://www.dnspython.org/) (specifically `dns.asyncresolver`)
- [csv](https://docs.python.org/3/library/csv.html) (built-in)
- [io](https://docs.python.org/3/library/io.html) (built-in)
- [time](https://docs.python.org/3/library/time.html) (built-in)
- [streamlit](https://streamlit.io/)
- [pandas](https://pandas.pydata.org/)
- [python-whois](https://pypi.org/project/python-whois/)
- [ssl](https://docs.python.org/3/library/ssl.html) (built-in)
- [socket](https://docs.python.org/3/library/socket.html) (built-in)
- [datetime](https://docs.python.org/3/library/datetime.html) (built-in)
- [crtsh](https://pypi.org/project/crtsh/) (for subdomain discovery)
- [typing](https://docs.python.org/3/library/typing.html) (built-in)
```
```

## How It Works
The application is organized into several key modules that handle specific types of domain checks. Below is an overview of the core components:

### HTTP Checks
- **Key Functions:** `check_http_domain`, `run_http_checks`  
- **Description:**  
  - **`check_http_domain`:** Attempts to connect to a domain using HTTP/HTTPS. It supports retry logic and measures the response time. It also handles redirection by comparing normalized URLs.
  - **`run_http_checks`:** Manages multiple concurrent HTTP requests using an asyncio semaphore to limit concurrency. Progress is updated using Streamlit's progress bar.

### DNS Lookups
- **Key Functions:** `get_dns_record_for_domain`, `run_dns_checks`, `get_recursive_dns_chain`  
- **Description:**  
  - **`get_dns_record_for_domain`:** Uses `dns.asyncresolver` to retrieve DNS records (A, AAAA, MX, etc.) for a domain. It also checks for CNAME inheritance.
  - **`get_recursive_dns_chain`:** Builds a chain of DNS resolutions by following CNAME records and retrieving the final A/AAAA records.
  - **`run_dns_checks`:** Executes DNS queries concurrently for multiple domains and provides progress feedback.

### WHOIS Checks
- **Key Functions:** `get_whois_info`, `process_whois_domain`, `run_whois_checks`  
- **Description:**  
  - **`get_whois_info`:** Retrieves WHOIS information using the `python-whois` library. It includes retry logic and caching to prevent repeated queries.
  - **`process_whois_domain` & `run_whois_checks`:** Wrap the synchronous WHOIS lookup in asynchronous calls to enable concurrent processing of multiple domains.

### TLS/SSL Certificate Checks
- **Key Functions:** `get_certificate_info`, `process_certificate_check`, `run_certificate_checks`  
- **Description:**  
  - **`get_certificate_info`:** Establishes an SSL connection to extract certificate details such as the expiry date and calculates days until expiration.
  - **`process_certificate_check` & `run_certificate_checks`:** Enable asynchronous certificate checks across multiple domains.

### Subdomain Finder
- **Key Functions:** `check_subdomain_advanced`, `perform_http_checks`  
- **Description:**  
  - Uses the `crtshAPI` to search for subdomains associated with a given domain.
  - Performs HTTP checks on each discovered subdomain to determine if they are live (i.e., responding with HTTP status codes below 400 or through redirections).

### Advanced Check
- **Key Functions:** `process_all_in_one`, `run_all_in_one_checks`  
- **Description:**  
  - Combines all the checks (HTTP, DNS, WHOIS, TLS/SSL certificate, and wildcard DNS) into one comprehensive report.
  - Offers detailed insights including certificate status, DNS record details, WHOIS data, and HTTP performance metrics.

## Streamlit User Interface
The user interface is built using Streamlit and is divided into several tabs:
- **HTTP Check Tab:** Input domains and parameters to perform HTTP checks.
- **DNS Lookup Tab:** Enter domains, select DNS record types, and view DNS results along with recursive resolution chains.
- **WHOIS Check Tab:** Input domains to fetch WHOIS registration details.
- **TLS/SSL Certificate Check Tab:** Perform certificate checks to get expiry dates and days until expiry.
- **Subdomain Finder Tab:** Input a domain to find subdomains via crt.sh and check their availability.
- **Advanced Check Tab:** Combine multiple checks into a single comprehensive analysis.

Each tab provides forms for user input, displays results in formatted tables (using Pandas DataFrames), and offers options to download the results as CSV files.

## Detailed Code Documentation
The code is thoroughly documented with inline comments and detailed docstrings for each function. For example:

- **`get_whois_info(domain: str) -> Dict[str, Any]`:* 
  Retrieves WHOIS information for the specified domain, caches results to reduce redundant lookups, and includes error handling with retry logic.

- **`check_http_domain(...) -> Tuple[Any, ...]`:**  
  Handles HTTP requests with support for both HTTPS and HTTP protocols, retries on failure, and gathers details like status code, response snippet, and redirection history.

- **`get_dns_record_for_domain(...) -> Tuple[str, Dict[str, Union[List[str], str]]]`:**  
  Performs DNS record lookups for a domain using specified record types and manages exceptions such as timeouts or NXDOMAIN errors.

- **`get_certificate_info(domain: str) -> Tuple[Optional[str], Optional[int], str]`:**  
  Connects to the domain using an SSL context, retrieves the certificate, and calculates how many days remain until the certificate expires.

- **`process_all_in_one(...) -> Dict[str, Any]`:**  
  Aggregates results from HTTP, DNS, WHOIS, certificate, and wildcard DNS checks into a single dictionary for advanced reporting.

Each function is designed to be modular, making the code easy to maintain, extend, and understand.

## Contributing
Contributions, suggestions, and bug reports are welcome! To contribute:
1. Fork the repository.
2. Create a new feature branch.
3. Commit your changes with clear messages.
4. Open a pull request for review.




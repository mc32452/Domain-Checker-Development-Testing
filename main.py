import asyncio
import aiohttp
import dns.asyncresolver
import csv
import io
import time
import streamlit as st
import pandas as pd
import whois
from urllib.parse import urlparse
import ssl
import socket
import datetime
from crtsh import crtshAPI  # For Subdomain Finder
from typing import List, Tuple, Dict, Any, Optional, Callable, Union

# Define HTTP headers for requests
http_headers: Dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/90.0.4430.93 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5"
}

# Global cache for WHOIS lookups
WHOIS_CACHE: Dict[str, Dict[str, Any]] = {}

def get_whois_info(domain: str) -> Dict[str, Any]:
    """
    Retrieves WHOIS information for the specified domain.

    Args:
        domain (str): The domain to look up.

    Returns:
        Dict[str, Any]: A dictionary containing registrar, creation/expiration dates, name servers,
                        and any error message encountered.
    """
    global WHOIS_CACHE
    if domain in WHOIS_CACHE:
        return WHOIS_CACHE[domain]
    time.sleep(0.2)
    max_attempts: int = 3
    backoff_factor: float = 0.5
    for attempt in range(max_attempts):
        try:
            if attempt > 0:
                time.sleep(backoff_factor * (2 ** (attempt - 1)))
            w = whois.whois(domain)
            registrar = w.registrar if hasattr(w, 'registrar') else ""
            creation_date = w.creation_date
            expiration_date = w.expiration_date
            name_servers = w.name_servers if hasattr(w, 'name_servers') else ""
            if isinstance(name_servers, list):
                name_servers = ", ".join(name_servers)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            result: Dict[str, Any] = {
                "registrar": registrar,
                "creation_date": creation_date,
                "expiration_date": expiration_date,
                "name_servers": name_servers,
                "error": ""
            }
            WHOIS_CACHE[domain] = result
            return result
        except Exception as e:
            error_str = str(e)
            if "reset" in error_str.lower():
                error_str = "Connection reset error. Please try again later."
            if attempt == max_attempts - 1:
                result = {"registrar": "", "creation_date": "", "expiration_date": "", "name_servers": "", "error": error_str}
                WHOIS_CACHE[domain] = result
                return result

async def process_whois_domain(domain: str) -> Tuple[str, Any, Any, Any, str, str]:
    """
    Asynchronously retrieves WHOIS information for a given domain.

    Args:
        domain (str): The domain to process.

    Returns:
        Tuple containing the domain, registrar, creation date, expiration date, name servers, and any error.
    """
    info = await asyncio.to_thread(get_whois_info, domain)
    return (
        domain,
        info.get("registrar", ""),
        info.get("creation_date", ""),
        info.get("expiration_date", ""),
        info.get("name_servers", ""),
        info.get("error", "")
    )

async def run_whois_checks(domains: List[str]) -> List[Tuple[str, Any, Any, Any, str, str]]:
    """
    Runs WHOIS lookups for a list of domains asynchronously.

    Args:
        domains (List[str]): List of domains.

    Returns:
        List of tuples with WHOIS lookup results.
    """
    tasks = [process_whois_domain(domain) for domain in domains]
    results: List[Tuple[str, Any, Any, Any, str, str]] = []
    total = len(tasks)
    progress_bar = st.progress(0)
    for i, coro in enumerate(asyncio.as_completed(tasks), start=1):
        result = await coro
        results.append(result)
        progress_bar.progress(int((i / total) * 100))
    return results

async def check_http_domain(domain: str, timeout: int, retries: int, session: aiohttp.ClientSession, headers: Dict[str, str], semaphore: asyncio.Semaphore) -> Tuple[Any, ...]:
    """
    Checks the HTTP response for a given domain.

    Args:
        domain (str): The domain to check.
        timeout (int): Request timeout in seconds.
        retries (int): Number of retry attempts.
        session (aiohttp.ClientSession): The aiohttp session for making requests.
        headers (Dict[str, str]): HTTP headers.
        semaphore (asyncio.Semaphore): Semaphore to control concurrency.

    Returns:
        Tuple with domain, status code, response snippet, response time, attempts count,
        whether a response was received, redirect history, and if redirection occurred.
    """
    url = "http://" + domain if not domain.startswith(("http://", "https://")) else domain
    attempt = 0
    error_message = ""
    response_time: Optional[float] = None
    redirect_info = ""
    redirected = "No"
    start_time = time.perf_counter()

    def normalize_url(url_str: str) -> Tuple[str, str, str]:
        parsed = urlparse(url_str)
        netloc = parsed.netloc.lower().lstrip("www.")
        path = parsed.path.rstrip("/") or "/"
        return netloc, path, parsed.query

    while attempt < retries:
        attempt += 1
        try:
            async with semaphore:
                async with session.get(url, headers=headers, timeout=timeout) as response:
                    response_time = time.perf_counter() - start_time
                    status = response.status
                    text = await response.text()
                    snippet = text[:200]
                    if response.history:
                        redirects = [str(resp.url) for resp in response.history] + [str(response.url)]
                        redirect_info = " -> ".join(redirects)
                    else:
                        redirect_info = "No redirect"
                    if normalize_url(url) != normalize_url(str(response.url)):
                        redirected = "Yes"
                    return (
                        domain, status, snippet, round(response_time, 2),
                        attempt, "Yes", redirect_info, redirected
                    )
        except Exception as e:
            error_message = str(e)
            await asyncio.sleep(0.5)
    response_time = time.perf_counter() - start_time
    snippet = f"Error occurred: {error_message}"
    return (domain, None, snippet, round(response_time, 2), attempt, "No", "No redirect", "No")

async def run_http_checks(domains: List[str], timeout: int, concurrency: int, retries: int) -> List[Tuple[Any, ...]]:
    """
    Runs HTTP checks for a list of domains asynchronously.

    Args:
        domains (List[str]): List of domains.
        timeout (int): Timeout in seconds.
        concurrency (int): Maximum number of concurrent HTTP requests.
        retries (int): Number of retries per domain.

    Returns:
        List of tuples with HTTP check results.
    """
    results: List[Tuple[Any, ...]] = []
    semaphore = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        tasks = [check_http_domain(domain, timeout, retries, session, http_headers, semaphore) for domain in domains]
        progress_bar = st.progress(0)
        total = len(tasks)
        completed = 0
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            completed += 1
            progress_bar.progress(int((completed / total) * 100))
    return results

async def get_dns_record_for_domain(domain: str, record_types: List[str]) -> Tuple[str, Dict[str, Union[List[str], str]]]:
    """
    Performs DNS record lookups for the specified domain and record types.

    Args:
        domain (str): Domain to look up.
        record_types (List[str]): List of DNS record types (e.g., A, AAAA, MX).

    Returns:
        Tuple containing the domain and a dictionary of record types to their results.
    """
    if not domain or '.' not in domain:
        return domain, {rtype: "Invalid domain format" for rtype in record_types}
    records: Dict[str, Union[List[str], str]] = {}
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    cname_result: Optional[List[str]] = None
    try:
        cname_answer = await resolver.resolve(domain, "CNAME")
        cname_result = [rdata.to_text() for rdata in cname_answer]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        cname_result = None
    except Exception:
        cname_result = None

    for rtype in record_types:
        try:
            if rtype in ["A", "AAAA"]:
                if cname_result:
                    target = cname_result[0].rstrip('.')
                    answer = await resolver.resolve(target, rtype)
                    record_list = [rdata.to_text() for rdata in answer]
                    record_list = [f"{rec} (Inherited from {target})" for rec in record_list]
                else:
                    answer = await resolver.resolve(domain, rtype)
                    record_list = [rdata.to_text() for rdata in answer]
                records[rtype] = record_list if record_list else "No records found"
            elif rtype == "MX":
                answer = await resolver.resolve(domain, rtype)
                mx_records: List[str] = []
                for rdata in answer:
                    target = str(rdata.exchange).rstrip('.')
                    mx_cname: Optional[List[str]] = None
                    try:
                        mx_cname_answer = await resolver.resolve(target, "CNAME")
                        mx_cname = [rd.to_text() for rd in mx_cname_answer]
                    except Exception:
                        mx_cname = None
                    mx_str = f"Priority {rdata.preference}: {target}"
                    if mx_cname:
                        mx_str += " (Inherited from CNAME)"
                    mx_records.append(mx_str)
                records[rtype] = mx_records if mx_records else "No records found"
            else:
                answer = await resolver.resolve(domain, rtype)
                record_list = [rdata.to_text() for rdata in answer]
                records[rtype] = record_list if record_list else "No records found"
        except dns.resolver.NoAnswer:
            records[rtype] = "No records found"
        except dns.resolver.NXDOMAIN:
            records[rtype] = "Domain does not exist"
        except dns.resolver.Timeout:
            records[rtype] = "Lookup timed out"
        except Exception as e:
            records[rtype] = f"Error: {str(e)}"
    if cname_result and "CNAME" not in record_types:
        records["CNAME_Inheritance"] = "Inherited from CNAME"
    return domain, records

async def run_dns_checks(domains: List[str], record_types: List[str],
                         progress_callback: Optional[Callable[[int, int], None]]) -> Dict[str, Any]:
    """
    Runs DNS lookups for multiple domains asynchronously.

    Args:
        domains (List[str]): List of domains.
        record_types (List[str]): DNS record types to query.
        progress_callback (Optional[Callable[[int, int], None]]): Function to update progress.

    Returns:
        Dictionary mapping each domain to its DNS record results.
    """
    results: Dict[str, Any] = {}
    tasks = [get_dns_record_for_domain(domain, record_types) for domain in domains]
    total = len(tasks)
    completed = 0
    for task in asyncio.as_completed(tasks):
        domain, result = await task
        results[domain] = result
        completed += 1
        if progress_callback:
            progress_callback(completed, total)
    return results

def get_certificate_info(domain: str) -> Tuple[Optional[str], Optional[int], str]:
    """
    Retrieves TLS/SSL certificate information for the given domain.

    This function establishes an SSL connection with SNI support.
    If the certificate is obtained, the function returns its expiry date and the number of days until expiry.

    Args:
        domain (str): The domain to check.

    Returns:
        Tuple containing:
            - Certificate expiry date as a string (or None if error),
            - Days until expiry as an integer (or None if error),
            - Error message (empty string if no error).
    """
    try:
        context = ssl.create_default_context()
        # Removed CRL checking to avoid the CERTIFICATE_VERIFY_FAILED error.
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date_str = cert.get('notAfter')
                if not expiry_date_str:
                    return None, None, "Certificate does not have an expiration date"
                expiry_date = datetime.datetime.strptime(expiry_date_str, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                days_until_expiry = (expiry_date - now).days
                return expiry_date_str, days_until_expiry, ""
    except Exception as e:
        return None, None, str(e)

async def process_certificate_check(domain: str) -> Tuple[Optional[str], Optional[int], str]:
    """
    Asynchronously obtains TLS/SSL certificate information for a given domain.

    Args:
        domain (str): The domain to check.

    Returns:
        Tuple with certificate expiry date, days until expiry, and any error message.
    """
    return await asyncio.to_thread(get_certificate_info, domain)

async def process_cert_domain(domain: str) -> Tuple[str, str, str, str]:
    """
    Processes certificate check for a domain and returns a tuple of results.

    Args:
        domain (str): The domain to process.

    Returns:
        Tuple containing domain, certificate expiry date, days until expiry, and error message.
    """
    cert_expiry_date, days_until_expiry, cert_error = await process_certificate_check(domain)
    return (
        domain,
        cert_expiry_date if cert_expiry_date else "",
        str(days_until_expiry) if days_until_expiry is not None else "",
        cert_error
    )

async def run_certificate_checks(domains: List[str]) -> List[Tuple[str, str, str, str]]:
    """
    Runs TLS/SSL certificate checks for a list of domains asynchronously.

    Args:
        domains (List[str]): List of domains.

    Returns:
        List of tuples with certificate check results.
    """
    tasks = [process_cert_domain(domain) for domain in domains]
    results: List[Tuple[str, str, str, str]] = []
    total = len(tasks)
    progress_bar = st.progress(0)
    for i, task in enumerate(asyncio.as_completed(tasks), start=1):
        result = await task
        results.append(result)
        progress_bar.progress(int((i / total) * 100))
    return results

async def check_wildcard_dns(domain: str, record_type: str = "A") -> str:
    """
    Checks if a domain supports wildcard DNS by querying a randomized subdomain.

    Args:
        domain (str): The domain to check.
        record_type (str): DNS record type to query (default is "A").

    Returns:
        "Yes" if wildcard DNS is detected, "No" otherwise.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    random_sub = "wildcardtest" + str(int(time.time() * 1000)) + "." + domain
    try:
        await resolver.resolve(random_sub, record_type)
        return "Yes"
    except dns.resolver.NXDOMAIN:
        return "No"
    except Exception:
        return "No"

async def process_all_in_one(
    domain: str,
    timeout: int,
    retries: int,
    dns_record_types: List[str],
    whois_enabled: bool,
    cert_enabled: bool,
    wildcard_enabled: bool,
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore
) -> Dict[str, Any]:
    """
    Performs a comprehensive set of checks (HTTP, WHOIS, DNS, TLS/SSL, wildcard) for a domain.

    Args:
        domain (str): The domain to check.
        timeout (int): HTTP timeout.
        retries (int): Number of HTTP retries.
        dns_record_types (List[str]): DNS record types to check.
        whois_enabled (bool): Whether to perform WHOIS lookup.
        cert_enabled (bool): Whether to perform TLS/SSL certificate check.
        wildcard_enabled (bool): Whether to check for wildcard DNS.
        session (aiohttp.ClientSession): The aiohttp session for HTTP checks.
        semaphore (asyncio.Semaphore): Semaphore to control concurrency.

    Returns:
        Dictionary with the combined results from all checks.
    """
    result: Dict[str, Any] = {"Domain": domain}
    if whois_enabled:
        whois_info = await asyncio.to_thread(get_whois_info, domain)
        result["Registrar"] = whois_info.get("registrar", "")
        result["WHOIS Creation Date"] = whois_info.get("creation_date", "")
        result["WHOIS Expiration Date"] = whois_info.get("expiration_date", "")
        result["Name Servers"] = whois_info.get("name_servers", "")
        result["WHOIS Error"] = whois_info.get("error", "")
    http_result = await check_http_domain(domain, timeout, retries, session, http_headers, semaphore)
    (_, http_status, http_snippet, http_response_time, http_attempts,
     http_response_received, http_redirect_history, http_redirected) = http_result
    result["HTTP Status"] = http_status
    result["HTTP Snippet"] = http_snippet
    result["HTTP Response Time (s)"] = http_response_time
    result["HTTP Attempts"] = http_attempts
    result["Response Received"] = http_response_received
    result["Redirect History"] = http_redirect_history
    result["Redirected"] = http_redirected
    if dns_record_types:
        dns_result = await get_dns_record_for_domain(domain, dns_record_types)
        dns_records = dns_result[1]
        dns_summary = ", ".join(
            [f"{rtype}: {', '.join(val) if isinstance(val, list) else val}" for rtype, val in dns_records.items()]
        )
        result["DNS Records"] = dns_summary
        recursive_dns = await get_recursive_dns_chain(domain, dns_record_types)
        result["Recursive DNS Chain"] = recursive_dns
    if cert_enabled:
        cert_expiry_date, days_until_expiry, cert_error = await process_certificate_check(domain)
        result["Certificate Expiry Date"] = cert_expiry_date if cert_expiry_date else ""
        result["Days Until Expiry"] = days_until_expiry if days_until_expiry is not None else ""
        result["Certificate Error"] = cert_error
    if wildcard_enabled:
        wildcard = await check_wildcard_dns(domain)
        result["Wildcard DNS"] = wildcard
    return result

async def get_recursive_dns_chain(domain: str, record_types: List[str]) -> str:
    """
    Generates a recursive DNS resolution chain for a domain.

    Args:
        domain (str): The domain to resolve.
        record_types (List[str]): DNS record types to include in the chain.

    Returns:
        A formatted string representing the recursive DNS chain.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    output_lines: List[str] = []
    output_lines.append(f"DNS Resolution for {domain}")
    output_lines.append("    ")
    if "A" in record_types or "AAAA" in record_types:
        output_lines.append("A/AAAA Resolution:")
        chain_lines: List[str] = []
        current = domain
        chain_lines.append(f"Start Domain: {current}")
        last_cname: Optional[str] = None
        while True:
            try:
                cname_answer = await resolver.resolve(current, "CNAME")
                cname_list = [rdata.to_text() for rdata in cname_answer]
                cname_value = cname_list[0]
                chain_lines.append(f"CNAME: {cname_value} (inherited from {current})")
                last_cname = current = cname_value.rstrip('.')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
                break
            except Exception as e:
                chain_lines.append(f"CNAME: Error: {str(e)}")
                break
        if "A" in record_types:
            try:
                a_answer = await resolver.resolve(current, "A")
                a_recs = [rdata.to_text() for rdata in a_answer]
                if last_cname:
                    chain_lines.append(f"A Records (inherited from {current}): {', '.join(a_recs)}")
                else:
                    chain_lines.append(f"A Records: {', '.join(a_recs)}")
            except Exception as e:
                chain_lines.append(f"A Records: Error: {str(e)}")
        if "AAAA" in record_types:
            try:
                aaaa_answer = await resolver.resolve(current, "AAAA")
                aaaa_recs = [rdata.to_text() for rdata in aaaa_answer]
                if last_cname:
                    chain_lines.append(f"AAAA Records (inherited from {current}): {', '.join(aaaa_recs)}")
                else:
                    chain_lines.append(f"AAAA Records: {', '.join(aaaa_recs)}")
            except Exception as e:
                chain_lines.append(f"AAAA Records: Error: {str(e)}")
        for cl in chain_lines:
            output_lines.append("  - " + cl)
        output_lines.append("")
    if "MX" in record_types:
        output_lines.append("MX Records:")
        try:
            mx_answer = await resolver.resolve(domain, "MX")
            for rdata in mx_answer:
                priority = rdata.preference
                target = str(rdata.exchange).rstrip('.')
                mx_chain: List[str] = [f"Priority {priority}: {target}"]
                last_mx = target
                current_mx = target
                while True:
                    try:
                        mx_cname_answer = await resolver.resolve(current_mx, "CNAME")
                        cname_list = [rd.to_text() for rd in mx_cname_answer]
                        cname_value = cname_list[0]
                        mx_chain.append(f"CNAME: {cname_value} (inherited from {current_mx})")
                        last_mx = current_mx = cname_value.rstrip('.')
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
                        break
                    except Exception as e:
                        mx_chain.append(f"CNAME: Error: {str(e)}")
                        break
                try:
                    a_answer = await resolver.resolve(current_mx, "A")
                    a_recs = [rdata.to_text() for rdata in a_answer]
                    mx_chain.append(f"A Records (from {current_mx}): {', '.join(a_recs)}")
                except Exception as e:
                    mx_chain.append(f"A Records: Error: {str(e)}")
                for item in mx_chain:
                    output_lines.append("  - " + item)
                output_lines.append("")
        except Exception as e:
            output_lines.append(f"MX Records: Error: {str(e)}")
            output_lines.append("")
    for rtype in record_types:
        if rtype not in ["A", "AAAA", "MX"]:
            output_lines.append(f"{rtype} Records:")
            try:
                answer = await resolver.resolve(domain, rtype)
                recs = [rdata.to_text() for rdata in answer]
                output_lines.append("  - " + ", ".join(recs))
            except Exception as e:
                output_lines.append(f"  - Error: {str(e)}")
            output_lines.append("")
    return "\n".join(output_lines)

async def run_all_in_one_checks(
    domains: List[str],
    timeout: int,
    concurrency: int,
    retries: int,
    dns_record_types: List[str],
    whois_enabled: bool,
    cert_enabled: bool,
    wildcard_enabled: bool
) -> List[Dict[str, Any]]:
    """
    Runs a comprehensive set of checks (HTTP, DNS, WHOIS, TLS/SSL, wildcard) on a list of domains.

    Args:
        domains (List[str]): List of domains.
        timeout (int): HTTP timeout.
        concurrency (int): Maximum number of concurrent HTTP requests.
        retries (int): HTTP retries.
        dns_record_types (List[str]): DNS record types to check.
        whois_enabled (bool): Whether to perform WHOIS lookup.
        cert_enabled (bool): Whether to perform TLS/SSL certificate check.
        wildcard_enabled (bool): Whether to check for wildcard DNS.

    Returns:
        List of dictionaries with combined check results.
    """
    results: List[Dict[str, Any]] = []
    semaphore = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        tasks = [
            process_all_in_one(domain, timeout, retries, dns_record_types, whois_enabled, cert_enabled, wildcard_enabled, session, semaphore)
            for domain in domains
        ]
        progress_bar = st.progress(0)
        total = len(tasks)
        completed = 0
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            completed += 1
            progress_bar.progress(int((completed / total) * 100))
    return results

# --- New helper functions for Subdomain Finder ---

async def check_subdomain(session: aiohttp.ClientSession, subdomain: str) -> Dict[str, str]:
    """
    Asynchronously checks if a given subdomain is live via an HTTP request.

    Args:
        session (aiohttp.ClientSession): The HTTP session.
        subdomain (str): The subdomain to check.

    Returns:
        Dictionary containing the subdomain, its status, and any error encountered.
    """
    url = f"http://{subdomain}"
    try:
        async with session.get(url, timeout=3) as response:
            if response.status < 400:
                return {"Subdomain": subdomain, "Status": f"Live ({response.status})", "Error": ""}
            else:
                return {"Subdomain": subdomain, "Status": f"Down ({response.status})", "Error": f"HTTP Error {response.status}"}
    except Exception as e:
        return {"Subdomain": subdomain, "Status": "Down (Error)", "Error": str(e)}

async def perform_http_checks(subdomain_list: List[str], progress_callback: Callable[[float], None]) -> List[Dict[str, str]]:
    """
    Performs HTTP checks on a list of subdomains asynchronously.

    Args:
        subdomain_list (List[str]): List of subdomains.
        progress_callback (Callable[[float], None]): Function to update progress (value between 0 and 1).

    Returns:
        List of dictionaries with subdomain check results.
    """
    results: List[Dict[str, str]] = []
    async with aiohttp.ClientSession() as session:
        tasks = [check_subdomain(session, sub) for sub in subdomain_list]
        total = len(tasks)
        for i, future in enumerate(asyncio.as_completed(tasks)):
            result = await future
            results.append(result)
            progress_callback((i + 1) / total)
    return results

# --- Streamlit App Layout ---

st.set_page_config(page_title="Domain Checker", layout="wide")
st.title("Domain Checker")

tabs = st.tabs([
    "HTTP Check", 
    "DNS Lookup", 
    "WHOIS Check", 
    "TLS/SSL Certificate Check", 
    "Subdomain Finder", 
    "Advanced Check"
])

with tabs[0]:
    st.header("HTTP Check")
    st.markdown("Retrieve HTTP status code, response snippet, response time, and redirection details to verify website availability and performance.")
    with st.form("http_form"):
        domains_input_http: str = st.text_area("Enter one or more domains (one per line):", height=200, help="Example: example.com")
        timeout: int = st.number_input("Timeout (seconds)", min_value=1, value=10, step=1, help="Maximum time to wait for a response.")
        concurrency: int = st.number_input("Concurrency", min_value=1, value=20, step=1, help="Number of simultaneous HTTP requests.")
        retries: int = st.number_input("Retries", min_value=1, value=3, step=1, help="Number of retry attempts per domain.")
        submit_http = st.form_submit_button("Run HTTP Check")
        
    if submit_http:
        if not domains_input_http.strip():
            st.error("Please enter at least one domain.")
        else:
            domains_http: List[str] = [line.strip() for line in domains_input_http.splitlines() if line.strip()]
            st.info("Starting HTTP checks...")
            http_results = asyncio.run(run_http_checks(domains_http, timeout, concurrency, retries))
            df_http = pd.DataFrame(
                http_results,
                columns=["Domain", "Status Code", "Response Snippet", "Response Time (s)",
                         "Attempts", "Response Received", "Redirect History", "Redirected"]
            )
            st.write("### HTTP Check Results", df_http)
            st.session_state["http_df"] = df_http
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            st.download_button("Download Table as CSV", df_http.to_csv(index=False),
                               file_name=f"HTTP_Check_Results_{timestamp}.csv", mime="text/csv")
    elif "http_df" in st.session_state:
        st.write("### HTTP Check Results", st.session_state["http_df"])

with tabs[1]:
    st.header("DNS Lookup")
    st.markdown("Perform DNS record lookups for specified domains using non-recursive searches. Select one or more DNS record types to retrieve detailed information.")
    with st.form("dns_form"):
        domains_input_dns: str = st.text_area("Enter one or more domains (one per line):", height=150, help="Example: example.com")
        st.markdown("### Select DNS Record Types")
        record_options: List[str] = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
        selected_record_types: List[str] = []
        cols = st.columns(4)
        for i, rtype in enumerate(record_options):
            col = cols[i % 4]
            if col.checkbox(rtype, value=True, key=f"checkbox_{rtype}"):
                selected_record_types.append(rtype)
        submit_dns = st.form_submit_button("Lookup DNS Records")
        
    if submit_dns:
        if not domains_input_dns.strip():
            st.error("Please enter at least one domain.")
        elif not selected_record_types:
            st.error("Please select at least one DNS record type.")
        else:
            domains_dns: List[str] = [line.strip() for line in domains_input_dns.splitlines() if line.strip()]
            total_domains = len(domains_dns)
            st.write(f"Processing **{total_domains}** domain(s)...")
            progress_bar = st.progress(0)
            def progress_callback(completed: int, total: int) -> None:
                progress_bar.progress(int((completed / total) * 100))
            start_time = time.time()
            dns_results = asyncio.run(run_dns_checks(domains_dns, selected_record_types, progress_callback))
            end_time = time.time()
            elapsed_time = end_time - start_time
            csv_output = io.StringIO()
            csv_writer = csv.writer(csv_output)
            header = ["Domain"] + selected_record_types
            if any("CNAME_Inheritance" in recs for recs in dns_results.values()):
                header.append("CNAME_Inheritance")
            csv_writer.writerow(header)
            data_rows = []
            for domain, recs in dns_results.items():
                row = [domain]
                for rtype in selected_record_types:
                    val = recs.get(rtype, "")
                    if isinstance(val, list):
                        val = "; ".join(val)
                    row.append(val)
                if "CNAME_Inheritance" in header:
                    row.append(recs.get("CNAME_Inheritance", ""))
                data_rows.append(row)
                csv_writer.writerow(row)
            csv_data = csv_output.getvalue()
            st.subheader("Statistics")
            st.write(f"**Time Taken:** {elapsed_time:.2f} seconds")
            st.write(f"**Processing Speed:** {total_domains / elapsed_time:.2f} domains/second")
            st.download_button("Download Table as CSV", data=csv_data,
                               file_name=f"DNS_Lookup_Results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")
            st.subheader("DNS Results")
            df_dns = pd.DataFrame(data_rows, columns=header)
            st.write(df_dns)
            st.session_state["dns_df"] = df_dns
    elif "dns_df" in st.session_state:
        st.write("DNS Results", st.session_state["dns_df"])

with tabs[2]:
    st.header("WHOIS Check")
    st.markdown("Retrieve domain registration details including Registrar, creation date, expiration date, and name servers.")
    with st.form("whois_form"):
        domains_input: str = st.text_area("Enter one or more domains (one per line):", height=200, help="Example: example.com")
        submit_whois = st.form_submit_button("Run WHOIS Check")
        
    if submit_whois:
        if not domains_input.strip():
            st.error("Please enter at least one domain.")
        else:
            domains: List[str] = [line.strip() for line in domains_input.splitlines() if line.strip()]
            st.info("Starting WHOIS lookups...")
            whois_results = asyncio.run(run_whois_checks(domains))
            df_whois = pd.DataFrame(
                whois_results,
                columns=["Domain", "Registrar", "WHOIS Creation Date", "WHOIS Expiration Date", "Name Servers", "WHOIS Error"]
            )
            if "WHOIS Error" in df_whois.columns and df_whois["WHOIS Error"].astype(str).str.strip().eq("").all():
                df_whois.drop(columns=["WHOIS Error"], inplace=True)
            st.write("### WHOIS Results", df_whois)
            st.session_state["whois_df"] = df_whois
            st.download_button("Download Table as CSV", df_whois.to_csv(index=False),
                               file_name=f"WHOIS_Results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")
    elif "whois_df" in st.session_state:
        st.write("### WHOIS Results", st.session_state["whois_df"])

with tabs[3]:
    st.header("TLS/SSL Certificate Check")
    st.markdown("Perform a TLS/SSL certificate check for each domain. This check returns the certificate expiry date, the number of days until expiry, and any errors encountered.")
    with st.form("cert_form"):
        domains_input_cert: str = st.text_area("Enter one or more domains (one per line):", height=200, help="Example: example.com")
        submit_cert = st.form_submit_button("Run TLS/SSL Certificate Check")
        
    if submit_cert:
        if not domains_input_cert.strip():
            st.error("Please enter at least one domain.")
        else:
            domains_cert: List[str] = [line.strip() for line in domains_input_cert.splitlines() if line.strip()]
            st.info("Starting TLS/SSL Certificate Check...")
            cert_results = asyncio.run(run_certificate_checks(domains_cert))
            df_cert = pd.DataFrame(
                cert_results,
                columns=["Domain", "Certificate Expiry Date", "Days Until Expiry", "Certificate Error"]
            )
            if "Certificate Error" in df_cert.columns and df_cert["Certificate Error"].astype(str).str.strip().eq("").all():
                df_cert.drop(columns=["Certificate Error"], inplace=True)
            st.write("### TLS/SSL Certificate Check Results", df_cert)
            st.session_state["cert_df"] = df_cert
            st.download_button("Download Table as CSV", df_cert.to_csv(index=False),
                               file_name=f"TLS_SSL_Certificate_Results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")
    elif "cert_df" in st.session_state:
        st.write("### TLS/SSL Certificate Check Results", st.session_state["cert_df"])

with tabs[4]:
    st.header("Subdomain Finder")
    st.write("Search crt.sh for subdomains of a given domain and perform HTTP checks to determine if they are online.")
    domain_input: str = st.text_input("Enter a naked domain (e.g. example.com):", help="Do not include www or subdomains.")
    if st.button("Search") and domain_input:
        with st.spinner(text=f"Searching for subdomains of {domain_input}... This can take a few minutes."):
            try:
                data = crtshAPI().search(domain_input)
                if not data:
                    st.error("No data returned from crt.sh. The domain may not have any certificate records or the API might be unavailable. (Try again or try another domain)")
                else:
                    subdomains = set()
                    for entry in data:
                        names = entry.get("name_value", "").splitlines()
                        for sub in names:
                            sub = sub.strip()
                            if sub.endswith(domain_input):
                                subdomains.add(sub)
                    subdomain_list: List[str] = list(subdomains)
                    st.write(f"Found {len(subdomain_list)} unique subdomains.")

                    progress_bar = st.progress(0)
                    def update_progress(value: float) -> None:
                        progress_bar.progress(value)

                    results = asyncio.run(perform_http_checks(subdomain_list, update_progress))

                    online_results = [{"Subdomain": res["Subdomain"], "Status": res["Status"]} 
                                      for res in results if "Live" in res["Status"]]
                    offline_results = [res for res in results if "Down" in res["Status"]]

                    st.subheader("Online Subdomains")
                    if online_results:
                        df_online = pd.DataFrame(online_results)
                        st.write(df_online)
                        csv_online = df_online.to_csv(index=False).encode("utf-8")
                        st.download_button(
                            label="Download Online CSV",
                            data=csv_online,
                            file_name="online_subdomains.csv",
                            mime="text/csv"
                        )
                    else:
                        st.write("No online subdomains found.")

                    st.subheader("Offline Subdomains")
                    if offline_results:
                        df_offline = pd.DataFrame(offline_results)
                        st.write(df_offline)
                        csv_offline = df_offline.to_csv(index=False).encode("utf-8")
                        st.download_button(
                            label="Download Offline CSV",
                            data=csv_offline,
                            file_name="offline_subdomains.csv",
                            mime="text/csv"
                        )
                    else:
                        st.write("No offline subdomains found.")
            except Exception as e:
                st.error(f"An error occurred: {e}")

with tabs[5]:
    st.header("Advanced Check")
    st.markdown("Combine HTTP, DNS, WHOIS, and TLS/SSL lookups into one comprehensive report.")
    with st.form("all_form"):
        domains_input_all: str = st.text_area("Enter one or more domains (one per line):", height=200, help="Example: example.com")
        # Extra options for wildcard check and enabling WHOIS/TLS lookups
        wildcard_enabled: bool = st.checkbox("Check for Wildcard DNS", value=False, key="check_wildcard")
        whois_enabled: bool = st.checkbox("Enable WHOIS Lookup *(Slows Down Large Batches)*", value=False, key="all_whois_enabled")
        cert_enabled: bool = st.checkbox("Enable TLS/SSL Certificate Check", value=False, key="all_cert_enabled")
        st.markdown("### Select DNS Record Types")
        record_options_all: List[str] = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
        selected_dns_all: List[str] = []
        cols = st.columns(4)
        for i, rtype in enumerate(record_options_all):
            col = cols[i % 4]
            if col.checkbox(rtype, value=True, key=f"all_checkbox_{rtype}"):
                selected_dns_all.append(rtype)      
        timeout_all: int = st.number_input("HTTP Timeout (seconds)", min_value=1, value=10, step=1, help="Max time (in seconds) for HTTP requests.")
        concurrency_all: int = st.number_input("HTTP Concurrency", min_value=1, value=20, step=1, help="Number of simultaneous HTTP requests.")
        retries_all: int = st.number_input("HTTP Retries", min_value=1, value=3, step=1, help="Number of retry attempts per domain.")
        submit_all = st.form_submit_button("Run Advanced Check")
        
    if submit_all:
        if not domains_input_all.strip():
            st.error("Please enter at least one domain.")
        else:
            domains_all: List[str] = [line.strip() for line in domains_input_all.splitlines() if line.strip()]
            enabled_checks = "HTTP"
            if whois_enabled:
                enabled_checks += ", WHOIS"
            if selected_dns_all:
                enabled_checks += ", DNS"
            if cert_enabled:
                enabled_checks += ", TLS/SSL Certificate Check"
            if wildcard_enabled:
                enabled_checks += ", Wildcard DNS Check"
            st.info(f"Starting All In One checks ({enabled_checks})...")
            start_time_all = time.time()
            all_results = asyncio.run(
                run_all_in_one_checks(domains_all, timeout_all, concurrency_all, retries_all, selected_dns_all, whois_enabled, cert_enabled, wildcard_enabled)
            )
            end_time_all = time.time()
            elapsed_all = end_time_all - start_time_all
            st.write(f"**Total Time Taken:** {elapsed_all:.2f} seconds")
            columns: List[str] = ["Domain", "HTTP Status"]
            if cert_enabled:
                columns.extend(["Certificate Expiry Date", "Days Until Expiry"])
            if selected_dns_all:
                columns.extend(["DNS Records", "Recursive DNS Chain"])
            if whois_enabled:
                columns.extend(["Registrar", "WHOIS Creation Date", "WHOIS Expiration Date", "Name Servers"])
            if wildcard_enabled:
                columns.append("Wildcard DNS")
            columns.extend(["HTTP Response Time (s)", "HTTP Attempts", "Response Received", "Redirected", "Redirect History", "HTTP Snippet"])
            if whois_enabled:
                columns.append("WHOIS Error")
            if cert_enabled:
                columns.append("Certificate Error")
            df_all = pd.DataFrame(all_results)
            df_all = df_all[[col for col in columns if col in df_all.columns]]
            if "WHOIS Error" in df_all.columns and df_all["WHOIS Error"].astype(str).str.strip().eq("").all():
                df_all.drop(columns=["WHOIS Error"], inplace=True)
            if "Certificate Error" in df_all.columns and df_all["Certificate Error"].astype(str).str.strip().eq("").all():
                df_all.drop(columns=["Certificate Error"], inplace=True)
            st.write("### Advanced Check Results", df_all)
            st.session_state["adv_df"] = df_all
            st.download_button("Download Table as CSV", df_all.to_csv(index=False),
                               file_name=f"Advanced_Check_Results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", mime="text/csv")
            st.session_state["all_results"] = all_results
    if "all_results" in st.session_state:
        with st.expander("View Statistics"):
            all_results = st.session_state["all_results"]
            http_times = [res.get("HTTP Response Time (s)") for res in all_results if res.get("HTTP Response Time (s)") is not None]
            if http_times:
                avg_time = sum(http_times) / len(http_times)
                max_time = max(http_times)
                min_time = min(http_times)
                slowest_domains = [res["Domain"] for res in all_results if res.get("HTTP Response Time (s)") == max_time]
                fastest_domains = [res["Domain"] for res in all_results if res.get("HTTP Response Time (s)") == min_time]
                speed = len(http_times) / sum(http_times) if sum(http_times) > 0 else 0
                st.write(f"**Total Domains Processed:** {len(http_times)}")
                st.write(f"**Average HTTP Response Time:** {avg_time:.2f} seconds")
                if fastest_domains:
                    st.write(f"The fastest response was from {fastest_domains[0]} taking {min_time:.2f} seconds.")
                if slowest_domains:
                    st.write(f"The slowest response was from {slowest_domains[0]} taking {max_time:.2f} seconds.")
                st.write(f"**Speed per Domain:** {speed:.2f} domains per second")
            else:
                st.write("No HTTP response times available for advanced statistics.")

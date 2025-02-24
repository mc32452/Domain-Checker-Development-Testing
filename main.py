import asyncio
import aiohttp
import dns.asyncresolver
import csv
import io
import time
import streamlit as st
import pandas as pd
import ssl
import socket
import datetime
from urllib.parse import urlparse
from crtsh import crtshAPI  # For Subdomain Finder
from typing import List, Tuple, Dict, Any, Optional, Callable, Union

# ------------------------------
# Global Variables and Headers
# ------------------------------
http_headers: Dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-GB,en;q=0.9,en-US;q=0.8,en-IE;q=0.7"
}

# ------------------------------
# WHOIS Lookup Functions
# ------------------------------
async def get_whois_info(domain: str, session: aiohttp.ClientSession) -> dict:
    """
    Retrieves WHOIS information for the specified domain using the endpoint:
      https://rdap.ports.domains/domain/{domain}
    Then it parses the JSON response into a simplified format.

    Extracted fields:
      - Creation Date: from events with eventAction "registration" or "created"
      - Last Updated: from events with eventAction "last updated" or "updated"
      - Expiration Date: from events with eventAction "expiration"
      - Nameservers: list of nameservers
      - Registrant: from the entity with role "registrant" (with handle, organization, and kind)
      - Registrar: from the entity with role "registrar" (with name, IANA ID, and URL)

    If no registrant info is found, defaults to "Not Available".
    """
    rdap_url = f"https://rdap.ports.domains/domain/{domain}"
    try:
        async with session.get(rdap_url, timeout=10) as response:
            if response.status != 200:
                return {
                    "registrant": "Not Available",
                    "registrar": "",
                    "creation_date": "",
                    "expiration_date": "",
                    "updated_date": "",
                    "name_servers": "",
                    "error": f"HTTP error {response.status}"
                }
            data = await response.json()
    except Exception as e:
        return {
            "registrant": "Not Available",
            "registrar": "",
            "creation_date": "",
            "expiration_date": "",
            "updated_date": "",
            "name_servers": "",
            "error": str(e)
        }

    # Parse dates from "events"
    creation_date = ""
    expiration_date = ""
    updated_date = ""
    if "events" in data:
        for event in data["events"]:
            action = event.get("eventAction", "").lower()
            if action in ["registration", "created"] and not creation_date:
                creation_date = event.get("eventDate", "")
            elif action in ["last updated", "updated"] and not updated_date:
                updated_date = event.get("eventDate", "")
            elif action == "expiration" and not expiration_date:
                expiration_date = event.get("eventDate", "")

    # Parse nameservers (join each ldhName with newline)
    ns_list = []
    if "nameservers" in data:
        for ns in data["nameservers"]:
            ns_name = ns.get("ldhName", "")
            if ns_name:
                ns_list.append(ns_name)
    nameservers = "\n".join(ns_list)

    # Default values for registrant and registrar
    registrant_str = "Not Available"
    registrar_str = ""

    # Parse entities for contact information
    if "entities" in data:
        for entity in data["entities"]:
            roles = entity.get("roles", [])
            # Registrant: look for role "registrant"
            if "registrant" in roles:
                handle = entity.get("handle", "")
                org = ""
                kind = ""
                if "vcardArray" in entity and len(entity["vcardArray"]) > 1:
                    for item in entity["vcardArray"][1]:
                        if len(item) >= 4:
                            key = item[0].lower()
                            value = item[3]
                            if key == "org":
                                org = value
                            elif key == "kind":
                                kind = value
                registrant_str = f"Handle: {handle}\nOrganization: {org}\nKind: {kind}"
            # Registrar: look for role "registrar"
            elif "registrar" in roles:
                handle = entity.get("handle", "")
                fn = ""
                url_val = ""
                if "vcardArray" in entity and len(entity["vcardArray"]) > 1:
                    for item in entity["vcardArray"][1]:
                        if len(item) >= 4:
                            key = item[0].lower()
                            value = item[3]
                            if key == "fn":
                                fn = value
                            elif key == "url":
                                url_val = value
                registrar_str = f"Name: {fn}\nIANA ID: {handle}\nURL: {url_val}"

    return {
        "registrant": registrant_str,
        "registrar": registrar_str,
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "updated_date": updated_date,
        "name_servers": nameservers,
        "error": ""
    }

async def run_whois_checks(domains: List[str]) -> List[Tuple[str, str, str, str, str, str, str]]:
    """
    Runs WHOIS lookups for a list of domains asynchronously.
    Returns tuples in the format:
    (domain, registrant, registrar, creation_date, expiration_date, updated_date, name_servers)
    """
    async with aiohttp.ClientSession() as session:
        tasks = [get_whois_info(domain, session) for domain in domains]
        results = await asyncio.gather(*tasks)
        output = []
        for domain, info in zip(domains, results):
            output.append((
                domain,
                info.get("registrant", "Not Available"),
                info.get("registrar", ""),
                info.get("creation_date", ""),
                info.get("expiration_date", ""),
                info.get("updated_date", ""),
                info.get("name_servers", "")
            ))
        return output

# ------------------------------
# HTTP Check Functions
# ------------------------------
def normalize_url(url_str: str) -> Tuple[str, str, str]:
    parsed = urlparse(url_str)
    netloc = parsed.netloc.lower().lstrip("www.")
    path = parsed.path.rstrip("/") or "/"
    return netloc, path, parsed.query

async def check_http_domain(domain: str, timeout: int, retries: int, session: aiohttp.ClientSession, headers: Dict[str, str], semaphore: asyncio.Semaphore) -> Tuple[Any, ...]:
    """
    Checks the HTTP response for a given domain.
    Tries https:// then falls back to http:// if needed.
    """
    protocols = [""] 
    if not domain.startswith(("http://", "https://")):
        protocols = ["https://", "http://"]
    last_exception = None
    for protocol in protocols:
        url = protocol + domain if protocol else domain
        attempt = 0
        start_time = time.perf_counter()
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
                        redirected = "Yes" if normalize_url(url) != normalize_url(str(response.url)) else "No"
                        return (domain, status, snippet, round(response_time, 2), attempt, "Yes", redirect_info, redirected)
            except Exception as e:
                last_exception = e
                await asyncio.sleep(0.5)
        response_time = time.perf_counter() - start_time
        return (domain, None, f"Error: {str(last_exception)}", round(response_time, 2), attempt, "No", "No redirect", "No")

async def run_http_checks(domains: List[str], timeout: int, concurrency: int, retries: int) -> List[Tuple[Any, ...]]:
    results: List[Tuple[Any, ...]] = []
    semaphore = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        tasks = [check_http_domain(domain, timeout, retries, session, http_headers, semaphore) for domain in domains]
        total = len(tasks)
        completed = 0
        progress_bar = st.progress(0)
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            completed += 1
            progress_bar.progress(int((completed / total) * 100))
    return results

# ------------------------------
# DNS Lookup Functions
# ------------------------------
async def get_dns_record_for_domain(domain: str, record_types: List[str]) -> Tuple[str, Dict[str, Union[List[str], str]]]:
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
                    mx_str = f"Priority {rdata.preference}: {target}"
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

# ------------------------------
# TLS/SSL Certificate Check Functions
# ------------------------------
def get_certificate_info(domain: str) -> Tuple[Optional[str], Optional[int], str]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date_str = cert.get('notAfter')
                if not expiry_date_str:
                    return None, None, "Certificate does not have an expiration date"
                expiry_timestamp = ssl.cert_time_to_seconds(expiry_date_str)
                expiry_date = datetime.datetime.fromtimestamp(expiry_timestamp, datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                days_until_expiry = (expiry_date - now).days
                return expiry_date.isoformat(), days_until_expiry, ""
    except Exception as e:
        return None, None, str(e)

async def process_certificate_check(domain: str) -> Tuple[Optional[str], Optional[int], str]:
    return await asyncio.to_thread(get_certificate_info, domain)

async def process_cert_domain(domain: str) -> Tuple[str, str, str, str]:
    cert_expiry_date, days_until_expiry, cert_error = await process_certificate_check(domain)
    return (
        domain,
        cert_expiry_date if cert_expiry_date else "",
        str(days_until_expiry) if days_until_expiry is not None else "",
        cert_error
    )

async def run_certificate_checks(domains: List[str]) -> List[Tuple[str, str, str, str]]:
    tasks = [process_cert_domain(domain) for domain in domains]
    results: List[Tuple[str, str, str, str]] = []
    total = len(tasks)
    progress_bar = st.progress(0)
    for i, task in enumerate(asyncio.as_completed(tasks), start=1):
        result = await task
        results.append(result)
        progress_bar.progress(int((i / total) * 100))
    return results

# ------------------------------
# Wildcard DNS Check Function
# ------------------------------
async def check_wildcard_dns(domain: str, record_type: str = "A") -> str:
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

# ------------------------------
# Comprehensive (All In One) Check Function
# ------------------------------
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
    result: Dict[str, Any] = {"Domain": domain}
    if whois_enabled:
        whois_info = await get_whois_info(domain, session)
        result["Registrant"] = whois_info.get("registrant", "Not Available")
        result["Registrar"] = whois_info.get("registrar", "")
        result["WHOIS Creation Date"] = whois_info.get("creation_date", "")
        result["WHOIS Expiration Date"] = whois_info.get("expiration_date", "")
        result["Last Updated"] = whois_info.get("updated_date", "")
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
                mx_chain: List[str] = [f"Priority {rdata.preference}: {str(rdata.exchange).rstrip('.') }"]
                current_mx = str(rdata.exchange).rstrip('.')
                while True:
                    try:
                        mx_cname_answer = await resolver.resolve(current_mx, "CNAME")
                        cname_list = [rd.to_text() for rd in mx_cname_answer]
                        cname_value = cname_list[0]
                        mx_chain.append(f"CNAME: {cname_value} (inherited from {current_mx})")
                        current_mx = cname_value.rstrip('.')
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
    results: List[Dict[str, Any]] = []
    semaphore = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        tasks = [
            process_all_in_one(domain, timeout, retries, dns_record_types, whois_enabled, cert_enabled, wildcard_enabled, session, semaphore)
            for domain in domains
        ]
        total = len(tasks)
        completed = 0
        progress_bar = st.progress(0)
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            completed += 1
            progress_bar.progress(int((completed / total) * 100))
    return results

# ------------------------------
# Subdomain Finder Functions
# ------------------------------
async def check_subdomain_advanced(session: aiohttp.ClientSession, subdomain: str, timeout: int = 3, retries: int = 3, semaphore: Optional[asyncio.Semaphore] = None) -> Dict[str, Any]:
    if semaphore is None:
        semaphore = asyncio.Semaphore(20)
    result = await check_http_domain(subdomain, timeout, retries, session, http_headers, semaphore)
    domain, status, snippet, response_time, attempts, response_received, redirect_history, redirected = result
    return {
         "Subdomain": domain,
         "HTTP Status": status,
         "HTTP Snippet": snippet,
         "Response Time (s)": response_time,
         "HTTP Attempts": attempts,
         "Response Received": response_received,
         "Redirect History": redirect_history,
         "Redirected": redirected,
    }

async def perform_http_checks(subdomain_list: List[str], progress_callback: Callable[[float], None]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    semaphore = asyncio.Semaphore(20)
    async with aiohttp.ClientSession() as session:
        tasks = [check_subdomain_advanced(session, sub) for sub in subdomain_list]
        total = len(tasks)
        for i, future in enumerate(asyncio.as_completed(tasks)):
            result = await future
            results.append(result)
            progress_callback((i + 1) / total)
    return results

# ------------------------------
# Streamlit App Layout
# ------------------------------
st.set_page_config(page_title="Domain Checker", layout="wide")
st.title("Domain Checker")

tabs = st.tabs([
    "HTTP Check", 
    "DNS Lookup", 
    "WHOIS Lookup", 
    "TLS/SSL Certificate Check", 
    "Subdomain Finder", 
    "Advanced Check"
])

# HTTP Check Tab
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
            st.write("### HTTP Check Results")
            st.caption("Double click any cell in the table to view its full content.")
            st.write(df_http)
            st.session_state["http_df"] = df_http
            date_str = datetime.datetime.now().strftime("%d.%m.%Y")
            st.download_button("Download Table as CSV", df_http.to_csv(index=False),
                               file_name=f"HTTP_Check_Results_{date_str}.csv", mime="text/csv")
    elif "http_df" in st.session_state:
        st.write("### HTTP Check Results", st.session_state["http_df"])

# DNS Lookup Tab
with tabs[1]:
    st.header("DNS Lookup")
    st.markdown("Perform DNS record lookups for specified domain(s). Use advanced search for recursive DNS lookups.")
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
            st.write("### DNS Results")
            st.caption("Double click any cell in the table to view its full content.")
            df_dns = pd.DataFrame(data_rows, columns=header)
            st.write(df_dns)
            st.session_state["dns_df"] = df_dns
            date_str = datetime.datetime.now().strftime("%d.%m.%Y")
            st.download_button("Download Table as CSV", data=csv_data,
                               file_name=f"DNS_Lookup_Results_{date_str}.csv", mime="text/csv")
            with st.expander("View Statistics"):
                st.write(f"**Time Taken:** {elapsed_time:.2f} seconds")
                st.write(f"**Processing Speed:** {total_domains / elapsed_time:.2f} domains/second")
    elif "dns_df" in st.session_state:
        st.write("DNS Results", st.session_state["dns_df"])

# WHOIS Lookup Tab
with tabs[2]:
    st.header("WHOIS Lookup")
    st.markdown("Retrieve domain registration details including registrant, registrar, creation date, expiration date, and name servers.")
    with st.form("whois_form"):
        domains_input: str = st.text_area("Enter one or more domains (one per line):", height=200, help="Example: example.com")
        submit_whois = st.form_submit_button("Run WHOIS Lookup")

    if submit_whois:
        if not domains_input.strip():
            st.error("Please enter at least one domain.")
        else:
            domains: List[str] = [line.strip() for line in domains_input.splitlines() if line.strip()]
            st.info("Starting WHOIS lookups...")
            whois_results = asyncio.run(run_whois_checks(domains))
            df_whois = pd.DataFrame(
                whois_results,
                columns=["Domain", "Registrant", "Registrar", "WHOIS Creation Date", "WHOIS Expiration Date", "Last Updated", "Name Servers"]
            )
            st.write("### WHOIS Lookup Results")
            st.caption("Double click any cell in the table to view its full content.")
            st.write(df_whois)
            st.session_state["whois_df"] = df_whois
            date_str = datetime.datetime.now().strftime("%d.%m.%Y")
            st.download_button("Download Table as CSV", df_whois.to_csv(index=False),
                               file_name=f"WHOIS_Results_{date_str}.csv", mime="text/csv")
    elif "whois_df" in st.session_state:
        st.write("### WHOIS Lookup Results", st.session_state["whois_df"])

# TLS/SSL Certificate Check Tab
with tabs[3]:
    st.header("TLS/SSL Certificate Check")
    st.markdown("Perform a TLS/SSL certificate check for each domain. This check returns the certificate expiry date and the number of days until expiry.")
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
            st.write("### TLS/SSL Certificate Check Results")
            st.caption("Double click any cell in the table to view its full content.")
            st.write(df_cert)
            st.session_state["cert_df"] = df_cert
            date_str = datetime.datetime.now().strftime("%d.%m.%Y")
            st.download_button("Download Table as CSV", df_cert.to_csv(index=False),
                               file_name=f"TLS_SSL_Certificate_Results_{date_str}.csv", mime="text/csv")
    elif "cert_df" in st.session_state:
        st.write("### TLS/SSL Certificate Check Results", st.session_state["cert_df"])

# Subdomain Finder Tab
with tabs[4]:
    st.header("Subdomain Finder")
    st.write("Search crt.sh for subdomains of a given domain and perform HTTP checks to determine if they are online.")
    domain_input: str = st.text_input("Enter a naked domain (e.g. example.com):", help="Do not include www or subdomains.")
    import streamlit.components.v1 as components
    components.html(
        """
        <script>
        const input = window.parent.document.querySelector('input[aria-label="Enter a naked domain (e.g. example.com):"]');
        if(input){
            input.addEventListener('keydown', function(e) {
                if(e.ctrlKey && e.key === "Enter"){
                    const btn = window.parent.document.querySelector('button[data-baseweb="button"]');
                    if(btn){ btn.click(); }
                }
            });
        }
        </script>
        """,
        height=0
    )
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
                            if sub == domain_input or sub.endswith("." + domain_input):
                                subdomains.add(sub)
                    subdomain_list: List[str] = list(subdomains)
                    st.write(f"Found {len(subdomain_list)} unique subdomains.")

                    progress_bar = st.progress(0)
                    def update_progress(value: float) -> None:
                        progress_bar.progress(value)
                    results = asyncio.run(perform_http_checks(subdomain_list, update_progress))

                    online_results = [res for res in results if ((res.get("HTTP Status") is not None and isinstance(res.get("HTTP Status"), int) and res.get("HTTP Status") < 400) or (res.get("Redirected") == "Yes"))]
                    offline_results = [res for res in results if not (((res.get("HTTP Status") is not None and isinstance(res.get("HTTP Status"), int) and res.get("HTTP Status") < 400) or (res.get("Redirected") == "Yes")))]

                    st.session_state["subdomain_results"] = results
                    st.session_state["subdomain_online"] = online_results
                    st.session_state["subdomain_offline"] = offline_results
                    st.session_state["searched_domain"] = domain_input

                    st.subheader("Online Subdomains")
                    if online_results:
                        df_online = pd.DataFrame(online_results)
                        st.write(df_online)
                        date_str = datetime.datetime.now().strftime("%d.%m.%Y")
                        file_name_online = f"{domain_input}_online_subdomains_{date_str}.csv"
                        csv_online = df_online.to_csv(index=False).encode("utf-8")
                        st.download_button(
                            label="Download Online Subdomains as CSV",
                            data=csv_online,
                            file_name=file_name_online,
                            mime="text/csv"
                        )
                    else:
                        st.write("No online subdomains found.")

                    st.subheader("Offline Subdomains")
                    if offline_results:
                        df_offline = pd.DataFrame(offline_results)
                        st.write(df_offline)
                        date_str = datetime.datetime.now().strftime("%d.%m.%Y")
                        file_name_offline = f"{domain_input}_offline_subdomains_{date_str}.csv"
                        csv_offline = df_offline.to_csv(index=False).encode("utf-8")
                        st.download_button(
                            label="Download Offline Subdomains as CSV",
                            data=csv_offline,
                            file_name=file_name_offline,
                            mime="text/csv"
                        )
                    else:
                        st.write("No offline subdomains found.")
            except Exception as e:
                st.error(f"An error occurred: {e}")
    elif "subdomain_results" in st.session_state:
        st.write(f"Showing previously searched results for domain: {st.session_state['searched_domain']}")
        online_results = st.session_state["subdomain_online"]
        offline_results = st.session_state["subdomain_offline"]
        st.subheader("Online Subdomains")
        if online_results:
            df_online = pd.DataFrame(online_results)
            st.write(df_online)
            date_str = datetime.datetime.now().strftime("%d.%m.%Y")
            file_name_online = f"{st.session_state['searched_domain']}_online_subdomains_{date_str}.csv"
            csv_online = df_online.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="Download Online Subdomains as CSV",
                data=csv_online,
                file_name=file_name_online,
                mime="text/csv"
            )
        else:
            st.write("No online subdomains found.")
        st.subheader("Offline Subdomains")
        if offline_results:
            df_offline = pd.DataFrame(offline_results)
            st.write(df_offline)
            date_str = datetime.datetime.now().strftime("%d.%m.%Y")
            file_name_offline = f"{st.session_state['searched_domain']}_offline_subdomains_{date_str}.csv"
            csv_offline = df_offline.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="Download Offline Subdomains as CSV",
                data=csv_offline,
                file_name=file_name_offline,
                mime="text/csv"
            )
        else:
            st.write("No offline subdomains found.")

# Advanced Check Tab
with tabs[5]:
    st.header("Advanced Check")
    st.markdown("Combine HTTP, DNS, WHOIS, and TLS/SSL lookups into one comprehensive report.")
    with st.form("all_form"):
        domains_input_all: str = st.text_area("Enter one or more domains (one per line):", height=200, help="Example: example.com")
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
                columns.extend(["Registrant", "Registrar", "WHOIS Creation Date", "WHOIS Expiration Date", "Last Updated", "Name Servers"])
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
            st.write("### Advanced Check Results")
            st.caption("Double click any cell in the table to view its full content.")
            st.write(df_all)
            st.session_state["adv_df"] = df_all
            date_str = datetime.datetime.now().strftime("%d.%m.%Y")
            st.download_button("Download Table as CSV", df_all.to_csv(index=False),
                               file_name=f"Advanced_Check_Results_{date_str}.csv", mime="text/csv")
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

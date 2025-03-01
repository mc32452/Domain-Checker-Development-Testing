import asyncio
import aiohttp
import dns.asyncresolver
import pandas as pd
import ssl
import socket
import datetime
import time
from urllib.parse import urlparse
from crtsh import crtshAPI
from typing import List, Dict, Any, Optional, Callable, Union, Tuple
import whois
import streamlit as st
import plotly.express as px
import re

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

resolver = dns.asyncresolver.Resolver()
resolver.nameservers = ['8.8.8.8', '1.1.1.1']
resolver.timeout = 5
resolver.lifetime = 5
resolver.cache = None

# ------------------------------
# Domain Validation Function
# ------------------------------
def is_valid_domain(domain: str) -> bool:
    """Validate if the input is a proper domain name."""
    pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

# ------------------------------
# Helper Function for crt.sh with Retry Mechanism
# ------------------------------
def get_crtsh_data(domain: str, max_retries: int = 3) -> Optional[List[Dict[str, Any]]]:
    for attempt in range(max_retries):
        try:
            data = crtshAPI().search(domain)
            if data:
                return data
        except Exception as e:
            st.warning(f"crt.sh request attempt {attempt + 1} failed for domain {domain}: {e}")
        time.sleep(1.0)
    return None

# ------------------------------
# WHOIS Lookup Functions with RDAP Fallback
# ------------------------------
async def get_whois_info(domain: str, session: aiohttp.ClientSession) -> Dict[str, str]:
    rdap_url = f"https://rdap.ports.domains/domain/{domain}"
    fallback_used = False
    rdap_error = ""
    try:
        async with session.get(rdap_url, timeout=10) as response:
            if response.status != 200:
                rdap_error = f"HTTP error {response.status}"
                rdap_data = None
            else:
                rdap_data = await response.json()
    except Exception as e:
        rdap_data = None
        rdap_error = str(e)

    registrant_str = "Not Available"
    registrar_str = ""
    creation_date = ""
    expiration_date = ""
    updated_date = ""
    nameservers = ""

    if rdap_data:
        if "events" in rdap_data:
            for event in rdap_data["events"]:
                action = event.get("eventAction", "").lower()
                if action in ["registration", "created"] and not creation_date:
                    creation_date = event.get("eventDate", "")
                elif action in ["last updated", "updated"] and not updated_date:
                    updated_date = event.get("eventDate", "")
                elif action == "expiration" and not expiration_date:
                    expiration_date = event.get("eventDate", "")
        ns_list = []
        if "nameservers" in rdap_data:
            for ns in rdap_data["nameservers"]:
                ns_name = ns.get("ldhName", "")
                if ns_name:
                    ns_list.append(ns_name)
        nameservers = "\n".join(ns_list)

        if "entities" in rdap_data:
            for entity in rdap_data["entities"]:
                roles = entity.get("roles", [])
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

    key_missing = 0
    if registrant_str == "Not Available":
        key_missing += 1
    if not registrar_str:
        key_missing += 1
    if not creation_date:
        key_missing += 1

    if not rdap_data or key_missing >= 2:
        try:
            fallback_data = await asyncio.to_thread(whois.whois, domain)
            def format_date(dt):
                if isinstance(dt, list):
                    dt = dt[0] if dt else ""
                if hasattr(dt, "isoformat"):
                    return dt.isoformat()
                return str(dt) if dt else ""
            fallback_registrant = fallback_data.get("org") or fallback_data.get("name") or "Not Available"
            registrant_str = f"Registrant: {fallback_registrant}"
            registrar_str = fallback_data.get("registrar", "")
            creation_date = format_date(fallback_data.get("creation_date", ""))
            expiration_date = format_date(fallback_data.get("expiration_date", ""))
            updated_date = format_date(fallback_data.get("updated_date", ""))
            ns = fallback_data.get("name_servers", "")
            if isinstance(ns, list):
                nameservers = "\n".join(ns)
            else:
                nameservers = ns
            fallback_used = True
        except Exception as e:
            rdap_error += f" | Fallback error: {str(e)}"

    return {
        "registrant": registrant_str,
        "registrar": registrar_str,
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "updated_date": updated_date,
        "name_servers": nameservers,
        "error": "" if fallback_used else rdap_error
    }

async def run_whois_checks(domains: List[str]) -> List[Tuple[str, str, str, str, str, str, str]]:
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

async def is_domain_resolvable(domain: str) -> bool:
    try:
        await resolver.resolve(domain, 'A')
        return True
    except Exception:
        try:
            await resolver.resolve(domain, 'AAAA')
            return True
        except Exception:
            return False

async def check_tcp_connectivity(domain: str, port: int, timeout: int = 3) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(domain, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def check_http_domain(domain: str, timeout: int, retries: int, session: aiohttp.ClientSession, headers: Dict[str, str], semaphore: asyncio.Semaphore) -> Tuple[Any, ...]:
    if not await is_domain_resolvable(domain):
        return (domain, "DNS Error", "DNS resolution failed", 0, 0, "No", "No redirect", "No")

    protocols = []
    if domain.startswith("http://") or domain.startswith("https://"):
        protocols = [""]
    else:
        protocols = ["https://", "http://"]

    last_exception = None
    for protocol in protocols:
        url = protocol + domain if protocol else domain
        for attempt in range(1, retries + 1):
            start_time = time.perf_counter()
            try:
                async with semaphore:
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
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
                        return (domain, status, snippet, round(response_time, 2), attempt, "HTTP Success", redirect_info, redirected)
            except Exception as e:
                last_exception = e
                if "Header value is too long" in str(e):
                    try:
                        async with semaphore:
                            async with session.head(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout), allow_redirects=True) as head_response:
                                response_time = time.perf_counter() - start_time
                                if head_response.history:
                                    redirects = [str(resp.url) for resp in head_response.history] + [str(head_response.url)]
                                    redirect_info = " -> ".join(redirects)
                                    redirected = "Yes" if normalize_url(url) != normalize_url(str(head_response.url)) else "No"
                                else:
                                    redirect_info = "No redirect"
                                    redirected = "No"
                                tcp443 = await check_tcp_connectivity(domain, 443, timeout)
                                if tcp443:
                                    status = "HTTP Header Too Large"
                                    snippet = "Header value exceeded limit"
                                    response_received_str = "TCP: Received Response / HTTP: Header Too Large"
                                    return (domain, status, snippet, round(response_time, 2), attempt, response_received_str, redirect_info, redirected)
                    except Exception as head_e:
                        tcp443 = await check_tcp_connectivity(domain, 443, timeout)
                        if tcp443:
                            status = "HTTP Header Too Large"
                            snippet = "Header value exceeded limit"
                            response_received_str = "TCP: Received Response / HTTP: Header Too Large"
                            response_time = time.perf_counter() - start_time
                            return (domain, status, snippet, round(response_time, 2), attempt, response_received_str, "No redirect", "No")
                await asyncio.sleep(0.5 * (2 ** (attempt - 1)))

    start_time = time.perf_counter()
    tcp443 = await check_tcp_connectivity(domain, 443, timeout)
    tcp80 = await check_tcp_connectivity(domain, 80, timeout)
    response_time = time.perf_counter() - start_time
    tcp_status = "TCP Connection Successful" if (tcp443 or tcp80) else "TCP Connection Failed"
    status = f"{tcp_status} / HTTP Error: {str(last_exception)}"
    response_received_str = "TCP: Received Response / HTTP: No Response" if (tcp443 or tcp80) else "TCP: No Response / HTTP: No Response"
    return (domain, status, status, round(response_time, 2), retries, response_received_str, "No redirect", "No")

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
async def resolve_dns_record(domain: str, rtype: str) -> List[str]:
    try:
        answer = await resolver.resolve(domain, rtype)
        return [rdata.to_text() for rdata in answer]
    except dns.resolver.NoAnswer:
        return ["No records found"]
    except dns.resolver.NXDOMAIN:
        return ["Domain does not exist"]
    except dns.resolver.Timeout:
        return ["Lookup timed out"]
    except Exception as e:
        return [f"Error: {str(e)}"]

async def get_dns_record_for_domain(domain: str, record_types: List[str]) -> Tuple[str, Dict[str, Union[List[str], str]]]:
    if not domain or '.' not in domain:
        return domain, {rtype: "Invalid domain format" for rtype in record_types}
    records: Dict[str, Union[List[str], str]] = {}
    cname_result = await resolve_dns_record(domain, "CNAME")
    if cname_result and "No records found" not in cname_result:
        records["CNAME"] = cname_result
    for rtype in record_types:
        if rtype in ["A", "AAAA"]:
            if cname_result and "No records found" not in cname_result:
                target = cname_result[0].rstrip('.')
                record_list = await resolve_dns_record(target, rtype)
                record_list = [f"{rec} (Inherited from {target})" for rec in record_list]
            else:
                record_list = await resolve_dns_record(domain, rtype)
            records[rtype] = record_list if record_list else "No records found"
        elif rtype == "MX":
            mx_records = await resolve_dns_record(domain, rtype)
            if mx_records and "No records found" not in mx_records:
                records[rtype] = [f"Priority {rdata.split()[0]}: {rdata.split()[1]}" for rdata in mx_records]
            else:
                records[rtype] = "No records found"
        else:
            record_list = await resolve_dns_record(domain, rtype)
            records[rtype] = record_list if record_list else "No records found"
    if cname_result and "CNAME" not in record_types:
        records["CNAME_Inheritance"] = "Inherited from CNAME"
    return domain, records

async def get_recursive_dns_summary(domain: str, record_types: List[str]) -> str:
    summary_lines = []
    for rtype in record_types:
        chain = []
        current = domain
        while True:
            cname_result = await resolve_dns_record(current, "CNAME")
            if cname_result and "No records found" not in cname_result:
                cname_value = cname_result[0].rstrip('.')
                chain.append(f"CNAME: {cname_value} (from {current})")
                current = cname_value
            else:
                break
        records = await resolve_dns_record(current, rtype)
        if records and "No records found" not in records:
            chain.append(f"{rtype} Records (from {current}): {', '.join(records)}")
        else:
            chain.append(f"{rtype} Records: No records found")
        summary_lines.append(f"{rtype} Resolution:\n" + "\n".join([f"  - {line}" for line in chain]))
    return "\n\n".join(summary_lines)

async def run_dns_checks(domains: List[str], record_types: List[str],
                        recursive_dns: bool, progress_callback: Optional[Callable[[int, int], None]]) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    tasks = [get_dns_record_for_domain(domain, record_types) for domain in domains]
    total = len(tasks)
    completed = 0
    for task in asyncio.as_completed(tasks):
        domain, result = await task
        if recursive_dns:
            recursive_summary = await get_recursive_dns_summary(domain, record_types)
            result["Recursive DNS Resolution"] = recursive_summary
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

async def run_certificate_checks(domains: List[str]) -> List[Tuple[str, str, str, str]]:
    tasks = [process_certificate_check(domain) for domain in domains]
    results: List[Tuple[str, str, str, str]] = []
    total = len(tasks)
    progress_bar = st.progress(0)
    for i, task in enumerate(asyncio.as_completed(tasks), start=1):
        cert_expiry_date, days_until_expiry, cert_error = await task
        results.append((
            domains[i-1],
            cert_expiry_date if cert_expiry_date else "",
            str(days_until_expiry) if days_until_expiry is not None else "",
            cert_error
        ))
        progress_bar.progress(int((i / total) * 100))
    return results

# ------------------------------
# Wildcard DNS Check Function
# ------------------------------
async def check_wildcard_dns(domain: str, record_type: str = "A") -> str:
    random_sub = "wildcardtest" + str(int(time.time() * 1000)) + "." + domain
    try:
        await resolver.resolve(random_sub, record_type)
        return "Yes"
    except dns.resolver.NXDOMAIN:
        return "No"
    except Exception:
        return "No"

# ------------------------------
# Geolocation Function using freeIPAPI
# ------------------------------
async def get_geolocation(ip: str, session: aiohttp.ClientSession) -> Dict[str, Union[str, float]]:
    url = f"https://freeipapi.com/api/json/{ip}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
            if response.status == 200:
                data = await response.json()
                return {
                    "IP": ip,
                    "Country": data.get("countryName", "N/A"),
                    "City": data.get("cityName", "N/A"),
                    "Latitude": data.get("latitude", "N/A"),
                    "Longitude": data.get("longitude", "N/A"),
                }
            else:
                return {"IP": ip, "Error": f"HTTP {response.status}"}
    except Exception as e:
        return {"IP": ip, "Error": str(e)}

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
    geolocate_enabled: bool,
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
    result["Status"] = http_status
    result["HTTP Snippet"] = http_snippet
    result["HTTP Response Time (s)"] = http_response_time
    result["HTTP Attempts"] = http_attempts
    result["Response Received"] = http_response_received
    result["Redirect History"] = http_redirect_history
    result["Redirected"] = http_redirected
    if dns_record_types:
        dns_result = await get_dns_record_for_domain(domain, dns_record_types)
        dns_records = dns_result[1]
        dns_lines = ["DNS Records:"]
        for rtype, val in dns_records.items():
            if rtype == "CNAME_Inheritance":
                continue
            dns_lines.append(f"{rtype}:")
            if isinstance(val, list):
                for record in val:
                    dns_lines.append(f"  - {record}")
            else:
                dns_lines.append(f"  - {val}")
            if rtype == "SOA" and isinstance(val, str) and " " in val:
                soa_parts = val.split()
                if len(soa_parts) >= 5:
                    dns_lines[-1] = "  - Primary NS: " + soa_parts[0]
                    dns_lines.append(f"    Contact: {soa_parts[1]}")
                    dns_lines.append(f"    Serial: {soa_parts[2]}")
                    dns_lines.append(f"    Refresh: {soa_parts[3]}")
                    dns_lines.append(f"    Retry: {soa_parts[4]}")
                    if len(soa_parts) >= 6:
                        dns_lines.append(f"    Expire: {soa_parts[5]}")
                    if len(soa_parts) >= 7:
                        dns_lines.append(f"    Minimum TTL: {soa_parts[6]}")
        result["DNS Records"] = "\n".join(dns_lines)
        recursive_dns = await get_recursive_dns_summary(domain, dns_record_types)
        result["Recursive DNS Chain"] = recursive_dns

        if geolocate_enabled:
            ips = []
            for rtype in ["A", "AAAA"]:
                records = dns_records.get(rtype, [])
                if isinstance(records, list):
                    for record in records:
                        if record and record != "No records found":
                            ip = record.split()[0]
                            ips.append(ip)
            if ips:
                geolocation_tasks = [get_geolocation(ip, session) for ip in ips]
                geolocation_results = await asyncio.gather(*geolocation_tasks)
                result["Geolocation Data"] = [res for res in geolocation_results if "Error" not in res]
                geolocation_str = "\n".join(
                    [f"IP: {res['IP']} - Country: {res.get('Country', 'N/A')}, City: {res.get('City', 'N/A')}"
                     for res in result["Geolocation Data"]]
                )
                result["Geolocation"] = geolocation_str if geolocation_str else "No geolocation data available"
            else:
                result["Geolocation"] = "No IP addresses found"
                result["Geolocation Data"] = []

    if cert_enabled:
        cert_expiry_date, days_until_expiry, cert_error = await process_certificate_check(domain)
        result["Certificate Expiry Date"] = cert_expiry_date if cert_expiry_date else ""
        result["Days Until Expiry"] = days_until_expiry if days_until_expiry is not None else ""
        result["Certificate Error"] = cert_error
    if wildcard_enabled:
        wildcard = await check_wildcard_dns(domain)
        result["Wildcard DNS"] = wildcard
    return result

async def run_all_in_one_checks(
    domains: List[str],
    timeout: int,
    concurrency: int,
    retries: int,
    dns_record_types: List[str],
    whois_enabled: bool,
    cert_enabled: bool,
    wildcard_enabled: bool,
    geolocate_enabled: bool
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    semaphore = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession() as session:
        tasks = [
            process_all_in_one(domain, timeout, retries, dns_record_types, whois_enabled, cert_enabled, wildcard_enabled, geolocate_enabled, session, semaphore)
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
async def check_subdomain_advanced(
    session: aiohttp.ClientSession,
    subdomain: str,
    semaphore: asyncio.Semaphore,
    timeout: int = 3,
    retries: int = 3
) -> Dict[str, Any]:
    result = await check_http_domain(subdomain, timeout, retries, session, http_headers, semaphore)
    domain, status, snippet, response_time, attempts, response_received, redirect_history, redirected = result
    return {
        "Subdomain": domain,
        "Status": status,
        "HTTP Snippet": snippet,
        "Response Time (s)": response_time,
        "HTTP Attempts": attempts,
        "Response Received": response_received,
        "Redirect History": redirect_history,
        "Redirected": redirected,
    }

async def perform_http_checks(subdomain_list: List[str], progress_callback: Callable[[float], None], semaphore: asyncio.Semaphore) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    connector = aiohttp.TCPConnector(limit=100, ssl=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_subdomain_advanced(session, sub, semaphore) for sub in subdomain_list]
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

if "subdomain_results" not in st.session_state:
    st.session_state["subdomain_results"] = []
if "subdomain_online" not in st.session_state:
    st.session_state["subdomain_online"] = []
if "subdomain_flagged" not in st.session_state:
    st.session_state["subdomain_flagged"] = []
if "subdomain_offline" not in st.session_state:
    st.session_state["subdomain_offline"] = []
if "searched_domain" not in st.session_state:
    st.session_state["searched_domain"] = ""

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
    st.markdown("Retrieve HTTP status code, response snippet, response time, and redirection details.")
    with st.form("http_form"):
        domains_input_http: str = st.text_area("Enter one or more domains (one per line):", height=200, help="Example: example.com")
        timeout: int = st.number_input("Timeout (seconds)", min_value=1, value=10, step=1)
        concurrency: int = st.number_input("Concurrency", min_value=1, value=20, step=1)
        retries: int = st.number_input("Retries", min_value=1, value=3, step=1)
        submit_http = st.form_submit_button("Run HTTP Check")

    if submit_http:
        if not domains_input_http.strip():
            st.error("Please enter at least one domain.")
        else:
            domains_http: List[str] = [line.strip() for line in domains_input_http.splitlines() if line.strip()]
            invalid_domains = [d for d in domains_http if not is_valid_domain(d)]
            if invalid_domains:
                st.warning(f"Invalid domains skipped: {', '.join(invalid_domains)}")
            domains_http = [d for d in domains_http if is_valid_domain(d)]
            if not domains_http:
                st.error("No valid domains to process.")
            else:
                st.info("Starting HTTP checks...")
                http_results = asyncio.run(run_http_checks(domains_http, timeout, concurrency, retries))
                df_http = pd.DataFrame(
                    http_results,
                    columns=["Domain", "Status", "HTTP Snippet", "HTTP Response Time (s)",
                             "HTTP Attempts", "Response Received", "Redirect History", "Redirected"]
                )
                df_http["Status"] = df_http["Status"].astype(str)
                st.write("### HTTP Check Results")
                st.caption("Double click any cell to view full content.")
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
    st.markdown("Perform DNS record lookups for specified domain(s).")
    with st.form("dns_form"):
        domains_input_dns: str = st.text_area("Enter one or more domains (one per line):", height=150, help="Example: example.com")
        recursive_dns = st.checkbox("Enable Recursive DNS Lookup", value=False)
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
        st.session_state.pop("dns_df", None)
        if not domains_input_dns.strip():
            st.error("Please enter at least one domain.")
        elif not selected_record_types:
            st.error("Please select at least one DNS record type.")
        else:
            domains_dns: List[str] = [line.strip() for line in domains_input_dns.splitlines() if line.strip()]
            invalid_domains = [d for d in domains_dns if not is_valid_domain(d)]
            if invalid_domains:
                st.warning(f"Invalid domains skipped: {', '.join(invalid_domains)}")
            domains_dns = [d for d in domains_dns if is_valid_domain(d)]
            if not domains_dns:
                st.error("No valid domains to process.")
            else:
                total_domains = len(domains_dns)
                st.write(f"Processing **{total_domains}** domain(s)...")
                progress_bar = st.progress(0)
                def progress_callback(completed: int, total: int) -> None:
                    progress_bar.progress(int((completed / total) * 100))
                start_time = time.time()
                dns_results = asyncio.run(run_dns_checks(domains_dns, selected_record_types, recursive_dns, progress_callback))
                end_time = time.time()
                elapsed_time = end_time - start_time
                data_rows = []
                for domain, recs in dns_results.items():
                    row = {"Domain": domain}
                    for rtype in selected_record_types:
                        val = recs.get(rtype, "")
                        if isinstance(val, list):
                            val = "\n".join(val)
                        row[rtype] = val
                    if "CNAME_Inheritance" in recs:
                        row["CNAME_Inheritance"] = recs["CNAME_Inheritance"]
                    if recursive_dns:
                        row["Recursive DNS Resolution"] = recs.get("Recursive DNS Resolution", "")
                    data_rows.append(row)
                df_dns = pd.DataFrame(data_rows)
                st.write("### DNS Results")
                st.caption("Double click any cell to view full content.")
                st.write(df_dns)
                st.session_state["dns_df"] = df_dns
                date_str = datetime.datetime.now().strftime("%d.%m.%Y")
                csv_data = df_dns.to_csv(index=False)
                st.download_button("Download Table as CSV", data=csv_data,
                                   file_name=f"DNS_Lookup_Results_{date_str}.csv", mime="text/csv")
                with st.expander("View Statistics"):
                    st.write(f"**Time Taken:** {elapsed_time:.2f} seconds")
                    st.write(f"**Processing Speed:** {total_domains / elapsed_time:.2f} domains/second")
    elif "dns_df" in st.session_state:
        st.write("### DNS Results", st.session_state["dns_df"])

# WHOIS Lookup Tab
with tabs[2]:
    st.header("WHOIS Lookup")
    st.markdown("Retrieve domain registration details.")
    with st.form("whois_form"):
        domains_input: str = st.text_area("Enter one or more domains (one per line):", height=200, help="Example: example.com")
        submit_whois = st.form_submit_button("Run WHOIS Lookup")

    if submit_whois:
        if not domains_input.strip():
            st.error("Please enter at least one domain.")
        else:
            domains: List[str] = [line.strip() for line in domains_input.splitlines() if line.strip()]
            invalid_domains = [d for d in domains if not is_valid_domain(d)]
            if invalid_domains:
                st.warning(f"Invalid domains skipped: {', '.join(invalid_domains)}")
            domains = [d for d in domains if is_valid_domain(d)]
            if not domains:
                st.error("No valid domains to process.")
            else:
                st.info("Starting WHOIS lookups...")
                whois_results = asyncio.run(run_whois_checks(domains))
                df_whois = pd.DataFrame(
                    whois_results,
                    columns=["Domain", "Registrant", "Registrar", "WHOIS Creation Date", "WHOIS Expiration Date", "Last Updated", "Name Servers"]
                )
                st.write("### WHOIS Lookup Results")
                st.caption("Double click any cell to view full content.")
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
    st.markdown("Perform a TLS/SSL certificate check.")
    with st.form("cert_form"):
        domains_input_cert: str = st.text_area("Enter one or more domains (one per line):", height=200, help="Example: example.com")
        submit_cert = st.form_submit_button("Run TLS/SSL Certificate Check")

    if submit_cert:
        if not domains_input_cert.strip():
            st.error("Please enter at least one domain.")
        else:
            domains_cert: List[str] = [line.strip() for line in domains_input_cert.splitlines() if line.strip()]
            invalid_domains = [d for d in domains_cert if not is_valid_domain(d)]
            if invalid_domains:
                st.warning(f"Invalid domains skipped: {', '.join(invalid_domains)}")
            domains_cert = [d for d in domains_cert if is_valid_domain(d)]
            if not domains_cert:
                st.error("No valid domains to process.")
            else:
                st.info("Starting TLS/SSL Certificate Check...")
                cert_results = asyncio.run(run_certificate_checks(domains_cert))
                df_cert = pd.DataFrame(
                    cert_results,
                    columns=["Domain", "Certificate Expiry Date", "Days Until Expiry", "Certificate Error"]
                )
                if "Certificate Error" in df_cert.columns and df_cert["Certificate Error"].astype(str).str.strip().eq("").all():
                    df_cert.drop(columns=["Certificate Error"], inplace=True)
                st.write("### TLS/SSL Certificate Check Results")
                st.caption("Double click any cell to view full content.")
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
    st.write("Extracts subdomains from crt.sh and checks them via HTTP.")
    st.caption("Relies on crt.sh API, which may have downtime.")
    with st.form("subdomain_form"):
        domain_input: str = st.text_input("Enter a naked domain (e.g. example.com):", help="No www or subdomains.")
        submit_subdomain = st.form_submit_button("Search")

    if submit_subdomain:
        if not domain_input:
            st.error("Please enter a domain.")
        elif not is_valid_domain(domain_input):
            st.error("Please enter a valid domain (e.g., example.com).")
        else:
            with st.spinner(text=f"Searching for subdomains of {domain_input}..."):
                try:
                    data = get_crtsh_data(domain_input, max_retries=3)
                    if not data:
                        st.error("crt.sh request failed. No records or API unavailable.")
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
                        semaphore = asyncio.Semaphore(20)
                        results = asyncio.run(perform_http_checks(subdomain_list, update_progress, semaphore))

                        online_results = [
                            res for res in results
                            if ((res.get("Status") is not None and isinstance(res.get("Status"), int) and (res.get("Status") < 400 or res.get("Status") == 401))
                                or res.get("Redirected") == "Yes"
                                or res.get("Status") == "HTTP Header Too Large")
                        ]
                        offline_candidates = [res for res in results if res not in online_results]
                        flagged_unreachable = [res for res in offline_candidates if res.get("Status") != "DNS Error"]
                        offline_results = [res for res in offline_candidates if res.get("Status") == "DNS Error"]

                        st.session_state["subdomain_results"] = results
                        st.session_state["subdomain_online"] = online_results
                        st.session_state["subdomain_flagged"] = flagged_unreachable
                        st.session_state["subdomain_offline"] = offline_results
                        st.session_state["searched_domain"] = domain_input

                        date_str = datetime.datetime.now().strftime("%d.%m.%Y")
                        df_all_subdomains = pd.DataFrame(results)
                        st.download_button(
                            label="Download All Subdomain Results as CSV",
                            data=df_all_subdomains.to_csv(index=False).encode("utf-8"),
                            file_name=f"{domain_input}_all_subdomains_{date_str}.csv",
                            mime="text/csv"
                        )

                        st.subheader("Online Subdomains")
                        if online_results:
                            df_online = pd.DataFrame(online_results)
                            st.write(df_online)
                            st.download_button(
                                label="Download Online Subdomains as CSV",
                                data=df_online.to_csv(index=False).encode("utf-8"),
                                file_name=f"{domain_input}_online_subdomains_{date_str}.csv",
                                mime="text/csv"
                            )
                        else:
                            st.write("No online subdomains found.")

                        st.subheader("Flagged/Unreachable Subdomains")
                        if flagged_unreachable:
                            df_flagged = pd.DataFrame(flagged_unreachable)
                            st.write(df_flagged)
                            st.download_button(
                                label="Download Flagged/Unreachable Subdomains as CSV",
                                data=df_flagged.to_csv(index=False).encode("utf-8"),
                                file_name=f"{domain_input}_flagged_unreachable_subdomains_{date_str}.csv",
                                mime="text/csv"
                            )
                        else:
                            st.write("No flagged/unreachable subdomains found.")

                        st.subheader("Offline Subdomains")
                        if offline_results:
                            df_offline = pd.DataFrame(offline_results)
                            st.write(df_offline)
                            st.download_button(
                                label="Download Offline Subdomains as CSV",
                                data=df_offline.to_csv(index=False).encode("utf-8"),
                                file_name=f"{domain_input}_offline_subdomains_{date_str}.csv",
                                mime="text/csv"
                            )
                        else:
                            st.write("No offline subdomains found.")

                        with st.expander("Graphs"):
                            status_counts = {
                                "Online": len(st.session_state["subdomain_online"]),
                                "Flagged/Unreachable": len(st.session_state["subdomain_flagged"]),
                                "Offline": len(st.session_state["subdomain_offline"])
                            }
                            if sum(status_counts.values()) > 0:
                                fig_pie = px.pie(
                                    names=list(status_counts.keys()),
                                    values=list(status_counts.values()),
                                    title="Subdomain Status Distribution"
                                )
                                st.plotly_chart(fig_pie, use_container_width=True)
                            else:
                                st.write("No subdomain data available for pie chart.")

                            if st.session_state["subdomain_online"]:
                                online_subdomains = [res["Subdomain"] for res in st.session_state["subdomain_online"]]
                                response_times = [res["Response Time (s)"] for res in st.session_state["subdomain_online"]]
                                fig_bar = px.bar(
                                    x=online_subdomains,
                                    y=response_times,
                                    title="Response Times for Online Subdomains",
                                    labels={"x": "Subdomain", "y": "Response Time (s)"}
                                )
                                st.plotly_chart(fig_bar, use_container_width=True)
                            else:
                                st.write("No online subdomains to display response times.")
                except Exception as e:
                    st.error(f"An error occurred: {e}")
    elif st.session_state.get("searched_domain", ""):
        st.write(f"Showing results for: {st.session_state['searched_domain']}")
        online_results = st.session_state["subdomain_online"]
        flagged_unreachable = st.session_state["subdomain_flagged"]
        offline_results = st.session_state["subdomain_offline"]

        st.subheader("Online Subdomains")
        if online_results:
            df_online = pd.DataFrame(online_results)
            st.write(df_online)
            date_str = datetime.datetime.now().strftime("%d.%m.%Y")
            st.download_button(
                label="Download Online Subdomains as CSV",
                data=df_online.to_csv(index=False).encode("utf-8"),
                file_name=f"{st.session_state['searched_domain']}_online_subdomains_{date_str}.csv",
                mime="text/csv"
            )
        else:
            st.write("No online subdomains found.")

        st.subheader("Flagged/Unreachable Subdomains")
        if flagged_unreachable:
            df_flagged = pd.DataFrame(flagged_unreachable)
            st.write(df_flagged)
            date_str = datetime.datetime.now().strftime("%d.%m.%Y")
            st.download_button(
                label="Download Flagged/Unreachable Subdomains as CSV",
                data=df_flagged.to_csv(index=False).encode("utf-8"),
                file_name=f"{st.session_state['searched_domain']}_flagged_unreachable_subdomains_{date_str}.csv",
                mime="text/csv"
            )
        else:
            st.write("No flagged/unreachable subdomains found.")

        st.subheader("Offline Subdomains")
        if offline_results:
            df_offline = pd.DataFrame(offline_results)
            st.write(df_offline)
            date_str = datetime.datetime.now().strftime("%d.%m.%Y")
            st.download_button(
                label="Download Offline Subdomains as CSV",
                data=df_offline.to_csv(index=False).encode("utf-8"),
                file_name=f"{st.session_state['searched_domain']}_offline_subdomains_{date_str}.csv",
                mime="text/csv"
            )
        else:
            st.write("No offline subdomains found.")

        with st.expander("Graphs"):
            status_counts = {
                "Online": len(st.session_state["subdomain_online"]),
                "Flagged/Unreachable": len(st.session_state["subdomain_flagged"]),
                "Offline": len(st.session_state["subdomain_offline"])
            }
            if sum(status_counts.values()) > 0:
                fig_pie = px.pie(
                    names=list(status_counts.keys()),
                    values=list(status_counts.values()),
                    title="Subdomain Status Distribution"
                )
                st.plotly_chart(fig_pie, use_container_width=True)
            else:
                st.write("No subdomain data available for pie chart.")

            if st.session_state["subdomain_online"]:
                online_subdomains = [res["Subdomain"] for res in st.session_state["subdomain_online"]]
                response_times = [res["Response Time (s)"] for res in st.session_state["subdomain_online"]]
                fig_bar = px.bar(
                    x=online_subdomains,
                    y=response_times,
                    title="Response Times for Online Subdomains",
                    labels={"x": "Subdomain", "y": "Response Time (s)"}
                )
                st.plotly_chart(fig_bar, use_container_width=True)
            else:
                st.write("No online subdomains to display response times.")

# Advanced Check Tab
with tabs[5]:
    st.header("Advanced Check")
    st.markdown("Combine HTTP, DNS, WHOIS, and TLS/SSL lookups.")
    st.info("**Note:** If you have caching issues, CTRL/CMD + Shift + R to clear all domain cache.")
    with st.form("all_form"):
        domains_input_all: str = st.text_area("Enter one or more domains (one per line):", height=200, help="Example: example.com")
        wildcard_enabled: bool = st.checkbox("Check for Wildcard DNS", value=False)
        whois_enabled: bool = st.checkbox("Enable WHOIS Lookup", value=False)
        cert_enabled: bool = st.checkbox("Enable TLS/SSL Certificate Check", value=False)
        geolocate_enabled: bool = st.checkbox("Enable IP Geolocation", value=False)
        st.caption("Note: 60 requests per minute limit for IP Geolocation")
        st.markdown("### Select DNS Record Types")
        record_options_all: List[str] = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]
        selected_dns_all: List[str] = []
        cols = st.columns(4)
        for i, rtype in enumerate(record_options_all):
            col = cols[i % 4]
            if col.checkbox(rtype, value=True, key=f"all_checkbox_{rtype}"):
                selected_dns_all.append(rtype)
        timeout_all: int = st.number_input("HTTP Timeout (seconds)", min_value=1, value=10, step=1)
        concurrency_all: int = st.number_input("HTTP Concurrency", min_value=1, value=20, step=1)
        retries_all: int = st.number_input("HTTP Retries", min_value=1, value=3, step=1)
        submit_all = st.form_submit_button("Run Advanced Check")

    if submit_all:
        if not domains_input_all.strip():
            st.error("Please enter at least one domain.")
        else:
            domains_all: List[str] = [line.strip() for line in domains_input_all.splitlines() if line.strip()]
            invalid_domains = [d for d in domains_all if not is_valid_domain(d)]
            if invalid_domains:
                st.warning(f"Invalid domains skipped: {', '.join(invalid_domains)}")
            domains_all = [d for d in domains_all if is_valid_domain(d)]
            if not domains_all:
                st.error("No valid domains to process.")
            else:
                enabled_checks = "HTTP"
                if whois_enabled:
                    enabled_checks += ", WHOIS"
                if selected_dns_all:
                    enabled_checks += ", DNS"
                if cert_enabled:
                    enabled_checks += ", TLS/SSL Certificate Check"
                if wildcard_enabled:
                    enabled_checks += ", Wildcard DNS Check"
                if geolocate_enabled:
                    enabled_checks += ", IP Geolocation"
                st.info(f"Starting All In One checks ({enabled_checks})...")
                start_time_all = time.time()
                all_results = asyncio.run(
                    run_all_in_one_checks(domains_all, timeout_all, concurrency_all, retries_all, selected_dns_all, whois_enabled, cert_enabled, wildcard_enabled, geolocate_enabled)
                )
                end_time_all = time.time()
                elapsed_all = end_time_all - start_time_all
                st.write(f"**Total Time Taken:** {elapsed_all:.2f} seconds")
                columns: List[str] = ["Domain", "Status"]
                if cert_enabled:
                    columns.extend(["Certificate Expiry Date", "Days Until Expiry"])
                if selected_dns_all:
                    columns.extend(["DNS Records", "Recursive DNS Chain"])
                if whois_enabled:
                    columns.extend(["Registrant", "Registrar", "WHOIS Creation Date", "WHOIS Expiration Date", "Last Updated", "Name Servers"])
                if wildcard_enabled:
                    columns.append("Wildcard DNS")
                if geolocate_enabled:
                    columns.append("Geolocation")
                columns.extend(["HTTP Response Time (s)", "HTTP Attempts", "Response Received", "Redirected", "Redirect History", "HTTP Snippet"])
                if whois_enabled:
                    columns.append("WHOIS Error")
                if cert_enabled:
                    columns.append("Certificate Error")
                df_all = pd.DataFrame(all_results)
                df_all = df_all[[col for col in columns if col in df_all.columns]]
                if "Status" in df_all.columns:
                    df_all["Status"] = df_all["Status"].astype(str)
                if "WHOIS Error" in df_all.columns and df_all["WHOIS Error"].astype(str).str.strip().eq("").all():
                    df_all.drop(columns=["WHOIS Error"], inplace=True)
                if "Certificate Error" in df_all.columns and df_all["Certificate Error"].astype(str).str.strip().eq("").all():
                    df_all.drop(columns=["Certificate Error"], inplace=True)
                st.write("### Advanced Check Results")
                st.caption("Double click any cell to view full content.")
                st.write(df_all)
                st.session_state["adv_df"] = df_all
                date_str = datetime.datetime.now().strftime("%d.%m.%Y")
                st.download_button("Download Table as CSV", df_all.to_csv(index=False),
                                   file_name=f"Advanced_Check_Results_{date_str}.csv", mime="text/csv")
                if geolocate_enabled:
                    with st.expander("View Geolocation Map", expanded=False):
                        all_geo_data = []
                        for res in all_results:
                            geo_data = res.get("Geolocation Data", [])
                            for geo in geo_data:
                                lat = geo.get("Latitude")
                                lon = geo.get("Longitude")
                                if lat != "N/A" and lon != "N/A":
                                    try:
                                        all_geo_data.append({"lat": float(lat), "lon": float(lon)})
                                    except (ValueError, TypeError):
                                        pass
                        if all_geo_data:
                            df_geo = pd.DataFrame(all_geo_data)
                            st.map(df_geo)
                        else:
                            st.write("No geolocation data available for mapping.")
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
                    st.write(f"The **fastest** response was from {fastest_domains[0]} taking {min_time:.2f} seconds.")
                if slowest_domains:
                    st.write(f"The **slowest** response was from {slowest_domains[0]} taking {max_time:.2f} seconds.")
                st.write(f"**Speed per Domain:** {speed:.2f} domains per second")
            else:
                st.write("No HTTP response times available.")

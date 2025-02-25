# Domain Checker

**Domain Checker** is a powerful, web-based tool built with Streamlit that enables users to perform a variety of domain-related checks, including HTTP status verification, DNS record lookups, WHOIS information retrieval, TLS/SSL certificate validation, subdomain discovery, and an advanced combined analysis. Designed for accessibility and efficiency, this application provides an intuitive interface for both casual users and developers to monitor and analyze domain health and configuration.

---

## Table of Contents

- [Features](#features)
- [Usage](#usage)
  - [HTTP Check](#http-check)
  - [DNS Lookup](#dns-lookup)
  - [WHOIS Lookup](#whois-lookup)
  - [TLS/SSL Certificate Check](#tlsssl-certificate-check)
  - [Subdomain Finder](#subdomain-finder)
  - [Advanced Check](#advanced-check)
- [Visualizations](#visualizations)
- [Technical Details](#technical-details)
- [Known Issues and Limitations](#known-issues-and-limitations)

---

## Features

- **HTTP Check**: Assess website availability with HTTP status codes, response times, snippets, and redirection details.
- **DNS Lookup**: Query DNS records (A, AAAA, CNAME, MX, NS, SOA, TXT) with optional recursive resolution.
- **WHOIS Lookup**: Fetch domain registration details such as registrant, registrar, and expiration dates.
- **TLS/SSL Certificate Check**: Validate certificate expiry and calculate remaining days.
- **Subdomain Finder**: Identify subdomains via crt.sh and check their HTTP status.
- **Advanced Check**: Combine HTTP, DNS, WHOIS, and TLS/SSL checks into a single detailed report.
- **Interactive Visualizations**: View subdomain status and response time distributions with pie and bar charts.
- **Asynchronous Processing**: Leverage asynchronous operations for fast, concurrent domain checks.
- **User-Friendly Interface**: Built with Streamlit for an interactive and streamlined experience.

---

## Usage

The Domain Checker interface is organized into six tabs, each dedicated to a specific function. Here’s how to use each one:

### HTTP Check

- **Purpose**: Verify website availability and performance.
- **Input**:
  - Enter one or more domain names (e.g., `example.com`), one per line.
  - Adjust optional settings like timeout, concurrency, and retry attempts.
- **Output**:
  - A table with columns: domain, HTTP status, response snippet, response time, attempts, response received, redirect history, and redirection status.
  - Downloadable CSV file option.

### DNS Lookup

- **Purpose**: Retrieve DNS records for specified types.
- **Input**:
  - Enter one or more domain names.
  - Choose record types (A, AAAA, CNAME, MX, NS, SOA, TXT).
  - Toggle recursive DNS lookup for resolution chain details.
- **Output**:
  - A table displaying domain and DNS records.
  - Recursive lookup results (if enabled) in an additional column.
  - Downloadable CSV file option.

### WHOIS Lookup

- **Purpose**: Access domain registration information.
- **Input**:
  - Enter one or more domain names.
- **Output**:
  - A table with domain, registrant, registrar, creation date, expiration date, last updated, and name servers.
  - Downloadable CSV file option.

### TLS/SSL Certificate Check

- **Purpose**: Inspect TLS/SSL certificate validity.
- **Input**:
  - Enter one or more domain names.
- **Output**:
  - A table showing domain, certificate expiry date, days until expiry, and errors (if any).
  - Downloadable CSV file option.

### Subdomain Finder

- **Purpose**: Discover and check subdomains.
- **Input**:
  - Enter a naked domain (e.g., `example.com`).
- **Output**:
  - Lists of online, flagged/unreachable, and offline subdomains with HTTP check details.
  - Interactive pie chart of subdomain status distribution.
  - Bar chart of response times for online subdomains.
  - Downloadable CSV files for each category.

### Advanced Check

- **Purpose**: Perform a multi-faceted domain analysis.
- **Input**:
  - Enter one or more domain names.
  - Enable optional checks: WHOIS, TLS/SSL, wildcard DNS.
  - Select DNS record types (if DNS is included).
- **Output**:
  - A comprehensive table combining results from selected checks.
  - Downloadable CSV file option.

---

## Visualizations

The **Subdomain Finder** tab offers interactive charts for quick insights:

- **Pie Chart**: Illustrates the distribution of subdomain statuses (Online, Flagged/Unreachable, Offline).
- **Bar Chart**: Displays response times for online subdomains.

These visualizations, powered by Plotly, are accessible under a "Graphs" expander in the tab.

---

## Technical Details

- **Asynchronous Programming**: Utilizes `asyncio` and `aiohttp` for concurrent, non-blocking HTTP and DNS operations, optimizing performance for multiple domains.
- **Error Handling**: Implements try-except blocks and fallbacks (e.g., WHOIS when RDAP fails) for reliability.
- **Modular Design**: Organized into functions per check type for maintainability and scalability.
- **Type Hints**: Includes type annotations for improved code clarity.
- **External Dependencies**: Relies on services like crt.sh (subdomains) and RDAP/WHOIS (registration data), subject to external constraints.

---

## Known Issues and Limitations

- **External Service Reliance**: Dependent on third-party services (crt.sh, RDAP, WHOIS), which may impose rate limits or experience downtime.
- **WHOIS Fallback**: Falls back to WHOIS if RDAP fails, potentially yielding inconsistent data formats.
- **Certificate Checks**: Requires port 443 connectivity; domains without HTTPS or with misconfigured certificates may fail.

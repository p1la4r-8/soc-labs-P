#!/usr/bin/env python3
"""
IoC Threat Intelligence Enricher
Author: SOC Analyst Lab
"""

import sys
import json
import ipaddress
import requests

# CONFIGURATION: API Endpoint & Key placeholder
API_KEY = "YOUR_ABUSEIPB_API_KEY"
API_URL = "https://api.abuseipdb.com/api/v2/check"

def is_valid_ip(ip_str):
    """Validates if the string is a properly formatted IPv4 address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def check_ip_reputation(ip_address):
    """Queries Threat Intelligence API for telemetry."""
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }

    try:
        response = requests.get(API_URL, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            return response.json().get('data', {})
        elif response.status_code == 401:
            print(f"[!] Warning: Unauthorized/No API key for {ip_address}. Running simulation mode.")
            return None
        else:
            print(f"[!] HTTP Error {response.status_code} for IP {ip_address}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[!] Network error checking {ip_address}: {e}")
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ioc_enricher.py <path_to_ioc_file>")
        print("Example: python3 ioc_enricher.py iocs_example.txt")
        sys.exit(1)

    input_file = sys.argv[1]
    output_filename = "enriched_iocs.json"

    print("=" * 60)
    print("SOC tool: Automated IOC Enricher & Threat Intel")
    print("=" * 60)

    try:
        with open(input_file, 'r') as file:
            iocs = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"[!] Error: file '{input_file}' not found.")
        sys.exit(1)

    enriched_results = []

    for ioc in iocs:
        if not is_valid_ip(ioc):
            print(f"Skipping invalid IP format: {ioc}")
            continue

        print(f"[*] Querying Threat Intel for: {ioc}...")
        data = check_ip_reputation(ioc)

        if data:
            abuse_score = data.get('abuseConfidenceScore', 0)
            country = data.get('countryCode', 'Unknown')
            isp = data.get('isp', 'Unknown')
            domain = data.get('domain', 'N/A')

            risk_level = "HIGH" if abuse_score > 50 else ("MEDIUM" if abuse_score > 20 else "LOW")
            print(f" Status: [{risk_level}] Abuse score: {abuse_score}% | Country: {country} | ISP: {isp}")

            enriched_results.append({
                'ip': ioc,
                'risk_level': risk_level,
                'abuse_score': abuse_score,
                'country': country,
                'isp': isp,
                'domain': domain,
            })
        else:
            # Fallback local display if no API key is provided yet
            print(f" Status: [PROCESSED] IP Format Validated | Ready for Threat Intel Query")
            enriched_results.append({
                'ip': ioc,
                'status': 'validated',
                'note': 'Requires active API key for full enrichment'
            })

    # Save output to JSON
    try:
        with open(output_filename, 'w') as out_file:
            json.dump(enriched_results, out_file, indent=4)
        print("\n" + "=" * 60)
        print(f"[+] Enrichment process finished. Report saved to: {output_filename}")
        print("=" * 60)
    except IOError as e:
        print(f"[!] Error saving output file: {e}")

if __name__ == "__main__":
    main()

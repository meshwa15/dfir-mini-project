#!/usr/bin/env python3
"""
extract_cridex_artifacts.py
Performs targeted extraction of Cridex Trojan indicators directly from the memory dump:
1. Locates in-memory HTTP C2 check-in requests and extracts host, port, URI, and headers.
2. Extracts and normalizes the financial institution WebInject target URL patterns.
3. Outputs structured analysis data to results/endpoint/cridex_extracted_config.json.
"""

import sys
import os
import re
import json

def extract_c2_telemetry(memory_file_path):
    """Scans physical memory for Cridex HTTP POST check-ins."""
    print(f"[*] Scanning {memory_file_path} for C2 network streams...")
    c2_records = []
    post_marker = b"POST /zb/v_01_a/in/"
    
    with open(memory_file_path, "rb") as f:
        data = f.read()
        idx = data.find(post_marker)
        while idx != -1:
            header_end = data.find(b"\r\n\r\n", idx)
            if header_end != -1:
                header_raw = data[idx:header_end].decode("latin1", errors="replace")
                headers = {}
                for line in header_raw.split("\r\n")[1:]:
                    if ": " in line:
                        k, v = line.split(": ", 1)
                        headers[k.strip()] = v.strip()
                
                content_length = int(headers.get("Content-Length", 0))
                payload_offset = header_end + 4
                raw_payload = data[payload_offset:payload_offset + content_length]
                
                record = {
                    "memory_offset_hex": hex(idx),
                    "request_line": header_raw.split("\r\n")[0],
                    "c2_host": headers.get("Host", ""),
                    "user_agent": headers.get("User-Agent", ""),
                    "content_length": content_length,
                    "payload_preview_hex": raw_payload[:32].hex() if raw_payload else ""
                }
                c2_records.append(record)
            idx = data.find(post_marker, idx + 1)
            
    print(f"[+] Discovered {len(c2_records)} C2 telemetry stream(s).")
    return c2_records

def extract_webinject_targets(subkeys_file_path):
    """Extracts targeted banking URLs from the parsed WSH registry output."""
    if not os.path.exists(subkeys_file_path):
        print(f"[!] Subkeys file not found: {subkeys_file_path}")
        return []
    
    print(f"[*] Parsing WebInject target patterns from {subkeys_file_path}...")
    targets = set()
    url_pattern = re.compile(r"\*([a-zA-Z0-9\.\-_/]+)\*")
    
    with open(subkeys_file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            matches = url_pattern.findall(line)
            for m in matches:
                if "." in m and not m.startswith("0") and len(m) > 4:
                    targets.add(f"*{m}*")
                    
    sorted_targets = sorted(list(targets))
    print(f"[+] Extracted {len(sorted_targets)} unique financial WebInject URL pattern(s).")
    return sorted_targets

def main():
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    vmem_path = os.path.join(project_root, "evidence", "originals", "cridex.vmem")
    subkeys_path = os.path.join(project_root, "results", "memory", "windows_wsh_subkeys.txt")
    out_dir = os.path.join(project_root, "results", "endpoint")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "cridex_extracted_config.json")
    
    if not os.path.exists(vmem_path):
        print(f"[ERROR] Evidence file not found: {vmem_path}", file=sys.stderr)
        sys.exit(1)
        
    c2_data = extract_c2_telemetry(vmem_path)
    webinjects = extract_webinject_targets(subkeys_path)
    
    analysis_payload = {
        "case_name": "Volatility Foundation Cridex Malware Memory Analysis",
        "malware_family": "Cridex / Feodo / Bugat Banking Trojan",
        "c2_telemetry_streams": c2_data,
        "webinject_targets_count": len(webinjects),
        "targeted_banking_urls": webinjects
    }
    
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(analysis_payload, f, indent=2)
        
    print(f"[+] Structured analysis written to: {out_file}")

if __name__ == "__main__":
    main()

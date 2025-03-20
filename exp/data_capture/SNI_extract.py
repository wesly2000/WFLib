"""
This file extract SNIs from each .pcap(ng) files in the base dir, and summarize the results
into a JSON file.
"""

from WFlib.tools.capture import SNI_extract
from pathlib import Path
import pyshark
import json

if __name__=="__main__":
    json_file = "sni.json"
    results = dict()
    base_dir_path = Path("exp/vmess_capture")
    for subdir in sorted(base_dir_path.iterdir()):
        if subdir.is_dir():  # Check if it's a directory
            for file in subdir.iterdir():
                if file.is_file() and file.suffix in ['.pcapng', '.pcap']:  # Ensure it's a pcap(ng) file
                    cap = pyshark.FileCapture(file, display_filter="tcp.port == 443 and tls.handshake.type == 1")
                    SNIs = SNI_extract(cap)
                    cap.close()
                    results[file.name] = list(SNIs)
                    
    with open(json_file, "w") as f:
        json.dump(results, f)
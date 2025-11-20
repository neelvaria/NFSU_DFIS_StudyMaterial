import pyshark                      # Import PyShark for PCAP file parsing
import requests                     # Import requests for HTTP geolocation API calls
import json                         # Import json for logging output in JSON format
from datetime import datetime       # Import datetime for timestamping logs

# --- Configuration ---
PCAP_FILE = "http.cap"              # Set the PCAP filename (ensure http.cap is present)
BLACKLIST_FILE = "blacklist.txt"    # Set blacklist filename (should contain IPs, one per line)
LOG_FILE = "flagged_ips.log"        # Set log filename for flagged IPs output
IPINFO_API_URL = "https://ipinfo.io/{ip}/json"  # Geolocation API endpoint (IPinfo public API)

# --- Function to load blacklisted IPs from file ---
def load_blacklist(filepath):
    with open(filepath, "r") as f:                      # Open blacklist file for reading
        return set(line.strip() for line in f if line.strip())  # Read each line, strip whitespace, use as a set

# --- Function to geolocate a given IP using IPinfo API ---
def geolocate_ip(ip):
    try:
        res = requests.get(IPINFO_API_URL.format(ip=ip), timeout=5)   # Send GET request to IPinfo API
        data = res.json()                                             # Parse response as JSON
        return {                                                      # Return geolocation info as dictionary:
            "ip": ip,                                                 #   - IP address
            "city": data.get("city"),                                 #   - City
            "region": data.get("region"),                             #   - Region
            "country": data.get("country"),                           #   - Country
            "loc": data.get("loc")                                    #   - Latitude/longitude string
        }
    except Exception as e:                                            # If API call fails, catch error
        return {"ip": ip, "error": str(e)}                            # Return error string for failed lookup

# --- Function to extract all source and destination IPs from a PCAP file ---
def extract_ips_from_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, only_summaries=False)        # Open the PCAP file using PyShark
    ip_set = set()                                                    # Create a set to store all unique IP addresses
    for pkt in cap:                                                   # Loop through each packet in the capture
        if hasattr(pkt, 'ip'):                                        # Only consider packets with an IP layer
            ip_set.add(pkt.ip.src)                                    # Add the source IP address to ip_set
            ip_set.add(pkt.ip.dst)                                    # Add the destination IP address to ip_set
    cap.close()                                                       # Close the PCAP file to release resources
    ip_set.discard(None)                                              # Remove any None values (could appear for non-IP packets)
    return ip_set                                                     # Return the set of observed IP addresses

# --- Main function to orchestrate loading, analysis, flagging, and logging ---
def main():
    blacklist = load_blacklist(BLACKLIST_FILE)                        # Load blacklist from file into a Python set
    all_ips = extract_ips_from_pcap(PCAP_FILE)                        # Extract all unique IPs from the provided PCAP
    flagged_ips = set()                                               # Create a set to track flagged (blacklisted) IPs
    with open(LOG_FILE, "w") as logf:                                 # Open log file for writing
        for ip in all_ips:                                            # Process each IP seen in the PCAP
            if ip in blacklist:                                       # If the IP is in the blacklist
                flagged_ips.add(ip)                                   # Add it to the flagged set
                geo = geolocate_ip(ip)                                # Get geolocation info (dict) for flagged IP
                log_entry = {                                         # Build the log entry as a dictionary
                    "timestamp": datetime.now().isoformat(),          #  - Timestamp in ISO format
                    "flagged_ip": geo                                 #  - Geolocation info for flagged IP (dict)
                }
                logf.write(json.dumps(log_entry) + '\n')              # Write the log entry to the file (as JSON)
                print(f"Flagged & logged: {ip} -> {geo}")             # Print a summary of flagged & logged entry
    print(f"\nFlagged IP addresses:\n{flagged_ips}")                  # Print all flagged IPs at the end

# --- Run the main function when the script is executed directly ---
if __name__ == "__main__":
    main()                                                            # Entrypoint for script execution

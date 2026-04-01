#!/bin/bash

# The systemd unit for SSH. Use "sshd.service" for most distros.
SSH_UNIT="sshd.service"

# This file will store any suspect IPs (exceeding threshold)
OUTPUT_FILE="suspect_ips.txt"

# How many failed attempts are considered suspicious
THRESHOLD=5

# Extract failed SSH login attempts and IPs from the journal
# Use grep to extract only IPv4 addresses from the log lines.
# -o : outputs only the matching part of the line (the IP address).
# -E : enables extended regular expressions for easier pattern syntax.
# '([0-9]{1,3}\.){3}[0-9]{1,3}' : matches four groups of 1 to 3 digits separated by periods,
#   representing IPv4 addresses (e.g., 192.168.1.10).

journalctl -u $SSH_UNIT | \
  grep "Failed password" | \                              # Only lines about failed SSH passwords
  grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' > all_failed_ips.txt  # Extract just the IP addresses

# Count how many times each IP appears and sort by count (descending)
sort all_failed_ips.txt | uniq -c | sort -nr > temp_ips.txt

# Write only those IPs with count >= threshold to the output file
awk -v threshold="$THRESHOLD" '{if ($1 >= threshold) print $2}' temp_ips.txt > "$OUTPUT_FILE"

# If any suspect IPs found, send an email alert (customize as needed)
# Check if the file specified by $OUTPUT_FILE exists and is not empty (-s checks size > 0)
if [ -s "$OUTPUT_FILE" ]; then
    # If the file has content, send an email alert with subject "Suspect SSH Login Attempts Detected"
    # The email body consists of the contents of $OUTPUT_FILE (list of suspect IPs)
    # Replace "admin@example.com" with the actual alert recipient's email address
    # Ensure mail has been setup
    mail -s "Suspect SSH Login Attempts Detected" admin@example.com < "$OUTPUT_FILE"
fi
# Remove temporary files or you can keep them if need be
rm all_failed_ips.txt temp_ips.txt

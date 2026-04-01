#!/bin/bash
# Usage: Run this script on a Linux system to generate a network information report.
# The script collects network interface details, checks connectivity to specified servers,
# allows user input for additional diagnostics, and formats all data into a printable report.
#
# Disclaimer: This script uses the 'ifconfig' command. On Ubuntu or Debian-based systems,
# if 'ifconfig' is not installed, please install it using:
# sudo apt install net-tools
#
# Note: Printing the report is optional and requires the 'lp' command to be configured.

# Define the file name that will store the generated network report
REPORT="network_report.txt"

# Write the report heading into the file (overwrite if exists)
echo "Network Information Report" > $REPORT
echo "==========================" >> $REPORT
echo "" >> $REPORT

# Extract list of network interface names from ifconfig output
# The command first filters lines starting with a device name (in ifconfig output)
# and then awk selects the first token which is the interface name
interfaces=$(ifconfig | grep '^[a-zA-Z0-9]' | awk '{print $1}')

# Append a section title about network interfaces and their IPs
echo "Network Interfaces and IP Information:" >> $REPORT

# Iterate through each interface found
for iface in $interfaces; do
  # Append the interface name to the report
  echo "Interface: $iface" >> $REPORT

  # Extract the IPv4 address for the interface
  # Grep 'inet ' lines and awk prints the second field (IP address)
  ifconfig $iface | grep 'inet ' | awk '{print "  IP Address: "$2}' >> $REPORT

  # Extract the netmask by finding 'netmask' in ifconfig output and printing the fourth field
  ifconfig $iface | grep 'netmask' | awk '{print "  Netmask: "$4}' >> $REPORT

  # Extract the MAC (hardware) address by looking for 'ether' line and printing second field
  ifconfig $iface | grep 'ether' | awk '{print "  MAC Address: "$2}' >> $REPORT

  # Add a blank line to visually separate interface sections in the report
  echo "" >> $REPORT
done

# Define an array of key servers/IPs to test connectivity
servers=("8.8.8.8" "1.1.1.1" "www.google.com")

# Append connectivity check section header to report
echo "Connectivity Check:" >> $REPORT

# Loop over all servers in the array
for server in "${servers[@]}"; do
  # Ping the server once, with timeout of 1 second.
  # Redirect all output to null, we only care about success or failure
  if ping -c 1 -W 1 $server &>/dev/null; then
    # If ping success, log that server is reachable
    echo "$server is reachable." >> $REPORT
  else
    # Otherwise, log that server is unreachable
    echo "$server is unreachable." >> $REPORT
  fi
done

# Add a blank line before user diagnostics
echo "" >> $REPORT

# Prompt the user to enter a hostname or IP address for additional diagnostics
read -p "Enter hostname or IP to ping for diagnostics: " target

# Ping the user provided target once and check success
if ping -c 1 -W 1 $target &>/dev/null; then
  # If reachable, log success
  echo "$target is reachable." >> $REPORT
else
  # If not reachable, log failure
  echo "$target is unreachable." >> $REPORT
fi

# Add a blank line after user diagnostics section
echo "" >> $REPORT

# Inform the user that report generation is complete and saved
echo "Report generated and saved to $REPORT"

# Optionally, print the report using 'lp' command (commented out)
# lp $REPORT

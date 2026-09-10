#!/bin/bash
# ==============================================================================
# Save file as: lab_pipeline.sh
# Run using: sudo ./lab_pipeline.sh
# ==============================================================================

echo "============================================================"
echo " 1. NETWORK VERIFICATION & DIAGNOSTICS"
echo "============================================================"
echo "[+] Command: ip addr show"
echo "    Significance: Inspects active network interface controllers (NICs),"
echo "    assigned IP addresses, subnet masks, and interface states."
ip addr show
echo ""

echo "[+] Command: ping -c 2 8.8.8.8"
echo "    Significance: Tests layer-3 ICMP connectivity and measures round-trip"
echo "    latency to verify outbound network accessibility."
ping -c 2 8.8.8.8
echo ""

echo "============================================================"
echo " 2. STORAGE MANAGEMENT"
echo "============================================================"
echo "[+] Command: df -h"
echo "    Significance: Reports filesystem disk usage, allocated capacity,"
echo "    and mount points using human-readable values (GB/MB)."
df -h
echo ""

echo "[+] Command: du -sh /var/log"
echo "    Significance: Summarizes total space occupied recursively by the"
echo "    specified log directory to help identify storage bottlenecks."
du -sh /var/log
echo ""

echo "============================================================"
echo " 3. SECURITY & USER MANAGEMENT"
echo "============================================================"
TARGET_USER="lab_demo_user"

# User creation requires elevated root privileges
if [ "$EUID" -ne 0 ]; then
    echo "[!] Warning: User provisioning steps require root privileges."
    echo "    Please run this script with 'sudo' to test user creation."
else
    echo "[+] Command: useradd -m -s /bin/bash $TARGET_USER"
    echo "    Significance: Provisions a new system user profile, generates a home"
    echo "    directory (-m), and sets Bash as default login shell (-s)."
    
    if id "$TARGET_USER" &>/dev/null; then
        echo "    Result: User '$TARGET_USER' already exists. Skipping useradd."
    else
        useradd -m -s /bin/bash "$TARGET_USER"
        echo "    Result: User '$TARGET_USER' created successfully."
    fi
    echo ""

    echo "[+] Command: passwd / chpasswd ($TARGET_USER)"
    echo "    Significance: Writes an encrypted password hash to /etc/shadow"
    echo "    to enforce access control policies for the account."
    echo "$TARGET_USER:SecurePass123!" | chpasswd
    echo "    Result: Password set non-interactively for '$TARGET_USER'."
fi
echo ""

echo "============================================================"
echo " Pipeline execution completed."
echo "============================================================"
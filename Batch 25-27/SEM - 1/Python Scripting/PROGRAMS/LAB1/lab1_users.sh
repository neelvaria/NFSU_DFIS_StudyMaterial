#!/bin/bash

# Usage: ./create_users.sh users.csv

INPUT_FILE="$1"
REPORT_FILE="user_creation_report_$(date +%F_%H%M%S).log"

if [[ -z "$INPUT_FILE" ]]; then
  echo "Usage: $0 <csv_file>"
  exit 1
fi

if [[ ! -f "$INPUT_FILE" ]]; then
  echo "Error: File '$INPUT_FILE' not found!"
  exit 1
fi

# Initialize counters
created_count=0
skipped_count=0

echo "User Creation Report - $(date)" > "$REPORT_FILE"
echo "=====================================" >> "$REPORT_FILE"

while IFS=, read -r username; do
  # Skip empty lines or header
  if [[ -z "$username" || "$username" == "username" ]]; then
    continue
  fi

  if id "$username" &>/dev/null; then
    echo "SKIPPED: User '$username' already exists." | tee -a "$REPORT_FILE"
    ((skipped_count++))
  else
    if sudo useradd -m "$username"; then
      echo "CREATED: User '$username' has been created." | tee -a "$REPORT_FILE"
      ((created_count++))
    else
      echo "ERROR: Failed to create user '$username'." | tee -a "$REPORT_FILE"
    fi
  fi
done < "$INPUT_FILE"

echo "=====================================" >> "$REPORT_FILE"
echo "Summary:" >> "$REPORT_FILE"
echo "  Users created: $created_count" >> "$REPORT_FILE"
echo "  Users skipped: $skipped_count" >> "$REPORT_FILE"

echo
echo "Report saved to $REPORT_FILE"

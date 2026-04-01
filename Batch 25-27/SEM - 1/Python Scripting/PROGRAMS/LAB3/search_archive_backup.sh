#!/bin/bash

# Regex File Search, Archive, and Backup Script

# Usage: ./search_archive_backup.sh <search_dir> <regex_pattern>
# Example: ./search_archive_backup.sh /home/user ".*\.(jpg|png|jpeg)$"
# If using above example ensure you have pictures with .png or .jpg extensions present in the folder
# You can modify the above regex to work with file extensions of your choice note that each extension is separated by a |
# Also logs and archive will be created is current directory where the shell script is run from.


# Enable strict mode: exit on error, treat unset variables as errors, and propagate pipe errors
set -euo pipefail

# -------------------------
# Assign input parameters to variables
# "$1" is the first argument (search directory)
# "$2" is the second argument (regex pattern)
# -------------------------
SEARCH_DIR="$1"    # Directory in which to search for files
REGEX_PATTERN="$2" # Regular expression pattern to match files (POSIX-extended)

# Generate a unique timestamp based on date and time (YYYYMMDD_HHMMSS format)
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"

# Set archive and log filenames using the timestamp, ensuring unique output files
ARCHIVE_NAME="backup_${TIMESTAMP}.tar.gz"                  # Final archive filename
LOGFILE="backup_${TIMESTAMP}.log"                          # Logfile to record script actions
TMP_FILE_LIST="matched_files_${TIMESTAMP}.txt"             # Temporary file to store the matched filenames

# ---------------------------------------------------------------------------
# Define a logging function
# Prepends a timestamp to messages and appends them to the logfile
# Also prints to the terminal for user feedback
# ---------------------------------------------------------------------------
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOGFILE"
}

# ---------------------------------------------------------------------------
# Check if the target directory exists
# If not, log an error and exit the script (exit code 1)
# ---------------------------------------------------------------------------
if [[ ! -d "$SEARCH_DIR" ]]; then
    log "Error: Directory '$SEARCH_DIR' not found. Exiting."
    exit 1
fi

# Log the beginning of the search action, along with the parameters used
log "Starting file search in: $SEARCH_DIR"
log "Using regex pattern: $REGEX_PATTERN"

# ---------------------------------------------------------------------------
# Perform the regex file search using 'find'
# - Searches recursively (-type f for files)
# - Uses POSIX-extended regular expression matching (-regextype posix-extended)
# - Writes all matching file paths to the temporary file list
# If the find command fails, log an error and exit (exit code 2)
# ---------------------------------------------------------------------------
if ! find "$SEARCH_DIR" -type f -regextype posix-extended -regex "$REGEX_PATTERN" > "$TMP_FILE_LIST"; then
    log "Error: Error occurred while searching for files."
    exit 2
fi

# ----------------------------------------------------------------------------------------------------
# Check if the search produced any results
# -s tests if the file is non-empty
# If no matching files were found, clean up temporary files and exit gracefully
# ----------------------------------------------------------------------------------------------------
if [[ ! -s "$TMP_FILE_LIST" ]]; then
    log "No files matched the pattern. Nothing to archive."
    rm -f "$TMP_FILE_LIST"
    exit 0
fi

# Log how many files matched (using 'wc -l' to count lines in the file list)
log "Found $(wc -l < "$TMP_FILE_LIST") files. Proceeding to archive."

# ----------------------------------------------------------------------------------------------------
# Archive and compress the matched files using tar and gzip (-czf options)
# see which command works otherwise you may need to install. mostly both are present by default
# -c: create a new archive
# -z: filter the archive through gzip for compression
# -f: specify the output filename (-T: read file names from the temporary list)
# Output errors to the logfile, check success/failure for logging
# ----------------------------------------------------------------------------------------------------
if tar -czf "$ARCHIVE_NAME" -T "$TMP_FILE_LIST" 2>>"$LOGFILE"; then
    log "Archive created: $ARCHIVE_NAME"
else
    log "Error: Failed to create archive."
    rm -f "$TMP_FILE_LIST"
    exit 3
fi

# ----------------------------------------------------------------------------------------------------
# Remove the temporary file list (housekeeping)
# Ensure temporary files do not accumulate
# ----------------------------------------------------------------------------------------------------
rm -f "$TMP_FILE_LIST"
log "Temporary file list removed."
log "Backup and archiving complete!"

# End the script with success status (0)
exit 0


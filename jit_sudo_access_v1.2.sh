#!/bin/bash
set +x

# Script: jit_sudo_access_v1.3.sh
# Purpose: Provide Just in Time admin/sudo access to Linux servers for a stipulated time period.

#Function to display help
function help() {
	echo "Usage: $0 -u user_name [-p password] [-g group_name] [-r request_number] [-n requestor_mail] [-d additional_comments] [-a] [-f pam_safe] [-s]"
	echo "-u: User name (comma-separated, required if no group is provided)"
	#echo "-l: Local user for domain joined system (comma-separated, optional)"
	echo "-p: Password for the user(s) (optional)"
	echo "-g: User group name (comma-separated, required if no user is provided)"
	echo "-r: Request number (optional)"
	echo "-n: Requestor mail ID (optional)"
	echo "-d: Request details - additional comments for user creation (optional)"
	echo "-a: Make user/group as Admin (optional)"
	echo "-f: PAM safe of user for onboarding to Cyberark (optional)"
	echo "-s: Suppress minor errors (optional, NOT RECOMMENDED)"
	exit 0
}

# Constants
DEFAULT_GROUP="jit_admins"
SUDOERS_FILE="/etc/sudoers.d/jit_sudoers"
DATE_FORMAT="%d:%m:%Y:%H:%M:%S"
DEFAULT_DURATION_DAYS=15
MIN_DURATION_DAYS=3
MAX_DURATION_DAYS=365
LOG_FILE="/var/log/jit_sudo_access.log"

# Functions
function log() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" | tee -a "$LOG_FILE"
}

function usage() {
    echo "Usage: $0 <username> <end_date_time>"
    echo "  <username>       : AD/Local account that needs admin access"
    echo "  <end_date_time>  : End date/time in format <DD:MM:YYYY:HH:MN:SC>"
    exit 1
}

function validate_date() {
    local date="$1"
    date "+$DATE_FORMAT" -d "$date" >/dev/null 2>&1
    return $?
}

function calculate_duration_days() {
    local end_date="$1"
    local current_date
    current_date=$(date "+$DATE_FORMAT")
    local duration
    duration=$(( ($(date -d "$end_date" +%s) - $(date -d "$current_date" +%s)) / 86400 ))
    echo "$duration"
}

function create_user() {
    local username="$1"
    if id "$username" &>/dev/null; then
        log "User $username already exists."
    else
        log "Creating user $username..."
        useradd -m "$username"
        if [ $? -ne 0 ]; then
            log "Error: Failed to create user $username."
            exit 1
        fi
    fi
}

function add_user_to_group() {
    local username="$1"
    log "Adding user $username to group $DEFAULT_GROUP..."
    groupadd -f "$DEFAULT_GROUP"
    usermod -aG "$DEFAULT_GROUP" "$username"
    if [ $? -ne 0 ]; then
        log "Error: Failed to add user $username to group $DEFAULT_GROUP."
        exit 1
    fi
}

function configure_sudoers() {
    log "Configuring sudoers for group $DEFAULT_GROUP..."
    if ! grep -q "^%$DEFAULT_GROUP" "$SUDOERS_FILE"; then
        echo "%$DEFAULT_GROUP ALL=(ALL) NOPASSWD:ALL" >> "$SUDOERS_FILE"
        if [ $? -ne 0 ]; then
            log "Error: Failed to configure sudoers."
            exit 1
        fi
    fi
}

function schedule_removal() {
    local username="$1"
    local end_date="$2"
    log "Scheduling removal of user $username from group $DEFAULT_GROUP on $end_date..."
    local removal_command="gpasswd -d $username $DEFAULT_GROUP && echo \"User $username removed from group $DEFAULT_GROUP\""
    echo "$removal_command" | at -t "$(date -d "$end_date" +%Y%m%d%H%M.%S)"
    if [ $? -ne 0 ]; then
        log "Error: Failed to schedule removal of user $username."
        exit 1
    fi
}

# Main Script
log "Script execution started."

if [ $# -lt 2 ]; then
    log "Interactive mode: Collecting inputs from user."
    read -p "Enter username: " USERNAME
    read -p "Enter end date/time (format <DD:MM:YYYY:HH:MN:SC>): " END_DATE
else
    USERNAME="$1"
    END_DATE="$2"
fi

if ! validate_date "$END_DATE"; then
    log "Error: Invalid date format. Use <DD:MM:YYYY:HH:MN:SC>."
    exit 1
fi

DURATION_DAYS=$(calculate_duration_days "$END_DATE")
if [ "$DURATION_DAYS" -lt "$MIN_DURATION_DAYS" ] || [ "$DURATION_DAYS" -gt "$MAX_DURATION_DAYS" ]; then
    log "Error: Duration must be between $MIN_DURATION_DAYS and $MAX_DURATION_DAYS days."
    exit 1
fi

create_user "$USERNAME"
add_user_to_group "$USERNAME"
configure_sudoers
schedule_removal "$USERNAME" "$END_DATE"

log "Script executed successfully. User $USERNAME has been granted sudo access until $END_DATE."
log "Script execution completed."
exit 0
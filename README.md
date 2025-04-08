# System Administration Project: Vulnerability Detection & Remediation
## Group Members: Ike Rolader, Jacob Colson, Mathew Breland, Nicholas DiGennaro

## How to Run the Script
1. Clone the Repo
```sh
git clone <url>
```

2. Make the source script an executable
```sh
chmod +x source.sh
```

3. Run the script
	- in normal mode (no changes will be made to the system)
		 ```sh
		 sudo ./source.sh
		 ```
	- in remediation mode (script will fix the vulnerabilities found)
		 ```sh
		 sudo ./source.sh --remediate
		 ```

4. Analyze the resulting files

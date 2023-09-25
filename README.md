# Security Expert Labs
## Contents

- OWASP Top 10 2021
- OWASP Broken Access Control

## OWASP Top 10 2021
![owasp](./assets/images/owasp.png)

### Broken Access Control

A regular visitor being able to access protected pages can lead to the following:
- Being able to view sensitive information from other users
- Accessing unauthorized functionality

Broken access control allows attackers to bypass authorisation, allowing them to view sensitive data or perform tasks they aren't supposed to.

### IDOR Challenge
IDOR or Insecure Direct Object Reference refers to an access control vulnerability where you can access resources you wouldn't ordinarily be able to see. This occurs when the programmer exposes a Direct Object Reference, which is just an identifier that refers to specific objects within the server. Notice that direct object references aren't the problem, but rather that the application doesn't validate if the logged-in user should have access to the requested account.

Example: 
`https://bank.thm/account?id=111111` <-- changing `111111` to `222222`
`https://bank.thm/account?id=222222` --> exposing private information

**Challenge**
`http://10.10.118.159/note.php?note_id=2` <-- note_id number was able to be manipulated

Answer: `http://10.10.118.159/note.php?note_id=0` 

flag{fivefourthree}

### Cryptographic Failures

A cryptographic failure refers to any vulnerability arising from the misuse (or lack of use) of cryptographic algorithms for protecting sensitive information. Web applications require cryptography to provide confidentiality for their users at many levels. 

```
When we encrypt the network traffic between the client and server, we usually refer to this as encrypting data in transit.
"To this end, your emails might also be encrypted when stored on the servers. This is referred to as encrypting data at rest."
```

### Cryptographic Failures Challenge
What is the name of the mentioned directory? 
The source code in the login page revealed:

![login_dir](./assets/images/login_dir.png)

The `webapp.db` files stands out as a file that could contain sensitive information. Using `sqlite3` it was possible to examine the db file. 

![db_password](./assets/images/db_password.png)

Using CrackStation it was easily possible to crack the hash, password: `qwertyuiop`.

### Injection
Injection attacks depend on what technologies are used and how these technologies interpret the input. Some common examples include:

- SQL Injection: This occurs when user-controlled input is passed to SQL queries.
- Command Injection: This occurs when user input is passed to system commands.

The main defence for preventing injection attacks is ensuring that user-controlled input is not interpreted as queries or commands. There are different ways of doing this:

- Using an allow list
- Stripping input: If the input contains dangerous characters, these are removed before processing.

### Command Injection Challenge

![lsla](./assets/images/lsla.png)
The strange file is `drpepper.txt`

Other commands that were used to get the rest of the answers:
```bash
$(whoami)
$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd)
$(cat /etc/alpine-release)
```

### Insecure Design

Example: Instagram allowed users to reset their forgotten passwords by sending them a 6-digit code to their mobile number via SMS for validation. If an attacker wanted to access a victim's account, he could try to brute-force the 6-digit code. As expected, this was not directly possible as Instagram had rate-limiting implemented so that after 250 attempts, the user would be blocked from trying further. If an attacker had several different IP addresses from where to send requests, he could now try 250 codes per IP.

The challenge consisted of wild guessing Joseph's favourite colour

### Security Misconfiguration

Security misconfigurations include:

- Poorly configured permissions on cloud services, like S3 buckets.
- Having unnecessary features enabled, like services, pages, accounts or privileges.
- Default accounts with unchanged passwords.
- Error messages that are overly detailed and allow attackers to find out more about the system.
- Not using HTTP security headers.

Accessing `<IP>:86/console` allowed to interact with the console. The statement used to read the contents of `app.py` was: `import os; print(os.popen("cat app.py").read())`

### Vulnerable and outdated Components -Lab

Googling projectworld 2017 vulnerablity, the first link provides a RCE script: https://www.exploit-db.com/exploits/47887

This can be used as the password for the `admin` login. Full command for the online book store 
```
python3 /usr/share/exploitdb/exploits/php/webapps/47887.py http://<IP>:port
```

### Identification and Authentication Failures

Attacks include:
- Brute force attacks
- Use of weak credentials
- Weak Session cookies

### Software and Data Integrity Failures

By using a website that can identify hashes based of a URL, it was possible to extract the `sha256sum` value. 


![cookies](./assets/images/cookies.png)

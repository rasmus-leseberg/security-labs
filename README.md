# Security Expert Labs
---
### Contents

1. [OWASP Top 10 2021](#owasp-top-10-2021)
2. [OWASP Broken Access Control](#owasp-broken-access-control)
3. [Classic DevSecOps pipeline](#classic-devsecops-pipeline)
4. [Cloud-native DevSecOps pipeline](#cloud-native-devsecops-pipeline)
5. [Splunk: Exploring SPL](#splunk-exploring-spl)
6. [Microsoft Sentinel Lab](#microsoft-sentinel-lab)
7. [Intro to Endpoint Security](#intro-to-endpoint-security)
8. [Wazuh](#wazuh)
9. [Active Directory Basics](#active-directory-basics)
10. [Enumerating Active Directory](#enumerating-active-directory)
11. [Active Directory Hardening](#active-directory-hardening)
12. [NTLM leak via Outlook](#ntlm-leak-via-outlook)
13. [CVE-2022-26923 AD Certificate Services](#cve-2022-26923-ad-certificate-services)
14. [AttacktiveDirectory](#attacktivedirectory)

---
### OWASP Top 10 2021
![owasp](./assets/images/owasp.png)

#### Broken Access Control

**What:** A regular visitor being able to access protected pages. Leads to:

- Being able to view sensitive information from other users
- Accessing unauthorized functionality

Broken access control allows attackers to bypass `authorisation`, allowing them to view sensitive data or perform tasks they aren't supposed to.

#### IDOR Challenge
**IDOR** or `Insecure Direct Object Reference` refers to an access control vulnerability where you can access resources you wouldn't ordinarily be able to see. This occurs when the programmer exposes a `Direct Object Reference`, which is just an identifier that refers to specific objects within the server. Notice that direct object references aren't the problem, but rather that the application doesn't validate if the logged-in user should have access to the requested account.

Example: 
```
https://bank.thm/account?id=111111 <-- changing 111111 to 222222
https://bank.thm/account?id=222222 --> exposing private information
```

**Challenge:** `http://10.10.118.159/note.php?note_id=2` <-- note_id number was able to be manipulated

**Answer:** `http://10.10.118.159/note.php?note_id=0` --> flag{fivefourthree}

#### Cryptographic Failures

A cryptographic failure refers to any vulnerability arising from the misuse (or lack of use) of cryptographic algorithms for protecting sensitive information. Web applications require cryptography to provide confidentiality for their users at many levels. 

```
"When we encrypt the network traffic between the client and server, we usually refer to this as encrypting data in transit.
To this end, your emails might also be encrypted when stored on the servers. This is referred to as encrypting data at rest."
```

**Challenge:**

The cryptographic failure was a failure to encrypt data at rest in this case. When looking in `/assets`, a db file was found. The information could be extracted with `sqlite3`.

![login_dir](./assets/images/login_dir.png)

![db_password](./assets/images/db_password.png)

Using CrackStation it was easily possible to crack the hash, password: `qwertyuiop`.

#### Injection
Injection attacks depend on what technologies are used and how these technologies interpret the input. Some common examples include:

- SQL Injection: This occurs when user-controlled input is passed to SQL queries.
- Command Injection: This occurs when user input is passed to system commands.

The main defence for preventing injection attacks is ensuring that user-controlled input is not interpreted as queries or commands. There are different ways of doing this:

- Using an allow list
- Stripping input: If the input contains dangerous characters, these are removed before processing. (Sanitizing)

#### Command Injection Challenge

![lsla](./assets/images/lsla.png)

Injection commands that were used:

```bash
$(whoami)
$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd)
$(cat /etc/alpine-release)
```

#### Insecure Design

**Example:** Instagram allowed users to reset their forgotten passwords by sending them a 6-digit code to their mobile number via SMS for validation. If an attacker wanted to access a victim's account, he could try to brute-force the 6-digit code. As expected, this was not directly possible as Instagram had rate-limiting implemented so that after 250 attempts, the user would be blocked from trying further. If an attacker had several different IP addresses from where to send requests, he could now try 250 codes per IP.

The challenge consisted of wild guessing Joseph's favourite colour

#### Security Misconfiguration

Security misconfigurations include:

    - Poorly configured permissions on cloud services, like S3 buckets.
    - Having unnecessary features enabled, like services, pages, accounts or privileges.
    - Default accounts with unchanged passwords.
    - Error messages that are overly detailed and allow attackers to find out more about the system.
    - Not using HTTP security headers.

Accessing `<IP>:86/console` allowed to interact with the console. The statement used to read the contents of app.py was: 

```python
import os; print(os.popen("cat app.py").read())`
```

#### Vulnerable and outdated Components -Lab

Googling projectworld 2017 vulnerablity, the first link provides an RCE script: 
https://www.exploit-db.com/exploits/47887

This can be used as the password for the `admin` login. Full command for the online book store 

```sh
python3 /usr/share/exploitdb/exploits/php/webapps/47887.py http://<IP>:port
```

#### Identification and Authentication Failures

Attacks include:
- Brute force attacks
- Use of weak credentials
- Weak Session cookies

**Practical:** Exploiting the possibility of re-registration (with slightly modified data), enables us to retrieve information from `darren` and `arthurs` account. By using a space ' ' before the name, registration was possible under an existing users name. 

#### Software and Data Integrity Failures

**What is it:** Suppose you have a website that uses third-party libraries that are stored in some external servers. If an attacker hacks the external server repository they could change the content of the libraries being used. Anyone visiting the website would pull the malicious code.

**How to prevent it:** Modern browsers allow you to specify a hash along the library's URL so that the library code is executed only if the hash of the downloaded file matches the expected value. This security mechanism is called Subresource Integrity (SRI)

```javascript
<script src="https://code.jquery.com/jquery-3.6.1.min.js" integrity="sha256-o88AwQnZB+VDvE9tvIXrMQaPlFFSUTR+nldQm1LuPXQ=" crossorigin="anonymous"></script>
```

**Cookies** are key-value pairs that a web application will store on the user's browser and that will be automatically repeated on each request to the website that issued them. To make sure that the cookies haven't been altered by users, `JSON Web Tokens` (JWT) can help prove the integrity of a session. 

![jwt](./assets/images/jwt.png)

**JWT and the None Algorithm**
A data integrity failure was present on some libraries implementing JWT's a whie ago. JWT implements a signature to validate the integrty of a payload. To exploit the vulnerability, the header section `alg` needs to be `none`, and the signature removed.

![none](./assets/images/none.png)

Any decoding tool (like https://appdevtools.com/base64-encoder-decoder) that allows you to encode/decode base64 can help to manipulate the cookie.

#### Security Logging and Monitoring Failures

#### Server-Side Request Forgery (SSRF)

---
### OWASP Broken Access Control

---
### Classic DevSecOps pipeline

---
### Cloud-native DevSecOps pipeline

---
### Splunk: Exploring SPL

---
### Microsoft Sentinel Lab

---
### Intro to Endpoint Security

---
### Wazuh

---
### Active Directory Basics

---
### Enumerating Active Directory

---
### Active Directory Hardening

---
### NTLM leak via Outlook

---
### CVE-2022-26923 AD Certificate Services

---
### AttacktiveDirectory

#### [Back to top](#contents)
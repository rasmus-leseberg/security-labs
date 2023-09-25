# Security Expert Labs
## Contents

- OWASP Top 10 2021
- OWASP Broken Access Control

## OWASP Top 10 2021
![owasp](.assets/images/owasp.png)

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


## OFA

### Code Analysis
The server presents a menu with two options: **Encrypt Message** and **Encrypt Flag**.

- When encrypting the flag, the nonce is randomly generated using a time-based seed.
- When encrypting a custom message, we can specify our own nonce.

### Exploit
Since the seed is time-based, we can determine its value, allowing us to retrieve the nonce used for encrypting the flag.

Additionally, since **CTR mode** is used, encryption and decryption are identical.

With this knowledge, we can recover the nonce and decrypt the flag using the `encrypt_plain` function.


### Code :
[Check the script](solution/sol.py)
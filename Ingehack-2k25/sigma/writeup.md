## sigma

### Code Analysis
The server is implementing the short factoring proofs and you are the verfier

### Exploit
The r used is static in each connection.

- send e1 and get y1 .
- send e2 and get y2 .
- y1 - y2 = (n - phi ) * (e1-e2)
- k = (y1-y2) * pow((e1-e2) , -1 , n)
- phi = n - k 


### Code :
[Check the script](solution/sol.py)
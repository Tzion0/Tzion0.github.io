---
title: "[SHELLCTF] OX9OR2"
excerpt_separator: <!--more-->
categories:
  - CTF
tags:
  - SHELLCTF
  - CRYPTO
  - "2022"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

# Task source:
https://github.com/Tzion0/CTF/tree/master/ShellCTF/2022/OX9OR2

This challenge provided two files called `encryption.py` and `encrypted`. `encrypted` file contains ciphertext produced by `encryption.py`

<!--more-->

## encryption.py
```py
def xor(msg, key):
    o = ''
    for i in range(len(msg)):
        o += chr(ord(msg[i]) ^ ord(key[i % len(key)]))
    return o

with open('message', 'r') as f:
    msg = ''.join(f.readlines()).rstrip('\n')

with open('key', 'r') as k:
    key = ''.join(k.readlines()).rstrip('\n')

assert key.isalnum() and (len(key) == 9)
assert 'SHELL' in msg

with open('encrypted', 'w') as fo:
    fo.write(xor(msg, key))
```

Looking at encryption.py, we can conclude that the script is basically doing XOR on message with a key where the key is alphanumeric (isalnum) with the length of 9 and contains "SHELL" string in it.

We can assume that the "SHELL{" string is at beginning of the plaintext message since it is the flag format.

By using the XOR recipe in CyberChef with the key "SHELL{", we get the first 6 plaintext key: `XORISC`

![IMG](/assets/images/shellctf2022-ox9or2/img.png)

At this point we are left with remaining 3 characters to get the full key, we can achieve this by bruteforcing it. I created a python script to do this:
```py
#!/usr/bin/env python3
from itertools import product
import string
import re

with open('encrypted', 'rb') as f:
    ct = list(f.read())

pt = list("SHELL{")
perm = list(product(list(string.ascii_lowercase + string.ascii_uppercase + string.digits), repeat=3))

for p in perm:
	flag = ""
	key = list("XORISC") + list(p)
	for c in range(len(ct)):
		flag += chr(ct[c] ^ ord(key[c % len(key)]))
	if re.match(r"^SHELL{X[A-Za-z0-9]R_1S_R3[A-Za-z0-9]{3}51BL3}", flag):
		print("Flag: " + flag, "Key: " + "".join(key))
```

The regex match is basically obtained through trial and error where some of the trials produced some promising plaintext message.

Execute the script will get output below:
![IMG](/assets/images/shellctf2022-ox9or2/img2.png)

Just like that, we got the flag!

Flag:
```
SHELL{X0R_1S_R3VeR51BL3}
```
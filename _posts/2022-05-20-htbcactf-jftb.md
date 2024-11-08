---
title: "[HTBCACTF] Jenny From The Block"
excerpt_separator: <!--more-->
categories:
  - CTF
tags:
  - HTBCACTF
  - CRYPTO
  - HTB
  - "2022"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

# Task source:
https://github.com/Tzion0/CTF/tree/master/HTB/CA_CTF/2022/Crypto/Jenny_From_The_Block

This challenge provided a python source code.

Looking at the source code, we can see there are few whitelisted commands that we can run:
```
allowed_commands = [b'whoami', b'ls', b'cat secret.txt', b'pwd']
```

<!--more-->

In `challenge` function, the command we input will be execute after passing the check and the command itself and the output will be concat with a string for further block cipher encryption with a random 32 bytes password before sending back to us:
```
output = run_command(command)
response = b'Command executed: ' + command + b'\n' + output
password = os.urandom(32)
ct = encrypt(response, password)
req.sendall(ct.encode())
```

The function `encrypt` will split the `response` in blocks of size 32, which means the plaintext of first block will always be the below string as it was length 32:
```
b'Command executed: cat secret.txt'
```

This makes the whole operation reversible as it is constant. Notice that in `encrypt` function, the password to encrypt will changed after the first iteration:
```
h = sha256(enc_block + block).digest()
```

And the password is basically used to encrypt the plain text by adding byte by byte where you can see in `encrypt_block` function:
```
def encrypt_block(block, secret):
    enc_block = b''
    for i in range(BLOCK_SIZE):
        val = (block[i]+secret[i]) % 256
        enc_block += bytes([val])
    return enc_block
```

Knowing what the code does, we connect to the docker, get the `ct` and write a script to decode it:

![IMG](/assets/images/htbcactf2022-jftb/jftb.png)

```
from binascii import unhexlify
from hashlib import sha256

def decrypt_block(block, secret):
    dec_block = b""
    for i in range(32):
        val = (block[i] - secret[i]) % 256
        dec_block += bytes([val])
    return dec_block

def decrypt(ct):
    ct = unhexlify(ct)
    blocks = [ct[i:i+32] for i in range(0, len(ct), 32)]
    ori = b'Command executed: cat secret.txt'

    pt = b""
    h = sha256(bytes(blocks[0] + ori)).digest()
    for b in range(1, len(blocks)):
        dec_block = decrypt_block(blocks[b], h)
        h = sha256(blocks[b] + dec_block).digest()
        pt += dec_block
    return pt

def main():
    ori = b'Command executed: cat secret.txt'
    ct = "e67cfcfe40dddd1014117018e9fd98cdbb17e1d2bf43a316efd46f27347e1745df6b097a9122ea4148eaec162bae24119260a68b06ce89c339a6c5f9b28acf16c034aefb355f670e389389a42fe66b95691b3119ae2b2b63b094cb174f689852d1a5c8e125f9405e00265a5fbf2c93b8b774d32317d243ed4f7f7905b149818d7d22608b6834fdbeda02ceda13595467f0c316016725be0a2fca65fffef9bafc45ed349f715faffc61101c93d92922faa740bd222d81d501acfafef510c7c7365eeb3e44ae748d8b20ec21d1b89da60b40a5402f87eda9ae34f0c628ada142104e8baabd30deb467618f86a151d01ce44d38962241a1e6132adeb51ae80fbeaf"
    message = decrypt(ct).decode()
    print(message)

if __name__ == '__main__':
   main()
```

![IMG](/assets/images/htbcactf2022-jftb/jftb_flag.png)

Flag:
```
HTB{b451c_b10ck_c1ph3r_15_w34k!!!}
```
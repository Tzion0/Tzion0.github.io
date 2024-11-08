---
title: "[PICOCTF] Forensics Challenges Writeup"
excerpt_separator: <!--more-->
categories:
  - CTF
tags:
  - PICOCTF
  - Forensics
  - "2022"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

# Tasks source:
https://github.com/Tzion0/CTF/tree/master/PicoCTF/2022/Forensics

Worth to note that we managed to get rank 468 out of 7794 teams in PicoCTF 2022.
![IMG](/assets/images/picoctf2022-for/picoctf_ranking.png)
![IMG](/assets/images/picoctf2022-for/picoctf_myteam.png)


This writeup contains 11 out of 13 Forensics category challenges in PicoCTF 2022 that i solved.

# Enhance!
## Description
Download this image file and find the flag.

This challenge provided a SVG image file.

To solve it, we just need to view the text inside the SVG image file:
```
strings drawing.flag.svg
```
Then concat the flag char by char:
```md
<tspan
 	sodipodi:role="line"
	x="107.43014"
	y="132.08501"
	style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
	id="tspan3748">p </tspan><tspan
	sodipodi:role="line"
	x="107.43014"
	y="132.08942"
	style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
	id="tspan3754">i </tspan><tspan
	sodipodi:role="line"
	x="107.43014"
	y="132.09383"
	style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
	id="tspan3756">c </tspan><tspan
	sodipodi:role="line"
	x="107.43014"
	y="132.09824"
	style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
	id="tspan3758">o </tspan><tspan
	sodipodi:role="line"
	x="107.43014"
	y="132.10265"
	style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
	id="tspan3760">C </tspan><tspan
	sodipodi:role="line"
	x="107.43014"
	y="132.10706"
	style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
	id="tspan3762">T </tspan><tspan
	sodipodi:role="line"
	x="107.43014"
	y="132.11147"
	style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
	id="tspan3764">F { 3 n h 4 n </tspan><tspan
	sodipodi:role="line"
	x="107.43014"
	y="132.11588"
	style="font-size:0.00352781px;line-height:1.25;fill:#ffffff;stroke-width:0.26458332;"
	id="tspan3752">c 3 d _ a a b 7 2 9 d d }
</tspan>
```

Flag:
```
picoCTF{3nh4nc3d_aab729dd}
```

# File types
## Description
This file was found among some files marked confidential but my pdf reader cannot read it, maybe yours can.

This challenge provided a .pdf shell text.

This challenge file contains nested file with different type of compression, so we just need to uncompress it one by one and eventually will get the flag:
```
# Execute shell script
chmod +x Flag.pdf
./Flag.pdf

# Extract nested file inside file flag
binwalk -e flag
cd _flag.extracted

# Uncompress gz
mv 64 64.gz
gunzip -d 64.gz

# Uncompress lz
mv 64 64.lz
lzip -d 64.lz

# Uncompress lz4
mv 64 64.lz4
lz4 -d 64.lz4

# Uncompress lzma
mv 64 64.lzma
lzma -d 64.lzma

# Uncompress lzop
mv 64 64.lzop
lzop -d 64.lzop

# Uncompress lzip
mv 64 64.lzip
lzip -d 64.lzip

# Uncompress xz
mv 64.lzip.out 64.xz
xz -d 64.xz

# Unhex to get flag
unhex < 64
```

Flag:
```
picoCTF{f1len@m3_m@n1pul@t10n_f0r_0b2cur17y_3c79c5ba}
```

# Lookey here
## Description
Attackers have hidden information in a very large mass of data in the past, maybe they are still doing it.

This challenge provided a text file.

We just need to grep for flag format to obtain the flag:
```
grep pico anthem.flag.txt
```

Flag:
```
picoCTF{gr3p_15_@w3s0m3_4c479940}
```

# Packets Primer
## Description
Download the packet capture file and use packet analysis software to find the flag.

This challenge provided a pcap file.

Solution to get flag:
```
Open pcap file with wireshark -> Right click any of the TCP packet -> Follow -> TCP Stream
```

Flag:
```
picoCTF{p4ck37_5h4rk_ceccaa7f}
```

# Sleuthkit Intro
## Description
Download the disk image and use `mmls` on it to find the size of the Linux partition. Connect to the remote checker service to check your answer and get the flag.

This challenge provided a disk image file.

As stated in description, we just need to use the `mmls` command:
![IMG](/assets/images/picoctf2022-for/sleuthkit_intro.png)

Answer:
```
202752
```

![IMG](/assets/images/picoctf2022-for/sleuthkit_intro_flag.png)

Flag:
```
picoCTF{mm15_f7w!}
```

# Sleuthkit Apprentice
## Description
Download this disk image and find the flag.

This challenge provided a disk image file.

We need to find the flag inside the partition of disk image.

### Step 1
![IMG](/assets/images/picoctf2022-for/apprentice_s1.png)

### Step 2
![IMG](/assets/images/picoctf2022-for/apprentice_s2.png)

### Step 3
![IMG](/assets/images/picoctf2022-for/apprentice_s3.png)

Flag:
```
picoCTF{by73_5urf3r_3497ae6b}
```

# Redaction gone wrong
## Description
Now you DON’T see me.
This report has some critical data in it, some of which have been redacted correctly, while some were not. Can you find an important key that was not redacted properly?

This challenge provided a PDF file.

Open the PDF file we can see some sentences were redacted:
![IMG](/assets/images/picoctf2022-for/rgw_ori.png)

However, when we highlight all the text (Ctrl + a), we can see the redacted fields, which shows us the flag:

![IMG](/assets/images/picoctf2022-for/rgw_highlight.png)

Flag:
```
picoCTF{C4n_Y0u_S33_m3_fully}
```

# Eavesdrop
## Description
Download this packet capture and find the flag.

This challenge provided a pcap file.

Opening the pcap file using Wireshark and follow the TCP Stream at Stream 0, we can see a conversation:
```
Hey, how do you decrypt this file again?
You're serious?
Yeah, I'm serious
*sigh* openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123
Ok, great, thanks.
Let's use Discord next time, it's more secure.
C'mon, no one knows we use this program like this!
Whatever.
Hey.
Yeah?
Could you transfer the file to me again?
Oh great. Ok, over 9002?
Yeah, listening.
Sent it
Got it.
You're unbelievable
```

The key to takeaway from the conversation is how to decrypt the file using `openssl`:
```
openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123
```

By increasing the TCP Stream to 2, we can see a stream starting with `Salted_`:
![IMG](/assets/images/picoctf2022-for/eavesdrop1.png)

After that, change the value of field `Show and save data as` to `raw`, then click `Save as`:
![IMG](/assets/images/picoctf2022-for/eavesdrop2.png)

Next, apply the command we noted down before to decrypt the file we saved just now:
```
openssl des3 -d -salt -in file.des3 -out file.txt -k supersecretpassword123
```

If the decryption is success, the **file.txt** will contains the flag.

Flag:
```
picoCTF{nc_73115_411_5786acc3}
```

# Operation Oni
## Description
Download this disk image, find the key and log into the remote machine.
Remote machine:
```
ssh -i key_file -p 59367 ctf-player@saturn.picoctf.net
```

This challenge provided a disk image file.

The first step is to list the partitions inside the disk image:
```
mmls disk.img
```
![IMG](/assets/images/picoctf2022-for/oni1.png)

We can see at start of `206848` we have a `Linux (0x83)`. So let's try to list the files in it, we are specifically looking for SSH key and since SSH key normally starts with `id`, let's try to grep for it:
```
fls -r -o 206848 disk.img | grep id
```

We can see at the bottom of output shows `id_ed25519` and `id_ed25519.pub`. We can try our luck here by assuming it is the correct SSH key we are looking for:
![IMG](/assets/images/picoctf2022-for/oni2.png)

Let's view the content of it:
```
icat -o 206848 disk.img 2345
```
![IMG](/assets/images/picoctf2022-for/oni3.png)

Let's save the file and remember to `chmod 600 <file>` before trying to login to remote machine:
```
ssh -i id_ed25519 -p 59367 ctf-player@saturn.picoctf.net
```
![IMG](/assets/images/picoctf2022-for/oni4.png)

Flag:
```
picoCTF{k3y_5l3u7h_b5066e83}
```

# Operation Orchid
## Description
Download this disk image and find the flag.

This challenge provided a disk image file.

Again, first step is to list the partitions inside the disk image:
```
mmls disk.flag.img
```
![IMG](/assets/images/picoctf2022-for/orchid1.png)

By listing files inside these partitions, we found that `411648` contains the flag file:
```
fls -r -o 411648 disk.flag.img | grep flag
```
![IMG](/assets/images/picoctf2022-for/orchid2.png)

By viewing the content of `flag.txt.enc`. We can see it apparently was a OpenSSL encrypted file:
```
icat -o 411648 disk.flag.img 1782
```
![IMG](/assets/images/picoctf2022-for/orchid3.png)

After saving the file as `flag.txt.enc`, now we to look for a way to decrypt it, by looking again at the list of files, i found a history file:
```
fls -r -o 411648 disk.flag.img | grep -v Orphan
```
![IMG](/assets/images/picoctf2022-for/orchid4.png)

By viewing the content of history file, it tells us the way to encrypt the flag:
```
icat -o 411648 disk.flag.img 1875
```
![IMG](/assets/images/picoctf2022-for/orchid5.png)

So now we have the information about the encryption type and the password, let's decrypt it:
```
openssl aes256 -d -in flag.txt.enc -out flag.txt
```
![IMG](/assets/images/picoctf2022-for/orchid6.png)

Flag:
```
picoCTF{h4un71ng_p457_0a710765}
```

# SideChannel
## Description
There's something fishy about this PIN-code checker, can you figure out the PIN and get the flag?
Once you've figured out the PIN (and gotten the checker program to accept it), connect to the master server using `nc saturn.picoctf.net 55824` and provide it the PIN to get your flag.

This challenge provided a PIN checker program.

This challenge is one of my favourite.

By running the PIN checker program, it prompt us for a 8-digit PIN code:
![IMG](/assets/images/picoctf2022-for/sidechannel1.png)

From the hint given by picoCTF, we know that the challenge is about "Timing-based side-channel attacks"

The theory is when a character/number is matched, it will take slightly longer to process than those not matched, so we can determine the correct character/number (PIN) by looking for the longest processing time:
![IMG](/assets/images/picoctf2022-for/sidechannel2.png)

I made a script to automate this:
```py
#!/usr/bin/env python3
# Timing-based Side Channel Attack
from pwn import *
import time
import numpy as np
import collections

context.log_level = 'error'
pin = ["0", "0", "0", "0", "0", "0", "0", "0"]
duration = {}

for z in range(8):
    duration.clear()
    for x in range(48, 58):
        pin[z] = chr(x)
        start_time = time.time()
        print("Pin:", "".join(pin))
        p = process("pin_checker")
        p.sendlineafter("code:\n", "".join(pin).encode())
        p.recvline()
        p.recvline()
        p.recvline()
        duration[chr(x)] = "{:.2g}".format(time.time() - start_time)
        # print(duration[chr(x)])
        p.close()

    """
    most_common()        : [('0.13', 8), ('0.12', 1), ('0.25', 1)]
    most_common()[-1]    : ('0.25', 1)
    most_common()[-1][0] : 0.25
    """
    uniq = collections.Counter(duration.values()).most_common()[-1][0]
    for key, value in duration.items():
        if uniq == value:
            pin[z] = key


print("Final pin:", "".join(pin))
```

By running the script, we can get the final pin number:
```
48390513
```
![IMG](/assets/images/picoctf2022-for/sidechannel3.png)

**Notes: Since this is time-based and my script isn't perfect, you may not getting the correct PIN at first try.**

Let's provide it to master server and get the flag!
![IMG](/assets/images/picoctf2022-for/sidechannel4.png)

Flag:
```
picoCTF{t1m1ng_4tt4ck_9803bd25}
```

Thank you so much for reading till here, have a great day ahead !
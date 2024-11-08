---
title: "[PICOCTF] Reverse Engineering Challenges Writeup"
excerpt_separator: <!--more-->
categories:
  - CTF
tags:
  - PICOCTF
  - REV
  - "2022"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

# Tasks source:
https://github.com/Tzion0/CTF/tree/master/PicoCTF/2022/Reverse_Engineering

Worth to note that we managed to get rank 468 out of 7794 teams in PicoCTF 2022.
![IMG](/assets/images/picoctf2022-for/picoctf_ranking.png)
![IMG](/assets/images/picoctf2022-for/picoctf_myteam.png)

This writeup contains 11 out of 12 Reverse Engineering category challenges in PicoCTF 2022 that i solved.

<!--more-->

# file-run1
## Description
A program has been provided to you, what happens if you try to run it on the command line?

This challenge provided an executable.

We just need to execute the executable to obtain the flag.

![IMG](/assets/images/picoctf2022-rev/file-run1.png)

Flag:
```
picoCTF{U51N6_Y0Ur_F1r57_F113_9bc52b6b}
```

# file-run2
## Description
Another program, but this time, it seems to want some input. What happens if you try to run it on the command line with input "Hello!"?

This challenge provided an executable.

Similar to **file-run1**, but this time we need to run file with the specific argument.

![IMG](/assets/images/picoctf2022-rev/file-run1.png)

Flag:
```
picoCTF{F1r57_4rgum3n7_be0714da}
```

# GDB Test Drive
## Description
Can you get the flag?
Here's the test drive instructions:
```
$ chmod +x gdbme
$ gdb gdbme
(gdb) layout asm
(gdb) break *(main+99)
(gdb) run
(gdb) jump *(main+104)
```

We just need to follow exactly the instructions given in the description above to get flag.

![IMG](/assets/images/picoctf2022-rev/gdb-test-drive.png)

Flag:
```
picoCTF{d3bugg3r_dr1v3_197c378a}
```

# patchme.py
## Description
Can you get the flag?
Run this Python program in the same directory as this encrypted flag.

This challenge provided an encrypted flag in text file and a python script:
```py
## THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################
def str_xor(secret, key):
    #extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])
###############################################################################


flag_enc = open('flag.txt.enc', 'rb').read()



def level_1_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    if( user_pw == "ak98" + \
                   "-=90" + \
                   "adfjhgj321" + \
                   "sleuth9000"):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), "utilitarian")
        print(decryption)
        return
    print("That password is incorrect")



level_1_pw_check()
```

From the source code we can see this script is used to decrypt the encrypted flag by providing the correct password, and the correct password apparently is hardcoded, so we just need to concat it. The password is:
```
ak98-=90adfjhgj321sleuth9000
```

![IMG](/assets/images/picoctf2022-rev/patchme.png)

Flag:
```
picoCTF{p47ch1ng_l1f3_h4ck_c4a4688b}
```

# Safe Opener
## Description
Can you open this safe?
I forgot the key to my safe but this program is supposed to help me with retrieving the lost key. Can you help me unlock my safe?
Put the password you recover into the picoCTF flag format like:
```
picoCTF{password}
```

This challenge provided a plain text java file:
```java
import java.io.*;
import java.util.*;
public class SafeOpener {
    public static void main(String args[]) throws IOException {
        BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
        Base64.Encoder encoder = Base64.getEncoder();
        String encodedkey = "";
        String key = "";
        int i = 0;
        boolean isOpen;


        while (i < 3) {
            System.out.print("Enter password for the safe: ");
            key = keyboard.readLine();

            encodedkey = encoder.encodeToString(key.getBytes());
            System.out.println(encodedkey);

            isOpen = openSafe(encodedkey);
            if (!isOpen) {
                System.out.println("You have  " + (2 - i) + " attempt(s) left");
                i++;
                continue;
            }
            break;
        }
    }

    public static boolean openSafe(String password) {
        String encodedkey = "cGwzYXMzX2wzdF9tM18xbnQwX3RoM19zYWYz";

        if (password.equals(encodedkey)) {
            System.out.println("Sesame open");
            return true;
        }
        else {
            System.out.println("Password is incorrect\n");
            return false;
        }
    }
}
```

Again, the password key is hardcoded with base64 encoding. We just need to base64 decode it:
```
echo -n "cGwzYXMzX2wzdF9tM18xbnQwX3RoM19zYWYz" | base64 -d
```

![IMG](/assets/images/picoctf2022-rev/safeopener.png)

Flag:
```
picoCTF{pl3as3_l3t_m3_1nt0_th3_saf3}
```

# bloat.py
## Description
Can you get the flag?
Run this Python program in the same directory as this encrypted flag.

This challenge provided an encrypted flag in text file and a python script:
```py
import sys
a = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"+ \
            "[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ "
def arg133(arg432):
  if arg432 == a[71]+a[64]+a[79]+a[79]+a[88]+a[66]+a[71]+a[64]+a[77]+a[66]+a[68]:
    return True
  else:
    print(a[51]+a[71]+a[64]+a[83]+a[94]+a[79]+a[64]+a[82]+a[82]+a[86]+a[78]+\
a[81]+a[67]+a[94]+a[72]+a[82]+a[94]+a[72]+a[77]+a[66]+a[78]+a[81]+\
a[81]+a[68]+a[66]+a[83])
    sys.exit(0)
    return False
def arg111(arg444):
  return arg122(arg444.decode(), a[81]+a[64]+a[79]+a[82]+a[66]+a[64]+a[75]+\
a[75]+a[72]+a[78]+a[77])
def arg232():
  return input(a[47]+a[75]+a[68]+a[64]+a[82]+a[68]+a[94]+a[68]+a[77]+a[83]+\
a[68]+a[81]+a[94]+a[66]+a[78]+a[81]+a[81]+a[68]+a[66]+a[83]+\
a[94]+a[79]+a[64]+a[82]+a[82]+a[86]+a[78]+a[81]+a[67]+a[94]+\
a[69]+a[78]+a[81]+a[94]+a[69]+a[75]+a[64]+a[70]+a[25]+a[94])
def arg132():
  return open('flag.txt.enc', 'rb').read()
def arg112():
  print(a[54]+a[68]+a[75]+a[66]+a[78]+a[76]+a[68]+a[94]+a[65]+a[64]+a[66]+\
a[74]+a[13]+a[13]+a[13]+a[94]+a[88]+a[78]+a[84]+a[81]+a[94]+a[69]+\
a[75]+a[64]+a[70]+a[11]+a[94]+a[84]+a[82]+a[68]+a[81]+a[25])
def arg122(arg432, arg423):
    arg433 = arg423
    i = 0
    while len(arg433) < len(arg432):
        arg433 = arg433 + arg423[i]
        i = (i + 1) % len(arg423)
    return "".join([chr(ord(arg422) ^ ord(arg442)) for (arg422,arg442) in zip(arg432,arg433)])
arg444 = arg132()
arg432 = arg232()
arg133(arg432)
arg112()
arg423 = arg111(arg444)
print(arg423)
sys.exit(0)
```

We can see the python script was deobfuscated. By manually deobfuscating it, we will get:
```py
import sys
a = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"+ \
            "[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ "

def check_usr_input(usr_input):
  if usr_input == "happychance":
    return True
  else:
    print('That password is incorrect')
    sys.exit(0)
    return False

def decode_with_key(encoded):
  return decode_process(encoded.decode(), "rapscallion")

def ask_input():
  return input("Please enter correct password for flag:")

def open_encoded_txt_file():
  return open('flag.txt.enc', 'rb').read()

def print_msg():
  print("Welcome back... your flag, user:")

def decode_process(usr_input, plain_flag):
    temp = plain_flag
    i = 0
    while len(temp) < len(usr_input):
        temp = temp + plain_flag[i]
        i = (i + 1) % len(plain_flag)
    return "".join([chr(ord(x) ^ ord(y)) for (x,y) in zip(usr_input,temp)])

encoded = open_encoded_txt_file()
usr_input = ask_input()
check_usr_input(usr_input)
print_msg()
plain_flag = decode_with_key(encoded)
print(plain_flag)
sys.exit(0)
```

From the deobfuscated source code, we can see we need to input a password in order to decrypt the encoded flag text file. However, the password is hardcoded:
```
happychance
```

With that being said, we just need to get the flag with the hardcoded password.

![IMG](/assets/images/picoctf2022-rev/bloat.png)

Flag:
```
picoCTF{d30bfu5c4710n_f7w_b8062eec}
```

# Fresh Java
## Description
Can you get the flag?
Reverse engineer this Java program.

This challenge provided a java file, by decompiling it, we get:
```java
// Decompiled with: CFR 0.151
// Class Version: 11
import java.util.Scanner;

public class KeygenMe {
    public static void main(String[] stringArray) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter key:");
        String string = scanner.nextLine();
        if (string.length() != 34) {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(33) != '}') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(32) != '9') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(31) != '8') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(30) != 'c') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(29) != 'a') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(28) != 'c') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(27) != '8') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(26) != '3') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(25) != '7') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(24) != '_') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(23) != 'd') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(22) != '3') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(21) != 'r') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(20) != '1') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(19) != 'u') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(18) != 'q') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(17) != '3') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(16) != 'r') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(15) != '_') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(14) != 'g') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(13) != 'n') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(12) != '1') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(11) != 'l') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(10) != '0') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(9) != '0') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(8) != '7') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(7) != '{') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(6) != 'F') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(5) != 'T') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(4) != 'C') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(3) != 'o') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(2) != 'c') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(1) != 'i') {
            System.out.println("Invalid key");
            return;
        }
        if (string.charAt(0) != 'p') {
            System.out.println("Invalid key");
            return;
        }
        System.out.println("Valid key");
    }
}
```

Again, hardcoded key, by concating it, we will get the flag.

Flag:
```
picoCTF{700l1ng_r3qu1r3d_738cac89}
```

# Bbbbloat
## Description
Can you get the flag?
Reverse engineer this binary.

This challenge provided a binary file.

I use Ghidra to disassemble this binary:
```c

undefined8 FUN_00101307(void)

{
  char *__s;
  long in_FS_OFFSET;
  int local_48;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = 0x4c75257240343a41;
  local_30 = 0x3062396630664634;
  local_28 = 0x65623066635f3d33;
  local_20 = 0x4e326560623535;
  printf("What\'s my favorite number? ");
  __isoc99_scanf();
  if (local_48 == 549255) {
    __s = (char *)FUN_00101249(0,&local_38);
    fputs(__s,stdout);
    putchar(10);
    free(__s);
  }
  else {
    puts("Sorry, that\'s not it!");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

From the decompiled code, we can see after it was for favorite number, it performs some kind of comparison:
```c
if (local_48 == 549255) {
	__s = (char *)FUN_00101249(0,&local_38);
	fputs(__s,stdout);
	putchar(10);
	free(__s);
}
```

So, let's try run the program with the number `549255`.

![IMG](/assets/images/picoctf2022-rev/Bbbbloat.png)

Flag:
```
picoCTF{cu7_7h3_bl047_36dd316a}
```

# unpackme
## Description
Can you get the flag?
Reverse engineer this binary.

This challenge provided a binary file.

The binary file was packed by using UPX, to unpack it, run the command below:
```
upx -d <file>
```

After that, same as **Bbbbloat** challenge, we use Ghidra to disassemble the binary:
```c

undefined8 main(void)

{
  long in_FS_OFFSET;
  int local_44;
  char *local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined4 local_20;
  undefined2 local_1c;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = 0x4c75257240343a41;
  local_30 = 0x30623e306b6d4146;
  local_28 = 0x3532666630486637;
  local_20 = 0x36665f60;
  local_1c = 0x4e;
  printf("What\'s my favorite number? ");
  __isoc99_scanf(&DAT_004b3020,&local_44);
  if (local_44 == 754635) {
    local_40 = (char *)rotate_encrypt(0,&local_38);
    fputs(local_40,(FILE *)stdout);
    putchar(10);
    free(local_40);
  }
  else {
    puts("Sorry, that\'s not it!");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

From the decompiled code, we can see after it was for favorite number, it performs some kind of comparison:
```c
if (local_44 == 754635) {
	local_40 = (char *)rotate_encrypt(0,&local_38);
	fputs(local_40,(FILE *)stdout);
	putchar(10);
	free(local_40);
}
```

So, let's try run the program with the number `754635`.

![IMG](/assets/images/picoctf2022-rev/unpackme.png)

Flag:
```
picoCTF{up><_m3_f7w_77ad107e}
```

# Keygenme
## Description
Can you get the flag?
Reverse engineer this binary.

This challenge provided a binary file.

By running the binary file, we can see it ask for license key:
![IMG](/assets/images/picoctf2022-rev/run-keygenme.png)

Below is the decompiled main function in Ghidra:
```c
undefined8 main(void)

{
  char result;
  long in_FS_OFFSET;
  char inpt [40];
  long canary;

  canary = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter your license key: ");
  fgets(inpt,0x25,stdin);
  result = validate(inpt);
  if (result == '\0') {
    puts("That key is invalid.");
  }
  else {
    puts("That key is valid.");
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

```

From the source code above, it asks for the license key, and then pass into the `validate()` function to validate whether the key is valid or not.

Looking into `validate()` function in Ghidra, it looks like nightmare for me, hence I decided to view it with IDA:
```c
__int64 __fastcall sub_55F390A28209(const char *inpt)
{
  int v2; // [rsp+18h] [rbp-C8h]
  int v3; // [rsp+18h] [rbp-C8h]
  int i; // [rsp+1Ch] [rbp-C4h]
  int j; // [rsp+20h] [rbp-C0h]
  int k; // [rsp+24h] [rbp-BCh]
  int m; // [rsp+28h] [rbp-B8h]
  char v8[34]; // [rsp+2Eh] [rbp-B2h] BYREF
  char half_flag[61]; // [rsp+50h] [rbp-90h] BYREF
  char v10; // [rsp+8Dh] [rbp-53h]
  char full_flag[72]; // [rsp+90h] [rbp-50h] BYREF
  unsigned __int64 v12; // [rsp+D8h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  strcpy(half_flag, "picoCTF{br1ng_y0ur_0wn_k3y_");// half_flag_len = 27
                                                // flag_len = 37
                                                //
  strcpy(v8, "}");
  strlen(half_flag);                            // 27
  MD5();
  strlen(v8);                                   // 1
  MD5();
  v2 = 0;
  for ( i = 0; i <= 15; ++i )
  {
    sprintf(&half_flag[v2 + 32], "%02x", (unsigned __int8)v8[i + 2]);
    v2 += 2;
  }
  v3 = 0;
  for ( j = 0; j <= 15; ++j )
  {
    sprintf(&full_flag[v3], "%02x", (unsigned __int8)v8[j + 18]);
    v3 += 2;
  }
  for ( k = 0; k <= 26; ++k )
    full_flag[k + 32] = half_flag[k];
  full_flag[59] = half_flag[45];
  full_flag[60] = half_flag[50];
  full_flag[61] = v10;
  full_flag[62] = half_flag[33];
  full_flag[63] = half_flag[46];
  full_flag[64] = half_flag[56];
  full_flag[65] = half_flag[58];
  full_flag[66] = v10;
  full_flag[67] = v8[0];
  if ( strlen(inpt) != 36 )
    return 0LL;
  for ( m = 0; m <= 35; ++m )
  {
    if ( inpt[m] != full_flag[m + 32] )
      return 0LL;
  }
  return 1LL;
}
```

The code above is the cleaned version by me but i have to admit it still looks messy to be honest.

From the code above, we can see half of the flag:
```
picoCTF{br1ng_y0ur_0wn_k3y_
```

Besides that, the only information i observed is the length of of the full flag, which is 37. Next, we can see the code contains `MD5()` function. I'm guessing that the result of that function is used in further iterations.

Furthermore, we can guess that the full flag will exists by concating the `half_flag` array in this piece of code:
```c
for ( k = 0; k <= 26; ++k )
	full_flag[k + 32] = half_flag[k];
full_flag[59] = half_flag[45];
full_flag[60] = half_flag[50];
full_flag[61] = v10;
full_flag[62] = half_flag[33];
full_flag[63] = half_flag[46];
full_flag[64] = half_flag[56];
full_flag[65] = half_flag[58];
full_flag[66] = v10;
full_flag[67] = v8[0];
```

Because it will perform checking with our input later by comparing with the full flag:
```c
for ( m = 0; m <= 35; ++m )
{
	if ( inpt[m] != full_flag[m + 32] )
  		return 0LL;
}
```

At this point, i decides to debug it using debugger, i specifically paying extra attention when approaching these code while debugging:
```c
full_flag[59] = half_flag[45];
full_flag[60] = half_flag[50];
full_flag[61] = v10;
full_flag[62] = half_flag[33];
full_flag[63] = half_flag[46];
full_flag[64] = half_flag[56];
full_flag[65] = half_flag[58];
full_flag[66] = v10;
full_flag[67] = v8[0];
```

Eventually, i got the 8 last bytes of full flag byte by byte, which are the following:
```
0x7d
0x39
0x38
0x33
0x36
0x63
0x64
0x38
```

By using Python to concat it, we will get:
```
}9836cd8
```

![IMG](/assets/images/picoctf2022-rev/py-keygenme.png)

However, it appeared to be reversed, we just need to simply reverse it and concat with the half of the flag we obtained earlier to get the full flag.

Flag:
```
picoCTF{br1ng_y0ur_0wn_k3y_19836cd8}
```

Thank you so much for reading till here, have a great day ahead !
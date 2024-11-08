---
title: "[HITCONCTF-QUALS] Antivirus"
excerpt_separator: <!--more-->
categories:
  - CTF
tags:
  - HITCONCTF-QUALS
  - REV
  - ClamAV
  - "2024"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

I played HITCON Quals CTF 2024 with merger team World Wide Union.

This challenge provided a `run.sh` and `print_flag.cbc` file.

<!--more-->

Content of `run.sh` is as follow:
```
#!/bin/sh

docker run -v /home/ctf/clamav/:/test/ --rm -it clamav/clamav clamscan --bytecode-unsigned -d/test/print_flag.cbc /test/sample.exe
```

Looking at it, this is obviously a bytecode challenge, specifically ClamAV's bytecode.

# Setting up ClamAV
Below are the commands used to install ClamAV from scratch, please ensure you have **ninja** installed in prior:
```bash
sudo apt-get update && apt-get install -y \
  `# install tools` \
  gcc make pkg-config python3 python3-pip python3-pytest valgrind cmake \
  `# install clamav dependencies` \
  check libbz2-dev libcurl4-openssl-dev libjson-c-dev libmilter-dev \
  libncurses5-dev libpcre2-dev libssl-dev libxml2-dev zlib1g-dev


git clone https://github.com/Cisco-Talos/clamav.git
mkdir build
cd build
cmake .. -G Ninja \
    -D CMAKE_BUILD_TYPE=Debug \
    -D OPTIMIZE=OFF \
    -D CMAKE_INSTALL_PREFIX=`pwd`/install \
    -D ENABLE_EXAMPLES=ON \
    -D ENABLE_STATIC_LIB=ON \
    -D ENABLE_SYSTEMD=OFF

cmake --build . --target install

# To debug, getting output from function cli_dbgmsg
./clamscan/clamscan --bytecode-unsigned -dprint_flag.cbc ./example_pe_file.exe --debug 2>&1

# To run normally
./clamscan/clamscan --bytecode-unsigned -dprint_flag.cbc ./example_pe_file.exe
```

# Bytecode Disassemble
At first, I spent a lot of time modifying the source code in `/libclamav/bytecode.c` to call two apparent unused functions (`cli_byteinst_describe` & `cli_bytefunc_describe`) to spit out the bytecode debugging information runtime.

However, later our teammate **tamponlover69** mentioned that we can get the bytecode IR with the following command, which is a tool provided by ClamAV:
```
clambc --printbcir print_flag.cbc
```

The output IR is as follows (with some parts truncated due to length):
```
found 25 extra types of 89 total, starting at tid 69
TID  KIND                INTERNAL
------------------------------------------------------------------------
 65: DPointerType        i8*
 66: DPointerType        i16*
 67: DPointerType        i32*
 68: DPointerType        i64*
 69: DArrayType          [1 x i8]
 70: DArrayType          [2 x i8]
 71: DArrayType          [3 x i8]
 72: DArrayType          [4 x i8]
 73: DArrayType          [5 x i8]
 74: DArrayType          [6 x i8]
 75: DArrayType          [7 x i8]
 76: DPointerType        [32 x i8]*
 77: DPointerType        [396 x i8]*
 78: DPointerType        [16 x i8]*
 79: DPointerType        i8**
 80: DArrayType          [1024 x i8]
 81: DPointerType        [1024 x i8]*
 82: DFunctionType       i32 func ( i32 i32 )
 83: DFunctionType       i32 func ( i32 i32 )
 84: DFunctionType       i0 func ( i0 i0 i0 i0 )
 85: DFunctionType       i0 func ( i0 i0 i0 i0 )
 86: DArrayType          [16 x i8]
 87: DArrayType          [396 x i8]
 88: DArrayType          [32 x i8]
------------------------------------------------------------------------
########################################################################
####################### Function id   0 ################################
########################################################################
found a total of 13 globals
GID  ID    VALUE
------------------------------------------------------------------------
  0 [  0]: i0 unknown
  1 [  1]: [32 x i8] unknown
  2 [  2]: [396 x i8] unknown
  3 [  3]: [16 x i8] unknown
  4 [  4]: [16 x i8] unknown
  5 [  5]: i8* unknown
  6 [  6]: i8* unknown
  7 [  7]: i8* unknown
  8 [  8]: i8* unknown
  9 [  9]: i8* unknown
 10 [ 10]: i8* unknown
 11 [ 11]: i8* unknown
 12 [ 12]: i8* unknown
------------------------------------------------------------------------
found 30 values with 0 arguments and 30 locals
VID  ID    VALUE
------------------------------------------------------------------------
  0 [  0]: alloc i64
  1 [  1]: alloc i64
  2 [  2]: alloc i8*
  3 [  3]: alloc [1024 x i8]
  4 [  4]: i8*
  5 [  5]: i32
  6 [  6]: i1
  7 [  7]: i32
  8 [  8]: i32
  9 [  9]: i32
 10 [ 10]: i32
 11 [ 11]: i1
 12 [ 12]: i64
 13 [ 13]: i64
 14 [ 14]: i64
 15 [ 15]: i32
 16 [ 16]: i8*
 17 [ 17]: i8*
 18 [ 18]: i8
 19 [ 19]: i64
 20 [ 20]: i64
 21 [ 21]: i32
 22 [ 22]: i8*
 23 [ 23]: i8*
 24 [ 24]: i8
 25 [ 25]: i1
 26 [ 26]: i64
 27 [ 27]: i32
 28 [ 28]: i64
 29 [ 29]: i32
------------------------------------------------------------------------
found a total of 23 constants
CID  ID    VALUE
------------------------------------------------------------------------
  0 [ 30]: 0(0x0)
  1 [ 31]: 0(0x0)
  2 [ 32]: 2(0x2)
  3 [ 33]: 0(0x0)
  4 [ 34]: 1024(0x400)
  5 [ 35]: 396(0x18c)
  6 [ 36]: 15(0xf)
  7 [ 37]: 1(0x1)
  8 [ 38]: 0(0x0)
  9 [ 39]: 0(0x0)
 10 [ 40]: 396(0x18c)
 11 [ 41]: 396(0x18c)
 12 [ 42]: 0(0x0)
 13 [ 43]: 396(0x18c)
 14 [ 44]: 32(0x20)
 15 [ 45]: 32(0x20)
 16 [ 46]: 32(0x20)
 17 [ 47]: 32(0x20)
 18 [ 48]: 0(0x0)
 19 [ 49]: 1(0x1)
 20 [ 50]: 0(0x0)
 21 [ 51]: 15(0xf)
 22 [ 52]: 1(0x1)
------------------------------------------------------------------------
found a total of 53 total values
------------------------------------------------------------------------
FUNCTION ID: F.0 -> NUMINSTS 40
BB   IDX  OPCODE              [ID /IID/MOD]  INST
------------------------------------------------------------------------
  0    0  OP_BC_GEPZ          [36 /184/  4]  4 = gepz p.3 + (30)
  0    1  OP_BC_CALL_API      [33 /168/  3]  5 = seek[3] (31, 32)
  0    2  OP_BC_MEMSET        [40 /200/  0]  0 = memset (p.4, 33, 34)
  0    3  OP_BC_ICMP_EQ       [21 /108/  3]  6 = (5 == 35)
  0    4  OP_BC_BRANCH        [17 / 85/  0]  br 6 ? bb.2 : bb.1

  1    5  OP_BC_CALL_API      [33 /168/  3]  7 = setvirusname[4] (p.-2147483636, 36)
  1    6  OP_BC_COPY          [34 /174/  4]  cp 37 -> 0
  1    7  OP_BC_JMP           [18 / 90/  0]  jmp bb.6

  2    8  OP_BC_CALL_API      [33 /168/  3]  8 = seek[3] (38, 39)
  2    9  OP_BC_CALL_API      [33 /168/  3]  9 = read[1] (p.4, 40)
  2   10  OP_BC_CALL_DIRECT   [32 /163/  3]  10 = call F.1 (4, 41)
  2   11  OP_BC_COPY          [34 /174/  4]  cp 42 -> 1
  2   12  OP_BC_JMP           [18 / 90/  0]  jmp bb.4

  3   13  OP_BC_ICMP_ULT      [25 /129/  4]  11 = (26 < 43)
  3   14  OP_BC_COPY          [34 /174/  4]  cp 26 -> 1
  3   15  OP_BC_BRANCH        [17 / 85/  0]  br 11 ? bb.4 : bb.5

  4   16  OP_BC_COPY          [34 /174/  4]  cp 1 -> 12
  4   17  OP_BC_SHL           [8  / 44/  4]  13 = 12 << 44
  4   18  OP_BC_ASHR          [10 / 54/  4]  14 = 13 >> 45
  4   19  OP_BC_TRUNC         [14 / 73/  3]  15 = 14 trunc ffffffffffffffff
  4   20  OP_BC_COPY          [34 /174/  4]  cp -2147483640 -> 2
  4   21  OP_BC_COPY          [34 /174/  4]  cp 2 -> 16
  4   22  OP_BC_GEP1          [35 /179/  4]  17 = gep1 p.16 + (15 * 65)
  4   23  OP_BC_LOAD          [39 /196/  1]  load  18 <- p.17
  4   24  OP_BC_SHL           [8  / 44/  4]  19 = 12 << 46
  4   25  OP_BC_ASHR          [10 / 54/  4]  20 = 19 >> 47
  4   26  OP_BC_TRUNC         [14 / 73/  3]  21 = 20 trunc ffffffffffffffff
  4   27  OP_BC_GEPZ          [36 /184/  4]  22 = gepz p.3 + (48)
  4   28  OP_BC_GEP1          [35 /179/  4]  23 = gep1 p.22 + (21 * 65)
  4   29  OP_BC_LOAD          [39 /196/  1]  load  24 <- p.23
  4   30  OP_BC_ICMP_EQ       [21 /106/  1]  25 = (18 == 24)
  4   31  OP_BC_ADD           [1  /  9/  0]  26 = 12 + 49
  4   32  OP_BC_COPY          [34 /174/  4]  cp 50 -> 0
  4   33  OP_BC_BRANCH        [17 / 85/  0]  br 25 ? bb.3 : bb.6

  5   34  OP_BC_CALL_API      [33 /168/  3]  27 = setvirusname[4] (p.-2147483638, 51)
  5   35  OP_BC_COPY          [34 /174/  4]  cp 52 -> 0
  5   36  OP_BC_JMP           [18 / 90/  0]  jmp bb.6

  6   37  OP_BC_COPY          [34 /174/  4]  cp 0 -> 28
  6   38  OP_BC_TRUNC         [14 / 73/  3]  29 = 28 trunc ffffffffffffffff
  6   39  OP_BC_RET           [19 / 98/  3]  ret 29
------------------------------------------------------------------------
########################################################################
####################### Function id   1 ################################
########################################################################
found a total of 13 globals
GID  ID    VALUE
------------------------------------------------------------------------
  0 [  0]: i0 unknown
  1 [  1]: [32 x i8] unknown
  2 [  2]: [396 x i8] unknown
  3 [  3]: [16 x i8] unknown
  4 [  4]: [16 x i8] unknown
  5 [  5]: i8* unknown
  6 [  6]: i8* unknown
  7 [  7]: i8* unknown
  8 [  8]: i8* unknown
  9 [  9]: i8* unknown
 10 [ 10]: i8* unknown
 11 [ 11]: i8* unknown
 12 [ 12]: i8* unknown
------------------------------------------------------------------------
found 303 values with 2 arguments and 301 locals
VID  ID    VALUE
------------------------------------------------------------------------
  0 [  0]: i8* argument
  1 [  1]: i32 argument
  2 [  2]: alloc i64
  3 [  3]: alloc i64
  4 [  4]: alloc i64
  5 [  5]: alloc i64
  6 [  6]: alloc i64
  7 [  7]: alloc i64
  8 [  8]: alloc i64
  9 [  9]: alloc i64
 10 [ 10]: alloc i64
 11 [ 11]: alloc i64
 12 [ 12]: alloc i8*
 13 [ 13]: alloc i8*
 14 [ 14]: alloc i8*
 15 [ 15]: alloc i8*
 <SNIP>
299 [299]: i8
300 [300]: i8
301 [301]: i64
302 [302]: i1
------------------------------------------------------------------------
found a total of 154 constants
CID  ID    VALUE
------------------------------------------------------------------------
  0 [303]: 7(0x7)
  1 [304]: 0(0x0)
  2 [305]: 0(0x0)
  3 [306]: 32(0x20)
  4 [307]: 32(0x20)
  5 [308]: 255(0xff)
  6 [309]: 0(0x0)
  7 [310]: 0(0x0)
  8 [311]: 4290493196(0xffbbbb0c)
  9 [312]: 1(0x1)
 10 [313]: 0(0x0)
 11 [314]: 4290772926(0xffbfffbe)
 12 [315]: 1(0x1)
 13 [316]: 0(0x0)
 14 [317]: 16(0x10)
 15 [318]: 22(0x16)
 16 [319]: 22(0x16)
 17 [320]: 22(0x16)
 18 [321]: 6(0x6)
 19 [322]: 0(0x0)
 20 [323]: 4290509612(0xffbbfb2c)
 21 [324]: 1(0x1)
 22 [325]: 0(0x0)
 <SNIP>
150 [453]: 1(0x1)
151 [454]: 32(0x20)
152 [455]: 1(0x1)
153 [456]: 1(0x1)
------------------------------------------------------------------------
found a total of 457 total values
------------------------------------------------------------------------
FUNCTION ID: F.1 -> NUMINSTS 453
BB   IDX  OPCODE              [ID /IID/MOD]  INST
------------------------------------------------------------------------
  0    0  OP_BC_TRUNC         [14 / 71/  1]  19 = 1 trunc ffffffff
  0    1  OP_BC_AND           [11 / 56/  1]  20 = 19 & 303
  0    2  OP_BC_ICMP_EQ       [21 /108/  3]  21 = (1 == 304)
  0    3  OP_BC_BRANCH        [17 / 85/  0]  br 21 ? bb.92 : bb.1

  1    4  OP_BC_ZEXT          [16 / 84/  4]  22 = 1 zext ffffffff
  1    5  OP_BC_COPY          [34 /174/  4]  cp 305 -> 11
  1    6  OP_BC_JMP           [18 / 90/  0]  jmp bb.2

  <SNIP>
 92  452  OP_BC_RET           [19 / 98/  3]  ret 456
------------------------------------------------------------------------
```

From the looks of it, there are two functions (`F.0` and `F.1`), we can assumed that `F.0` is like the typical `main` function in C code. Let's analyze the first 5 opcodes from `F.0` to understand what it does:
```
0    0  OP_BC_GEPZ          [36 /184/  4]  4 = gepz p.3 + (30)
0    1  OP_BC_CALL_API      [33 /168/  3]  5 = seek[3] (31, 32)
0    2  OP_BC_MEMSET        [40 /200/  0]  0 = memset (p.4, 33, 34)
0    3  OP_BC_ICMP_EQ       [21 /108/  3]  6 = (5 == 35)
0    4  OP_BC_BRANCH        [17 / 85/  0]  br 6 ? bb.2 : bb.1
```

The opcode `OP_BC_GEPZ` is in charge of resolving the pointer value, the `(30)` in this case is the a constant value `0`, which can be obtain by referencing the constants table : `0 [ 30]: 0(0x0)`.

The opcode `OP_BC_CALL_API`, is in charge of calling API, in this case it is calling `seek` with argument `(31, 32)`, by referencing the constants table again, we will get:
```
1 [ 31]: 0(0x0)
2 [ 32]: 2(0x2)
```
And looking at the implementation of `seek` function call, this suggest that it is actually getting the sizes of input. The value 2 indicate `SEEK_END`. Since our input is an EXE file, we can assume that it is getting the sizes of our input file.

The opcode `OP_BC_MEMSET` is pretty straight forward, is setting the 0x400 bytes in memory to NULL (0x00), again, you can obtain the values from the constants table above.

The opcode `OP_BC_ICMP_EQ` in charge of comparison, its comparing 5 (our input file size) with 35 (correspond to constant value 396). This suggest that our input EXE file has to be file size of 396 bytes.

**Extra Note:**

It is worth mention that for example the value `-2147483638` appears below in **F.0**, must be converted to an unsigned value. This conversion is done by performing `-2147483638 & 0x7FFFFFFF`, which results in `6`. This value points to the global value `[6]`:
```
5   34  OP_BC_CALL_API      [33 /168/  3]  27 = setvirusname[4] (p.-2147483638, 51)
```

# F.0
This function is calculating our input file size, ensure it is 396 bytes before proceed, and later perform values comparison of the ciphertext from global constant with the input file byte values that is encrypted in **F.1**.

# F.1
This function is huge, the conclusion from our teammate is it will generates a keystream and then XOR it with each bytes from the input EXE file. You can use the script in [SECCON CTF 2022 Quals - Devil Hunter](https://tan.hatenadiary.jp/entry/2022/11/13/214219#reversing-Devil-Hunter-168-solves-31-points) to generate a C file from the IR then proceed with analyzing in your favourite decompiler.

# Solution
We all the information given, we can patch `/libclamav/bytecode_vm.c` like below to make it spit out important information for us, like the for the example what values being compared during the opcode `OP_BC_ICMP_EQ`:
```diff
diff --git a/libclamav/bytecode_vm.c b/libclamav/bytecode_vm.c
index 6c4d46c23..46dbb828d 100644
--- a/libclamav/bytecode_vm.c
+++ b/libclamav/bytecode_vm.c
@@ -831,16 +831,26 @@ cl_error_t cli_vm_execute(const struct cli_bc *bc, struct cli_bc_ctx *ctx, const
             DEFINE_OP_BC_RET_VOID(OP_BC_RET_VOID * 5 + 3, uint8_t);
             DEFINE_OP_BC_RET_VOID(OP_BC_RET_VOID * 5 + 4, uint8_t);

-            DEFINE_ICMPOP(OP_BC_ICMP_EQ, res = (op0 == op1));
-            DEFINE_ICMPOP(OP_BC_ICMP_NE, res = (op0 != op1));
-            DEFINE_ICMPOP(OP_BC_ICMP_UGT, res = (op0 > op1));
-            DEFINE_ICMPOP(OP_BC_ICMP_UGE, res = (op0 >= op1));
-            DEFINE_ICMPOP(OP_BC_ICMP_ULT, res = (op0 < op1));
-            DEFINE_ICMPOP(OP_BC_ICMP_ULE, res = (op0 <= op1));
-            DEFINE_ICMPOP(OP_BC_ICMP_SGT, res = (sop0 > sop1));
-            DEFINE_ICMPOP(OP_BC_ICMP_SGE, res = (sop0 >= sop1));
-            DEFINE_ICMPOP(OP_BC_ICMP_SLE, res = (sop0 <= sop1));
-            DEFINE_ICMPOP(OP_BC_ICMP_SLT, res = (sop0 < sop1));
+            // DEFINE_ICMPOP(OP_BC_ICMP_EQ, res = (op0 == op1));
+            // DEFINE_ICMPOP(OP_BC_ICMP_NE, res = (op0 != op1));
+            // DEFINE_ICMPOP(OP_BC_ICMP_UGT, res = (op0 > op1));
+            // DEFINE_ICMPOP(OP_BC_ICMP_UGE, res = (op0 >= op1));
+            // DEFINE_ICMPOP(OP_BC_ICMP_ULT, res = (op0 < op1));
+            // DEFINE_ICMPOP(OP_BC_ICMP_ULE, res = (op0 <= op1));
+            // DEFINE_ICMPOP(OP_BC_ICMP_SGT, res = (sop0 > sop1));
+            // DEFINE_ICMPOP(OP_BC_ICMP_SGE, res = (sop0 >= sop1));
+            // DEFINE_ICMPOP(OP_BC_ICMP_SLE, res = (sop0 <= sop1));
+            // DEFINE_ICMPOP(OP_BC_ICMP_SLT, res = (sop0 < sop1));
+            DEFINE_ICMPOP(OP_BC_ICMP_EQ, printf("OP_BC_ICMP_EQ : %d = %x == %x\n", bb_inst, op0, op1); res = (op0 == op1));
+            DEFINE_ICMPOP(OP_BC_ICMP_NE, printf("OP_BC_ICMP_NE : %d = %x != %x\n", bb_inst, op0, op1); res = (op0 != op1));
+            DEFINE_ICMPOP(OP_BC_ICMP_UGT, printf("OP_BC_ICMP_UGT : %d = %x > %x\n", bb_inst, op0, op1); res = (op0 > op1));
+            DEFINE_ICMPOP(OP_BC_ICMP_UGE, printf("OP_BC_ICMP_UGE : %d = %x >= %x\n", bb_inst, op0, op1); res = (op0 >= op1));
+            DEFINE_ICMPOP(OP_BC_ICMP_ULT, printf("OP_BC_ICMP_ULT : %d = %x < %x\n", bb_inst, op0, op1); res = (op0 < op1));
+            DEFINE_ICMPOP(OP_BC_ICMP_ULE, printf("OP_BC_ICMP_ULE : %d = %x <= %x\n", bb_inst, op0, op1); res = (op0 <= op1));
+            DEFINE_ICMPOP(OP_BC_ICMP_SGT, printf("OP_BC_ICMP_SGT : %d = %x > %x\n", bb_inst, sop0, sop1); res = (sop0 > sop1));
+            DEFINE_ICMPOP(OP_BC_ICMP_SGE, printf("OP_BC_ICMP_SGE : %d = %x >= %x\n", bb_inst, sop0, sop1); res = (sop0 >= sop1));
+            DEFINE_ICMPOP(OP_BC_ICMP_SLE, printf("OP_BC_ICMP_SLE : %d = %x <= %x\n", bb_inst, sop0, sop1); res = (sop0 <= sop1));
+            DEFINE_ICMPOP(OP_BC_ICMP_SLT, printf("OP_BC_ICMP_SLT : %d = %x < %x\n", bb_inst, sop0, sop1); res = (sop0 < sop1));

             case OP_BC_SELECT * 5: {
                 uint8_t t0, t1, t2;
@@ -1073,30 +1083,40 @@ cl_error_t cli_vm_execute(const struct cli_bc *bc, struct cli_bc_ctx *ctx, const
                 uint8_t op;
                 READ1(op, BINOP(0));
                 WRITE8(BINOP(1), op);
+                printf("OP_BC_COPY * 5: op=%lu\n", op);
+                printf("SRC=%u , DST=%u\n", BINOP(0), BINOP(1));
                 break;
             }
             case OP_BC_COPY * 5 + 1: {
                 uint8_t op;
                 READ8(op, BINOP(0));
                 WRITE8(BINOP(1), op);
+                printf("OP_BC_COPY * 5 + 1: op=%lu\n", op);
+                printf("SRC=%u , DST=%u\n", BINOP(0), BINOP(1));
                 break;
             }
             case OP_BC_COPY * 5 + 2: {
                 uint16_t op;
                 READ16(op, BINOP(0));
                 WRITE16(BINOP(1), op);
+                printf("OP_BC_COPY * 5 + 2: op=%lu\n", op);
+                printf("SRC=%u , DST=%u\n", BINOP(0), BINOP(1));
                 break;
             }
             case OP_BC_COPY * 5 + 3: {
                 uint32_t op;
                 READ32(op, BINOP(0));
                 WRITE32(BINOP(1), op);
+                printf("OP_BC_COPY * 5 + 3: op=%lu\n", op);
+                printf("SRC=%u , DST=%u\n", BINOP(0), BINOP(1));
                 break;
             }
             case OP_BC_COPY * 5 + 4: {
                 uint64_t op;
                 READ64(op, BINOP(0));
                 WRITE64(BINOP(1), op);
+                printf("OP_BC_COPY * 5 + 4: op=%lu\n", op);
+                printf("SRC=%u , DST=%u\n", BINOP(0), BINOP(1));
                 break;
             }

@@ -1105,24 +1125,28 @@ cl_error_t cli_vm_execute(const struct cli_bc *bc, struct cli_bc_ctx *ctx, const
                 uint8_t *ptr;
                 READPOP(ptr, inst->u.unaryop, 1);
                 WRITE8(inst->dest, (*ptr));
+                printf("OP_BC_LOAD * 5: value=%x\n", *ptr);
                 break;
             }
             case OP_BC_LOAD * 5 + 2: {
                 const union unaligned_16 *ptr;
                 READPOP(ptr, inst->u.unaryop, 2);
                 WRITE16(inst->dest, (ptr->una_u16));
+                printf("OP_BC_LOAD * 5 + 2: value=%x\n", *ptr);
                 break;
             }
             case OP_BC_LOAD * 5 + 3: {
                 const union unaligned_32 *ptr;
                 READPOP(ptr, inst->u.unaryop, 4);
                 WRITE32(inst->dest, (ptr->una_u32));
+                printf("OP_BC_LOAD * 5 + 3: value=%x\n", *ptr);
                 break;
             }
             case OP_BC_LOAD * 5 + 4: {
                 const union unaligned_64 *ptr;
                 READPOP(ptr, inst->u.unaryop, 8);
                 WRITE64(inst->dest, (ptr->una_u64));
+                printf("OP_BC_LOAD * 5 + 4: value=%x\n", *ptr);
                 break;
             }
```

Now when we run the command to load the bytecode on example EXE again, we will get tons of information, what we want specifically is the 4 lines after `SRC=16 , DST=1120`, like below:
```
SRC=16 , DST=1120
OP_BC_LOAD * 5: value=45
OP_BC_LOAD * 5: value=45
OP_BC_ICMP_EQ : 14 = 45 == 45
OP_BC_COPY * 5 + 4: op=0
--
SRC=16 , DST=1120
OP_BC_LOAD * 5: value=5f
OP_BC_LOAD * 5: value=5f
OP_BC_ICMP_EQ : 14 = 5f == 5f
```

From the output it is pretty clear that it is doing comparison, and we get the ciphertext too, therefore what we need to do now is write a script to solve it !

## Solve Script
```py
import subprocess
import regex as re


def check(buffer):
    # save buffer to file
    open("inp", "wb").write(buffer)

    # run command and get input "clamscan --bytecode-unsigned -dprint_flag.cbc inp"
    p = subprocess.Popen(
        ["./clamscan/clamscan", "--bytecode-unsigned", "-dprint_flag.cbc", "inp"],
        stdout=subprocess.PIPE,
    )
    out, _ = p.communicate()
    return out


def filtering_output(output):
    # SRC=16 , DST=1120
    # OP_BC_LOAD * 5: value=45
    # OP_BC_LOAD * 5: value=45
    # OP_BC_ICMP_EQ : 14 = 45 == 45
    # OP_BC_COPY * 5 + 4: op=0
    m = re.findall(
        r"""SRC=16 , DST=1120
OP_BC_LOAD \* 5: value=([\dabcdefABCDEF]+)
OP_BC_LOAD \* 5: value=([\dabcdefABCDEF]+)
OP_BC_ICMP_EQ : 14 = [\dabcdefABCDEF]+ == [\dabcdefABCDEF]+
OP_BC_COPY \* 5 \+ 4: op=0""",
        output,
    )
    return m


len_buffer = 0x18C

buffer = bytearray(b"\x00" * len_buffer)
buffer[0] = 0x4D
buffer[1] = 0x5A
known = 2

while known != len_buffer:
    out = check(buffer)
    list_known = filtering_output(out.decode())
    len_list_known = len(list_known)

    assert len_list_known >= known, "Must be more known bytes"

    buffer[len_list_known-1] = int(list_known[len_list_known-1][0], 16) ^ int(list_known[len_list_known-1][1], 16) ^ 0x0

    # print(hex(buffer[len_list_known-1]) + "=" + list_known[len_list_known-1][0] + "^" + list_known[len_list_known-1][1])

    known = len_list_known

open("flag.exe", "wb").write(buffer)
```

Or if you prefer a slow script that doesn't required you to analyze the **F.1** at all:
```py
#!/usr/bin/env python3
import subprocess
import re
import tqdm

def create_pe_file(filename, file_content, file_size):
    # Write the content to a file
    with open(filename, 'wb') as file:
        file.write(file_content)

def main():

    known = 6
    file_size = 0x0000018C

    command = ["./clamscan/clamscan", "--bytecode-unsigned", "-dprint_flag.cbc", "./example_pe.exe"]
    file_content = bytearray(b'MZ\x00\x00PE' + b'\x00' * (file_size - 6))

    while tqdm.tqdm(known < file_size):

        max_count_len = 0
        latest_known_byte = 0

        for byte in range(0xFF):
            file_content[known] = byte
            create_pe_file('example_pe.exe', file_content, file_size)

            result = subprocess.run(command, capture_output=True, text=True, check=True)

            count_len_result = re.findall(r"""SRC=16 , DST=1120
OP_BC_LOAD \* 5: value=([\dabcdefABCDEF]+)
OP_BC_LOAD \* 5: value=([\dabcdefABCDEF]+)
OP_BC_ICMP_EQ : 14 = [\dabcdefABCDEF]+ == [\dabcdefABCDEF]+
OP_BC_COPY \* 5 \+ 4: op=0""",
                result.stdout
                )
            if len(count_len_result) > max_count_len:
                max_count_len = len(count_len_result)
                latest_known_byte = byte

        file_content[known] = latest_known_byte
        print(file_content)

        known += 1


if __name__ == '__main__':
    main()
```

The correct EXE file should be like follow:
```
└─$ xxd flag.exe
00000000: 4d5a 0000 5045 0000 6486 0100 0000 0000  MZ..PE..d.......
00000010: 0000 0000 0000 0000 8000 2200 0b02 0000  ..........".....
00000020: 8201 0000 0000 0000 0000 0000 2601 0000  ............&...
00000030: 0a00 0000 0000 0040 0100 0000 0400 0000  .......@........
00000040: 0400 0000 0600 0000 0000 0000 0600 0000  ................
00000050: 0000 0000 8c01 0000 e900 0000 0000 0000  ................
00000060: 0300 6081 0000 1000 0000 0000 0010 0000  ..`.............
00000070: 0000 0000 0000 1000 0000 0000 0010 0000  ................
00000080: 0000 0000 0000 0000 0200 0000 0000 0000  ................
00000090: 0000 0000 6001 0000 2c00 0000 2e00 0000  ....`...,.......
000000a0: 0000 0000 8201 0000 1601 0000 8201 0000  ................
000000b0: 1601 0000 a0a1 bcab a7a6 b3bb adab baad  ................
000000c0: bc97 bda6 b8a9 aba3 adba 97a1 a697 aba4  ................
000000d0: a9a5 a9be 97aa b1bc adab a7ac ad97 bba1  ................
000000e0: afa6 a9bc bdba adb5 0094 0247 6574 5374  ...........GetSt
000000f0: 6448 616e 646c 6500 9502 5772 6974 6543  dHandle...WriteC
00000100: 6f6e 736f 6c65 4100 4b45 524e 454c 3332  onsoleA.KERNEL32
00000110: 2e64 6c6c 0000 e900 0000 0000 0000 f800  .dll............
00000120: 0000 0000 0000 b9f5 ffff ffff 15e5 ffff  ................
00000130: ff45 31c9 458d 4135 488d 1575 ffff ff48  .E1.E.A5H..u...H
00000140: 31c9 8034 0ac8 48ff c148 83f9 3575 f348  1..4..H..H..5u.H
00000150: 8d15 5eff ffff 4889 c1ff 15bf ffff ffc3  ..^...H.........
00000160: 7401 0000 0000 0000 0000 0000 0801 0000  t...............
00000170: 1601 0000 e900 0000 0000 0000 f800 0000  ................
00000180: 0000 0000 0000 0000 0000 0000            ............
```

Execute it in Windows environment and we will get a flag.

Flag:
```
hitcon{secret_unpacker_in_clamav_bytecode_signature}
```

# References
- [SECCON CTF 2022 Quals - Devil Hunter](https://tan.hatenadiary.jp/entry/2022/11/13/214219#reversing-Devil-Hunter-168-solves-31-points)


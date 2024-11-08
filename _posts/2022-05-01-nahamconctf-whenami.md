---
title: "[NAHAMCONCTF] WhenAmI"
excerpt_separator: <!--more-->
categories:
  - CTF
tags:
  - NAHAMCONCTF
  - MISC
  - "2022"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

# Task source:
https://github.com/Tzion0/CTF/tree/master/NahamConCTF/2022/Miscellaneous/WhenAmI

# Description
I know where I am, but... when am I?

This challenge provided a txt file.

<!--more-->

Content of txt file:
```
When am I??

So, I look down at my watch. It's December 28, 2011 at 11:59AM, and I'm just minding my own business at -13.582075733990298, -172.5084838587106.
I hung out there until the local time was 1:00AM on December 31st, and then I hopped on a plane and took a 1 hour flight over to -14.327595989244111, -170.71287979386747.
Some time has passed since I landed, and on December 30th, 12PM local time, I took a 1 hour flight back to my original location.
It's been 10 hours since I landed on my most recent flight - how many seconds have passed since I first looked at my watch?

(Submission format is flag{<number of seconds goes here>}, such as flag{600}.)
```

This is quite a fun challenge, and I enjoy solving it.

Before we begin, let me convert those geographic coordinates into its places name:
```
-13.582075733990298, -172.5084838587106	 : "A'opo Conservation Area, Samoa"
-14.327595989244111, -170.71287979386747 : "Tualauta, Western District, American Samoa"
```

Google also shows that **A'opo Conservation Area, Samoa** is 24 hours ahead of **Tualauta, Western District, American Samoa**.

Now let's start counting:
```
1 min + 12 hrs (29 December)
+ 24 hrs       (31 December)
+ 1 hr         (Because local time 1 AM)
+ 1 hr         (1 hour flight to Tualauta)
+ 10 hr        (Tualauta localtime December 30th, 12PM, which means "A'opo" is now December 31th, 12pm, and assuming "A'opo" was at 2 AM after arrived at Tualauta, so 12 - 2 = 10)
+ 1 hr 		   (1 hour flight back to "A'opo")
+ 10 hr    	   ("It's been 10 hours since I landed on my most recent flight")
+ 1 hr 		   (DST)
```

So, after 12 hrs and 1 min of 11:59 AM, December 28, 2011, we will enter 29 December, and after 24 hrs more we will be enter to 31 December. Why 31 instead of 30? Well, this is because **Samoa** changed its timezone on 2011, read more here:
https://www.abc.net.au/news/2011-12-30/samoa-skips-friday-in-time-zone-change/3753350

After that, 1 hr for flight to **Tualauta**. After arriving **Tualauta**, **A'opo** localtime was December 31th, 2 AM while **Tualauta** was December 30th, 2 AM. And then at December 20th, 12 PM in **Tualauta**, he flight back to **A'opo** which means 12 - 2 = 10, so we need to add 10 hrs for that. Also don't forget to add the 1 hr for the flight back to **A'opo**

Next, we need to add more 10 hrs as he said: "It's been 10 hours since I landed on my most recent flight"

Lastly, we need to add more 1 hr because of Daylight Saving Time (DST) in **Samoa** 2011:

![IMG](/assets/images/nahamconctf2022-whenami/nahamcon-misc.png)

So the total is 60 hrs and 1 min = 216060 secs

Flag:
```
flag{216060}
```
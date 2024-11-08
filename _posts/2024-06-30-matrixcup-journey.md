---
title: "[MATRIXCUP] My Journey & Experience"
excerpt_separator: <!--more-->
categories:
  - CTF
tags:
  - MATRIXCUP
  - "2024"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

I am thrilled to participate in MatrixCup 2024 in QingDao, China with my team, 打个没五分钟充电三小时, humorously named after [M53](https://ctftime.org/team/211971).

Before we begin, I would like to thank [360安全应急响应中心](https://security.360.cn/) and [VUL-AI](https://www.huaun.com/) for their support and sponsorship to make this trip possible, I am truly grateful for this unforgettable experience.

<!--more-->

# MatrixCup 2024 Adventure
The competition category we participate is called 人工智能挑战赛 basically is an AI track competition. Our task is to build an AI to automatically solve **Pwn** challenges...

![IMG](/assets/images/matrixcup2024-journey/matrixcup.png)

Although I have a general idea of what jeopardy CTFs look like, this track is a whole new concept that I'm pretty sure involved very in-depth research to build.

We were informed that the bot we built should be capable to perform the following tasks entirely automatically without human interaction:
1. Interact with the API to get challenge information
2. Download / Extract the challenge
3. Start the challenge instance (since it is a pwn challenge)
4. **Magically** exploit it, get the flag and submit it
5. Close the instance

We were also informed that during the competition day, we would receive a hint about the type of challenge expected for the bot (Stack/Heap/Etc). And presumably, we couldn't analyze the challenge manually; everything was to be done by the bot since this is an AI track. All we could do was tweak the bot based on the hint, submit it, and cross our fingers.

After knowing this, we researched as much as we could about the latest news in the Pwnable field. Apart from the research paper about the closed-source system **Mayhem** for performing Automatic Exploit Generation (AEG), there weren't many resources left.

Before the competition, we had an online demo round with a total of 10 demo challenges, all pwnable challenges. After analyzing all of them, the difficulty wasn't really baby-like easy; it was similar to the regular pwnable challenges we've encountered in CTFs. We could also see that the challenges were designed comprehensively to evaluate our AI bot, not only in Pwn (Exploit), but also in Path Finding, Fuzzing, Constraint Solving, and Symbolic Analysis.

At this point, we were like... damn, if someone was able to do this, I'd really be interested to see it live. However, the scoreboard at the end of the demo round showed that only the easiest stack overflow (ret2libc) challenge was solved by 7-8 out of 20 teams.

We were quite confused at that time. Were our opponents holding the flags? Did they submit the easiest challenge flag just to test their bot? (Remember, our bot had to be able to submit flags automatically).

We continued to enhance our bot and see if we could build something up to deliver... Also, at the same time, the API docs we are given kept changing and changing T.T, we had a hard time modifying our bot again and again.

Anyway let's get back to our adventure~

# Arriving in QingDao China (June 25)
Our hotel is very near the sea, one of the top attractions in QingDao. The weather in QingDao, not exaggeration to say, is very very chilly and comfortable.

Hotel check-in:

![IMG](/assets/images/matrixcup2024-journey/matrixcup1.jpg)

A walkable distance to get this view:

![IMG](/assets/images/matrixcup2024-journey/matrixcup2.jpg)

We then explored a bit the city and prepared for the competition tomorrow.

# Competition Day (June 26)

We had a quick breakfast and went to the competition hall. The Hall accommodates 40 teams (20 AI Track & 20 A&D Track).

![IMG](/assets/images/matrixcup2024-journey/matrixcup3.jpg)

Now, here is the part I think we kinda missed our golden opportunity because lack of detailed timetable given, the timetable we got is like whole duration is straight up competition, where I think players could start tweaking the bot by enabling the debug timestamp, each timestamp costs 20 minutes and players **cannot cancel** it. During the debug timestamp, the server (our bot placed in) will have no access to anything, including but not limited to API and instances. Only after the debug timestamp, the bot can access the API and instance environment and players are not allowed to touch the bot anymore. Therefore, even if you would like to make minor changes to your bot that take about 1 minute, you have to sacrifice the entire 20 minutes. The sad part is we only knew this in the last 30 minutes of the first 3 hours of the competition, during which organizers gave players time to debug their own bot that was able to interact with the API at the same time. This kind of made us lose the opportunity to utilize it. We spent quite a lot of time debugging our bot during the competition, which made us unable to submit the 4 challenges we solved T.T. We aren't sure if this was just us not being informed; if it was, we hope the organizers can improve this by providing a detailed timetable.

![IMG](/assets/images/matrixcup2024-journey/matrixcup4.png)

Anyway, regarding the atmosphere, the AI track is kinda chill, we can hear intense battle between teams in A&D track and sometimes the announcement of successfully Zero Day track's attack demostration and the bounty they earned, super cool !

![IMG](/assets/images/matrixcup2024-journey/matrixcup5.jpg)

Also, we noticed that none of the AI track teams actually used AI, all hand-crafted the exploits as players are able to download the challenges. Glad that pwners are not jobless that soon.

A group photo:

![IMG](/assets/images/matrixcup2024-journey/matrixcup6.jpg)

# MatrixCup Music Festival (June 27)

It's a music festival social event at the top of the hotel, the scenes were very beautiful at night.

![IMG](/assets/images/matrixcup2024-journey/matrixcup7.jpg)
![IMG](/assets/images/matrixcup2024-journey/matrixcup8.jpg)

# Award Ceremony (June 28)

Award Ceremony picture:

![IMG](/assets/images/matrixcup2024-journey/matrixcup9.jpg)

The remaining hours before return, we explored Qingdao as much as we could, below are some pictures we took:

![IMG](/assets/images/matrixcup2024-journey/matrixcup10.jpg)
![IMG](/assets/images/matrixcup2024-journey/matrixcup11.jpg)
![IMG](/assets/images/matrixcup2024-journey/matrixcup12.jpg)
![IMG](/assets/images/matrixcup2024-journey/matrixcup13.jpg)

# Returning Home (June 29)
We headed back to Malaysia.

By Teng with love <3
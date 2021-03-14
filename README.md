- [Nahamcon 2021 CTF Writeup](#nahamcon-2021-ctf-writeup)
  - [Warmups](#warmups)
    - [Veebee](#veebee)
    - [Shoelaces](#shoelaces)
    - [Read the Rules](#read-the-rules)
    - [Pollex](#pollex)
    - [esab64](#esab64)
    - [Eighth Circle](#eighth-circle)
    - [Chicken Wings](#chicken-wings)
    - [Car keys](#car-keys)
    - [Buzz](#buzz)
  - [Miscellaneous](#miscellaneous)
    - [Abyss](#abyss)
  - [NahamCon](#nahamcon)
    - [INE Career Corner](#ine-career-corner)
    - [IoT Village](#iot-village)
    - [HTB Village](#htb-village)
    - [Red Team Village](#red-team-village)
    - [Live Recon Village](#live-recon-village)
    - [Merch Store](#merch-store)
    - [#NahamCon2021](#nahamcon2021)
    - [UHC-BR](#uhc-br)
  - [Mission](#mission)
    - [The Mission](#the-mission)
    - [Meet The Team](#meet-the-team)
    - [Bionic](#bionic)
    - [Gus](#gus)
  - [Cryptography](#cryptography)
    - [Treasure](#treasure)
    - [eaxy](#eaxy)
  - [Forensics](#forensics)
    - [Henpeck](#henpeck)
    - [Typewriter](#typewriter)
  - [Mobile](#mobile)
    - [Andra](#andra)
    - [Resourceful](#resourceful)
  - [Sponsors Recon](#sponsors-recon)
    - [INE (Starter Pass)](#ine-starter-pass)

# Nahamcon 2021 CTF Writeup

## Warmups

### Veebee

`Buzz buzz, can you find the honey?`

Running `file` on the downloaded file I found that it was only a data file.

So I looked up the `.vbe` extentsion and found that it's a VBScript Encoded Script. These types of files aren't really used on Linux. So I copied over the file to the desktop and ran it. Some popups came up and ended up showing the flag.

![n16](nahamcon_screenshots\2021-03\PvPjQqtrxW.png)

Flag: `flag{f805593d933f5433f2a04f082f400d8c}`

### Shoelaces

`I can't get anything out of this website... can you find anything interesting?`

First download the `.jpg`

Running the `strings` command on `shoelaces.jpg` and piping to `more` you can read down through the strings and you'll find the flag hiding

Flag: `flag{137288e960a3ae9b148e8a7db16a69b0}`

### Read the Rules

The flag is found within the webpage source code of: `https://ctf.nahamcon.com/rules`

![n2](nahamcon_screenshots\2021-03\vmware_hWfPg3pFye.png)

Flag: `flag{90bc54705794a62015369fd8e86e557b}`

### Pollex

`Download the file below.`
`Some people seem to have trouble reading this, understandably so. Sorry. The flag ends in these characters: 8fe36bc00}`

First we download the file and the running `file` on it reveals that it's a `.jpeg`

Doing some stego tricks I wasn't able to see anything suspicious. When I looked at the thumbnail in the folder I noticed some white writing on the bottom. However, when I opened the file the writing was no longer there. So zooming into the thumbnail you can see the flag

![n14](nahamcon_screenshots\2021-03\vmware_1yGqSpoQfh.png)

Flag: `flag{65c34a1ec121a286600ddd48fe36bc00}`

### esab64

`Was it a car or a cat I saw?`

Running strings on the file I get the output: `mxWYntnZiVjMxEjY0kDOhZWZ4cjYxIGZwQmY2ATMxEzNlFjNl13X`

I took this and ran it through ciphey to get the flag: `sudo docker run -it --rm remnux/ciphey -t "mxWYntnZiVjMxEjY0kDOhZWZ4cjYxIGZwQmY2ATMxEzNlFjNl13X"`

![n11](nahamcon_screenshots\2021-03\vmware_jL1iVT7sxM.png)

Flag: `flag{fb5211b498afe87b1bd0db601117e16e}`

### Eighth Circle

`Abandon all hope, ye who enter here...`

First download the file, using `file` it seems it's just ASCII text.

The result of `cat eighth_circle` is this long line of garbled text:

    D'`r#LK\[}{{EUUTet,r*qo'nmlk5ihVB0S!>w<<)9xqYonsrqj0hPlkdcb(`Hd]#a`_A@VzZY;Qu8NMRQJn1MLKJCg*)ED=a$:?>7[;:981w/4-,P*p(L,%*)"!~}CB"!~}_uzs9wpotsrqj0Qmfkdcba'H^]\[Z~^W?[TSRWPt7MLKo2NMFj-IHG@dD&<;@?>76Z{9276/.R21q/.-&J*j(!E%$d"y?`_{ts9qpon4lTjohg-eMihg`&^cb[!_X@VzZ<RWVOTSLpP2HMFEDhBAFE>=BA:^8=6;:981Uvu-,10/(Lm%*)(!~D1 

Doing some Google searching for: `eighth circle CTF` leads to a writeup which mentions `Malbolge`.

Finding this site: `https://malbolge.doleczek.pl/` I entered in the string and ran the program and the flag was shown in the terminal.

![n22](nahamcon_screenshots\2021-03\vmware_Xskewi0SSW.png)

Flag: `flag{bf201f669b8c4adf8b91f09165ec8c5c}`

### Chicken Wings

`I ordered chicken wings at the local restaurant, but uh... this really isn't what I was expecting...`
`Download the file below.`

Downloading the file and running `file` I found that it was UTF-8 Unicode text and when I tried reading the file in the terminal I got some weird looking icons.

![n15](nahamcon_screenshots\2021-03\vmware_60IhczMK7y.png)

Searching this peculiar string in Google I found a WingDing translator website: `https://lingojam.com/WingDing`

Entering in the string into the tool I was able to decode it into the flag.

![n20](nahamcon_screenshots\2021-03\vmware_imMRbZrQPk.png)

Flag: `flag{e0791ce68f718188c0378b1c0a3bdc9e}`

### Car keys

`We found this note on someone's key chain! It reads... ygqa{6y980e0101e8qq361977eqe06508q3rt}? There was another key that was engraved with the word QWERTY, too...`

With the `QWERTY` hint I looked around Google and found out that it might be a keyed caesar cipher Time for some decoding!

I used this site and was able to decode the key: `https://www.boxentriq.com/code-breaking/keyed-caesar-cipher`

![n18](nahamcon_screenshots\2021-03\vmware_A1yzlsCtt0.png)

Flag: `flag{6f980c0101c8aa361977cac06508a3de}`

### Buzz

`You know, that sound that bumblebees make?`

Running `file` on the downloaded file I get the output: `buzz: compress'd data 16 bits`

Doing some Google searching I found there was some questions about `.z` files

So I renamed the file to `buzz.z` then I used `uncompress buzz.z` which resulted in an ASCII file that contained the flag

Flag: `flag{b3a33db7ba04c4c9052ea06d9ff17869}`

## Miscellaneous

### Abyss

`A Vortex? No... an Abyss.`
`# Password is userpass`
`ssh -p 32140 user@challenge.nahamcon.com`

Logging into this SSH connection all of a sudden nonsense starts scrolling down screen and keeps going. So I decided to stop the connection and start it again and redirect the output to a file so I can then use `grep` to look for the flag.

`ssh -p 32140 user@challenge.nahamcon.com > output.txt`

`grep flag output.txt`, this shows that the flag appears multiple times throughout the text file.

![n17](nahamcon_screenshots\2021-03\vmware_8GGcUjKZcf.png)

Flag: `flag{db758a0cc25523993416c305ef15f9ad}`

## NahamCon

### INE Career Corner

`Come join the party at the INE Career Corner, and track down a flag!`

Opening the link shown brings you to a Discord channel: `https://discord.com/invite/eQ4jGmkCaf`

Going to the `#ine-career-corner` you can see the flag in the channel description

![n3](nahamcon_screenshots\2021-03\Discord_m4W4yl3eCY.png)

Flag: `flag{e713de181584836c9499811f13cb0e62}`

### IoT Village

`Come join the party at the IoT Village, and track down a flag!`

Opening the link shown brings you to a Discord channel: `https://discord.com/invite/eQ4jGmkCaf`

Going to the `#iot-village` you can see the flag in the channel description

![n4](\nahamcon_screenshots\2021-03\Discord_GD4KVP8xEM.png)

Flag: `flag{1ff473816ef21857cc62f838e8a33fc7}`

### HTB Village

`Come join the party at the HTB Village, and track down a flag!`

Opening the link shown brings you to a Discord channel: `https://discord.com/invite/eQ4jGmkCaf`

Going to the `#htb-village` you can see the flag in the channel description

![n5](nahamcon_screenshots\2021-03\Discord_EQyDrtqoKl.png)

Flag: `flag{437f3e5ecdd39a29d695e2e31603f5b4}`

### Red Team Village

`Come join the party at the Red Team Village, and track down a flag!`

Opening the link shown brings you to a Discord channel: `https://discord.com/invite/eQ4jGmkCaf`

Going to the `#red-team-village` you can see the flag in the channel description

![n6](nahamcon_screenshots\2021-03\Discord_7X7aoPYa4r.png)

Flag: `flag{fd59547d85953cac9dd5f378daed2157}`

### Live Recon Village

`Come join the party at the Live Recon Village, and track down a flag!`

Opening the link shown brings you to a Discord channel: `https://discord.com/invite/eQ4jGmkCaf`

Going to the `#live-recon-village` you can see the flag in the channel description

![n7](nahamcon_screenshots\2021-03\Discord_HL7jBBSkAN.png)

Flag: `flag{2795da9d0d2055d259a3fb4d6b78629c}`

### Merch Store

`Check out our Merch Store! A portion of the proceeds go to support Women in CyberSecurity @WiCySorg!`
`Perform some online reconnaissance to track down a flag on the merch store!`

Clicking the link shown brings you to the site: `https://www.nahamcon.com/merch`

Viewing the web page source code and searching for `flag` you'll find the flag in a comment

![n8](nahamcon_screenshots\2021-03\vmware_EivJl5iR5U.png)

Flag: `flag{fafc10617631126361c693a2a3fce5a7}`

### #NahamCon2021

`#NahamCon2021 #awesome #cool #winning! Did you know that the hashtag has another much cooler name, called the "octothorp?"`

`Perform some online reconnaissance to track down a flag for #NahamCon2021!`

Using the following Google dork the flag appears at the very top of the results: `site:twitter.com intext:#NahamCon2021 intext:flag`

![n10](nahamcon_screenshots\2021-03\firefox_6Pbw3O4Whx.png)

Flag: `flag{e36bc5a67dd2fe5f33b62123f78fbcef}`

### UHC-BR

`Come join the party at UHC-BR, and track down a flag!`

Opening the link shown brings you to a Discord channel: `https://discord.gg/C6wvwE8RMX`

Going to the `uhc-br` you can see the flag in the channel description

![n12](nahamcon_screenshots\2021-03\Discord_N50DKmOn3b.png)

Flag: `flag{120c45c7b99d8cba1567441f5bef599e}`

## Mission

### The Mission

The flag is found within the webpage source code of: `https://ctf.nahamcon.com/mission`

![n1](nahamcon_screenshots\vmware_Bi5Bj5czpn.png)

Flag: `flag{48e117a1464c3202714dc9a350533a59}`

### Meet The Team

`Recover the list of employees working at CONSTELLATIONS.`
`With the flag of this challenge, you should find new information that will help with future challenges.`
`You should find the flag for this challenge ON THIS constellations.page website. You will not find it on GitHub.`
`HINT: "Can we please stop sharing our version control software out on our website?"`
`HINT AGAIN: you are looking for a publicly accessible version control software folder published on the constellations.page website itself`
`After solving this challenge, you may need to refresh the page to see the newly unlocked challenges.`

Using the hint from the Bionic challenge, we go to the webpage: `https://constellations.page/meet-the-team.html`

Looking through the source code of the webpage I found an HTML comment: `Vela, can we please stop sharing our version control software out on the public internet?`

Looking at the bottom of the page there's a link to a github repo (leads to another challenge.)

So let's see if there's a git leak by going to: `https://constellations.page/.git/`. This shows a foribidden message showing we don't have access to the server. Still, this is good becuase now we know there's a `.git` folder.

Using GitTools found at: `https://github.com/internetwache/GitTools` I used the Dumper tool specifcally to find whatever was available from `.git` and download it locally: `./gitdumper.sh https://constellations.page/.git/ .`

![n23](nahamcon_screenshots\2021-03\vmware_YT8lhfIbfv.png)

I then used the Extractor tool from the same toolset to extract the commits and content to a separate directory: `meet_the_team/GitTools/Extractor/extractor.sh meet_the_team meet_the_team/extracted`

I then used the following command to look for the flag regex: `grep -RE 'flag\{[0-9a-f]{32}\}.'` which then resulted in the flag which was located in `meet-the-team.html`

![n24](nahamcon_screenshots\2021-03\vmware_OdvWLlIKuS.png)

Flag: `flag{4063962f3a52f923ddb4411c139dd24c}`

### Bionic

`Thank you for taking on The Mission. You can begin by exploring the CONSTELLATIONS public website, constellations.page.`
`CONSTELLATIONS has "tried" to reduce their attack surface by offering just a static website. But you might find some low-hanging fruit to get you started.`
`You should find the flag for this challenge ON THIS constellations.page website.`
`With the flag of this challenge, you should also find a new URL that will assist in the next challenge.`
`After solving this challenge, you may need to refresh the page to see the newly unlocked challenges.`

Looking at the `robots.txt` we find the flag for this challenge and also what looks like a clue for another challenge.

![n13](nahamcon_screenshots\2021-03\vmware_26XEAEsZ7V.png)

Flag: `flag{33b5240485dda77430d3de22996297a1}`

### Gus

`This is Stage 1 of Path 4 in The Mission. After solving this challenge, you may need to refresh the page to see the newly unlocked challenges.`
`Use open-source intelligence to track down information on Gus.`
`With the flag of this challenge, you should also find details you can use in later challenges.`

While I was working on the challenege Meet The Team, I was scouting out the webpage and I saw that there was a link to a hithub repo for Constellations. There was one person listed under 'People' on the repo and his name was Gus Rodry.

![n25](nahamcon_screenshots\2021-03\vmware_6QW0GFiYdd.png)

Clicking on his profile lead to the repoistories that he is involved with, one called `development` that as to do with Constellations. Looking at this repo there was a reference to a `flag.txt`, which clicking on the link revealed the flag.

![n26](nahamcon_screenshots\2021-03\vmware_CNBcijf2ZY.png)

Flag: `flag{84d5cc7e162895fa0a5834f1efdd0b32}`

## Cryptography

### Treasure

`This movie is what pushed me to get into hacking. Good luck decrypting my note, I'm elite.`

There are two files to download, `note.txt` is a set of numbers in a flag format.

`4661 5099 13243 11578 { 14382 734 14024 10621 14382 2 3383 8702 6087 10621 7417 14382 12352 615 1208 4246 4657 9975 7203 2658 770 4 10621 8702 6125 980 9522 2659 14784 7203 8701 38 }`

`hackers.txt` looks like it's the movie script for Hackers.

`wc -w < hackers.txt` shows that there's 15,290 words within this file

### eaxy

`Crypto is eaxy, it's all about math and keys :)`

Doing a `file eaxy` shows that the file is just data, and looking through it, it all seems like nonsense.

So I took the file as input in CyberChef and used the `XOR Brute Force` recipie against it to see if I could find anything useful. Looking down through I recognized some actual words with the key being 66.

`The XOR key you used to find string this is the 0 character index of the flag`

66 when it's converted from hex is f. So I then decided what might XORing the file with the hex conversions of l,a, and g. In all ocurrences I found the above string somewhere in the text but with a different index number. I started to do this manually but it was going to take forever.

I downloaded a tool call `xcat` from: `https://github.com/mstrand/xcat`. I then proceeded to go through each letter of the alphabet and the numbers from 0 - 9 to fill out the rest of the flag.

`/opt/tools/xcat/xcat.py -a b eaxy | grep -a "character index"` : This was used for letters
`/opt/tools/xcat/xcat.py -x 39 eaxy | grep -a "character index"` : This was used for hex number representations of 0 - 9

I created a sheet in Excel to plot out my findings as I went along, and eventually I got the flag!

![n30](nahamcon_screenshots\2021-03\EXCEL_itFqAiOQUg.png)

Flag: `flag{16edfce5c12443b61828af6cab90dc79}`

## Forensics

### Henpeck

`So I'll be honest, I never actually went through the Mavis Beacon program...`

First you have to download the file which ends up being a `.pcap` file. Opening this in Wireshark shows that it's USB data.

I did some searching on Github and found a tool that is used to extract USB data from pcaps and rebuilds the data. You can find it at: `https://github.com/TeamRocketIst/ctf-usb-keyboard-parser`

First I used this command: `tshark -r ./henpeck.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > usbcapdata` which prepared the data.

Then I ran the `usbkeyboard.py` tool and I got the flag! `so the answer is flag{f7733e0093b7d281dd0a30fcf34a9634} hahahah lol`

Flag: `flag{f7733e0093b7d281dd0a30fcf34a9634}`

### Typewriter

`A CONSTELLATIONS employee had his machine crash and he lost all his work. Thankfully IT managed to get a memory dump. Can you recover his work?`
`Download the file below. Note, this is a large ~400MB file and may take some time to download.`

First I downloaded the file, `image.bin` then I looked at some of the strings but no easy flag to be found. Since it's a memory dump I decided that using `volatility` would be my best move. You can download the tool from: `https://github.com/volatilityfoundation/volatility`

I first did a scan of `image.bin` to find out what profile I should use with `volatility`: `python vol.py -f ../image.bin imageinfo`. This suggested I use `Win7SP1x86_23418`

Since the memory dump wasn't in a particular form I wanted to convert it to a `.raw` format to make it easier to work with: `python vol.py -f ../image.bin --profile=Win7SP1x86_23418 imagecopy -O copy.raw`

Next I wanted to see what processes were running at the time of the crash: `python volatility/vol.py -f copy.raw --profile=Win7SP1x86_23418 psscan`. Exploring the list I saw that Word was running at the time.

`0x85fa2d20 WINWORD.EXE            2760   2212      8      316      1      0 2021-02-21 16:24:39 UTC+0000`

So next I wanted to dump the memory of the process so I could explore it more: `python volatility/vol.py -f copy.raw --profile=Win7SP1x86_23418 -p 2760 -D dump/`

Doing some string searching I came across: `C:\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx`. I wanted to get access to that so I used `volatility` to search for files on the system and then used `grep` to search out all the `.docx` files.

`python volatility/vol.py -f copy.raw --profile=Win7SP1x86_23418 filescan > files.txt`

There was a few files that showed up. So the next step was trying to download the files, I did that by using: `sudo python volatility/vol.py -f copy.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000007e615f80 --name file -D /opt/`

I then transferred the files to my Windows desktop and renamed the file extensions to `.docx` so it would open correctly. I then explored the files and I found one which contained the flag!

![n32](nahamcon_screenshots\2021-03\WINWORD_sMQtJP2cwk.png)

Flag: `flag{c442f9ee67c7ab471bb5643a9346cf5e}`

## Mobile

### Andra

`You know what to do. :)`
`Download the file below.`

First I downloaded the `.apk` file I then used: `apktool build andra.apk` which generated some files.

I then used `grep -R -i flag` to recursively search for the term 'flag' which showed that there was a match within `res/layout/activity_flag.xml`

Reading the contents of the file I could see the flag within the text.

Flag: `flag{d9f72316dbe7ceab0db10bed1a738482}`

### Resourceful

`I built my first ever android app with authentication!`
`Download the file below.`

First I downloaded the `.apk` file and then used `unzip resourceful.apk` which uncompressed some files.

I then used `grep -R -i flag` to recursively search for the term 'flag', there was no match for an exact flag. So it seemed that I'd need to down an Android emulator. I did that by downloading Android Studio from: `https://developer.android.com/studio`

Opening the file within Android Studio and looking around, I found the password `sUp3R_S3cRe7_P4s5w0Rd` within the `MainActivity$1` file

Entering the above password into the emulator running `resourceful.apk` yields the flag

![n28](nahamcon_screenshots\2021-03\qemu-system-x86_64_dKKOpn6dEH.png)

Flag: `flag{7eecc051f5cb3a40cd6bda40de6eeb32}`

## Sponsors Recon

### INE (Starter Pass)

`Thanks to INE for helping sponsor NahamCon!`
`You might find some good stuff here ;) https://checkout.ine.com/starter-pass`
`Perform some reconnaissance on their online presence and find a flag you can submit for points :)`

Viewing the website page source and looking down through I noticed something odd, what appears to be base64.

![n29](nahamcon_screenshots\2021-03\vmware_M2TU5xlFtR.png)

Putting that value into Cyberchef using the `From Base64` recipe got me the flag.

Flag: `flag{29fa305aaf5e01e9edcf0142e4ddcdb9}`

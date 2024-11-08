---
title: "[TFCCTF] Secrets Of Tenochtitlan"
excerpt_separator: <!--more-->
categories:
  - CTF
tags:
  - TFCCTF
  - MISC
  - "2022"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

# Task source:
https://github.com/Tzion0/CTF/tree/master/TFCCTF/2022/SOT

# Description
Tenochtitlan was the island capital of the Aztec empire, believed to be founded in 1325, serving as an altar, awaiting the fulfillment of an ancient prophecy. However, it is highly unlikely that this prophecy comes true, as the city of Tenochtitlan, and the Aztec empire fell in 1521 August 13, after holding up for two years against the Spanish forces led by Cortés.

<!--more-->

This challenge provided a zip file.

Unzip the zip file you will get a PNG file which is an **Aztec** barcode along with 2 more zip files. Unzip the others zip files you will get another Aztec barcode PNG image with new zip files. At this point it looks like we going to keep unzip this recursively until its end. We can use this command (not fully automated) to help us in unzip:
```
find . -name "*.zip" | while read filename; do unzip -o -d "`dirname "$filename"`" "$filename"; rm $filename; done;
```

Everytime after I unzip the zip file, I move all the barcode images into new directory to organize it in a structural way (In layers). Eventually it will looks like this:

![IMG](/assets/images/tfcctf2022-SOT/img.png)

At first i thought that organize it in structural way might be help in later task, but turns out actually no needed.

The next step is the most painful step which is scanning all the barcode. All barcode contains a character of flag. I do this manually because I don't know any automated tools available online.

After gathering all the flag characters, we need to figure out the order of character to form a valid flag. While analyzing those barcode images, I found that each barcode contains a different `Date/Time Original` which can be obtain using this command:
```
exiftool -time:all *
```

![IMG](/assets/images/tfcctf2022-SOT/img2.png)

I rearrange each barcode image based on its `Date/Time Original` in ascending order, create an array of dictionary that use barcode image file name as the key to its corresponding character, then print out the flag. Below is the code in Python (The number in front of '/' in each value of `flag` array representing the folder, which can be ignore as I mentioned earlier it is no needed):

```py
#!/usr/bin/env python3

flag = [
"0/738c81a3-4036-4553-8c8d-065b7f490b6a",
"4/a46480fd-2887-4511-8e00-bbadf75b3903",
"5/a3625a77-7256-4432-9e8c-bce622ebf794",
"3/4121557f-07a5-4bb1-aaff-33336b96af95",
"5/799699d2-a58c-4660-abb1-d319d03bfb9d",
"4/d571120d-04b9-4333-84f0-e107b1e12b7b",
"5/28e722f0-1976-4300-9120-4118c532ff3a",
"5/aa908f25-a4b7-43d7-8c73-c6a26389cc77",
"4/21f23511-e468-47c5-986a-bc4a7afeaee8",
"5/ccdf60e1-a4d3-4755-b593-55d50c7b9a9e",
"4/29983b58-a220-4e68-9b2e-640ea15d7f41",
"5/51fb3d97-5ac4-4a46-b3a7-7bbca4384330",
"5/f74540a4-4949-4593-8cc0-c1ed13948d29",
"5/4807f95f-4298-43ca-a903-2795fbaeb5a4",
"4/7b14249f-0415-4b67-a5fc-85ad7973e98c",
"3/efc0700f-a0cf-40df-a6b7-41a3ad918e8d",
"3/f678e654-4498-4779-b5aa-7907296c6c49",
"5/a41a3d86-c630-4a88-9a13-ecba0091cbf8",
"5/699cd577-fcb1-4300-9611-af5d7a9d3d94",
"5/6eb25f88-d8b4-4f16-abca-5e9a3b53e11a",
"4/b9ad444f-5e2d-4ba5-869d-644f2d15cbf2",
"5/08ca58ac-dc06-41ad-a5e4-77ddc02d4b20",
"1/8ecd8915-445e-45b3-abf7-b4c81328ad8b",
"4/e5ae597e-7b8e-4f2d-824e-f9d2e066fedc",
"5/14f09500-eb58-4865-aca2-46e44160342f",
"5/37c40e16-c47d-4906-a081-12abb822380a",
"4/0e96ab5d-9e6f-47ba-8764-c20fbfcdc863",
"2/f8729933-e455-4a2d-84da-263c7d613179",
"5/1ddb3879-5b8e-4257-ad96-48c2c842dc80",
"5/01fd7c26-3de2-49f7-bd11-43dd0c09491b",
"4/02709749-7fd8-4d9a-a605-70ddcafb973a",
"3/45f2a087-a284-4add-8ee1-11ce8763ce3a",
"2/8441be40-f1b0-4c06-88fc-168c1544f7a5",
"2/2d42e973-89a4-473f-9bf9-3130d0a64f5b",
"3/77e8955d-745c-4d05-b84c-7cf394e247cb",
"1/8c9379b3-8dd8-4b49-891e-7d36fc7d9255",
"5/b2191064-5ca8-46cc-863a-da02b43c3307",
"5/90f1bf22-1c4d-45b8-b227-f0835df30865",
"4/39863c09-afa2-4e56-af1d-bf1c630f96a7",
"4/ace7f990-ac9b-442d-a80a-5469c1599995",
"3/a999e5d9-66ff-475c-a2b2-5f5e1913d9d2",
"4/25293981-e030-44c7-a918-f7fe3e07f33b",
]

database = [{
	"738c81a3-4036-4553-8c8d-065b7f490b6a":"}"
},{
	"8c9379b3-8dd8-4b49-891e-7d36fc7d9255":"{",
	"8ecd8915-445e-45b3-abf7-b4c81328ad8b":"n",
},{
	"2d42e973-89a4-473f-9bf9-3130d0a64f5b":"3",
	"8441be40-f1b0-4c06-88fc-168c1544f7a5":"c",
	"f8729933-e455-4a2d-84da-263c7d613179":"_",
},{
	"45f2a087-a284-4add-8ee1-11ce8763ce3a":"r",
	"77e8955d-745c-4d05-b84c-7cf394e247cb":"5",
	"4121557f-07a5-4bb1-aaff-33336b96af95":"1",
	"a999e5d9-66ff-475c-a2b2-5f5e1913d9d2":"F",
	"efc0700f-a0cf-40df-a6b7-41a3ad918e8d":"n",
	"f678e654-4498-4779-b5aa-7907296c6c49":"3",
},{
	"0e96ab5d-9e6f-47ba-8764-c20fbfcdc863":"0",
	"7b14249f-0415-4b67-a5fc-85ad7973e98c":"7",
	"21f23511-e468-47c5-986a-bc4a7afeaee8":"l",
	"29983b58-a220-4e68-9b2e-640ea15d7f41":"v",
	"39863c09-afa2-4e56-af1d-bf1c630f96a7":"C",
	"02709749-7fd8-4d9a-a605-70ddcafb973a":"3",
	"25293981-e030-44c7-a918-f7fe3e07f33b":"T",
	"a46480fd-2887-4511-8e00-bbadf75b3903":"n",
	"ace7f990-ac9b-442d-a80a-5469c1599995":"C",
	"b9ad444f-5e2d-4ba5-869d-644f2d15cbf2":"4",
	"d571120d-04b9-4333-84f0-e107b1e12b7b":"4",
	"e5ae597e-7b8e-4f2d-824e-f9d2e066fedc":"4",
},{
	"1ddb3879-5b8e-4257-ad96-48c2c842dc80":"5",
	"01fd7c26-3de2-49f7-bd11-43dd0c09491b":"7",
	"6eb25f88-d8b4-4f16-abca-5e9a3b53e11a":"n",
	"08ca58ac-dc06-41ad-a5e4-77ddc02d4b20":"_",
	"14f09500-eb58-4865-aca2-46e44160342f":"_",
	"28e722f0-1976-4300-9120-4118c532ff3a":"z",
	"37c40e16-c47d-4906-a081-12abb822380a":"f",
	"51fb3d97-5ac4-4a46-b3a7-7bbca4384330":"1",
	"90f1bf22-1c4d-45b8-b227-f0835df30865":"T",
	"699cd577-fcb1-4300-9611-af5d7a9d3d94":"c",
	"4807f95f-4298-43ca-a903-2795fbaeb5a4":"_",
	"799699d2-a58c-4660-abb1-d319d03bfb9d":"7",
	"a41a3d86-c630-4a88-9a13-ecba0091cbf8":"1",
	"a3625a77-7256-4432-9e8c-bce622ebf794":"0",
	"aa908f25-a4b7-43d7-8c73-c6a26389cc77":"1",
	"b2191064-5ca8-46cc-863a-da02b43c3307":"F",
	"ccdf60e1-a4d3-4755-b593-55d50c7b9a9e":"1",
	"f74540a4-4949-4593-8cc0-c1ed13948d29":"c"
}]

for c in flag[::-1]:
	idx = int(c.split("/")[0])
	key = c.split("/")[1]
	print(database[idx][key], end="")
```

Flag:
```
TFCCTF{53cr375_0f_4n_4nc13n7_c1v1l1z4710n}
```
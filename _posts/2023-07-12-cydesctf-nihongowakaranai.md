---
title: "[CYDESCTF] Nihongo Wakaranai"
excerpt_separator: <!--more-->
categories:
  - CTF
tags:
  - CYDESCTF
  - REV
  - "2023"
toc: true
toc_sticky: true
toc_label: "Table of Contents"
---

This challenge provided an Excel (.xlsx) file. [Here](https://github.com/Tzion0/CTF/tree/master/CydesCTF/Nihongo%20Wakaranai) is the challenge file.

Before we get started, I would like to express my heartfelt gratitude to the organizers **National Cyber Security Agency Malaysia (NACSA)**, **Velum Labs** and the exceptional technical team **WargamesMY** for their unwavering efforts in organizing the physically conducted Cyber Warzone CTF challenges. Their meticulous planning, flawless execution, and dedication made the event an incredible experience, fostering a vibrant atmosphere of learning and collaboration. Thanks again for providing us with an opportunity to challenge our skills, expand our knowledge, and create lasting memories.

<!--more-->

Without further ado, let's get started.

First we are given an xlsx file, we could use [**oledump.py**](https://blog.didierstevens.com/programs/oledump-py/) by Didier Stevens to analyze it:
```sh
python3 oledump.py nihongo.xlsm
```
![IMG](/assets/images/cydesctf2023-nihongowakaranai/img1.png)

We are particularly interested in those streams contains letter M (stands for VBA Macros), and we can decompress it with following command:
```sh
python3 oledump.py nihongo.xlsm -s A3 -v > dump.vba
```
## dump.vba :
```vb.net
Attribute VB_Name = "Module1"
Sub 関数()
    Dim オレンジ As String
    オレンジ = ""
    ' スプーン(オレンジ)
    ' ナイフ(オレンジ)
    ' ???(????, 5)
    ' チョコレート(オレンジ)
    ' ???(????)
    ' バニラ(オレンジ)
    ' Finalfunc(オレンジ)
    If オレンジ = "0716614B7C284F4AA56307E22434B93C" Then
        MsgBox "おめでとうございます！オレンジをキャプチャしました"
    Else
        MsgBox "申し訳ありませんが、オレンジをキャプチャできませんでした。"
    End If
End Sub


Function Finalfunc(ByVal text As String) As String
    Dim md5Obj As Object
    Set md5Obj = CreateObject("System.Security.Cryptography.MD5CryptoServiceProvider")

    Dim encodingObj As Object
    Set encodingObj = CreateObject("System.Text.UTF8Encoding")

    Dim inputBytes() As Byte
    inputBytes = encodingObj.GetBytes_4(text)

    Dim hashBytes() As Byte
    hashBytes = md5Obj.ComputeHash_2((inputBytes))

    Dim i As Integer
    Dim result As String
    result = ""

    For i = 0 To UBound(hashBytes)
        result = result & Right("0" & Hex(hashBytes(i)), 2)
    Next i

    Finalfunc = result
End Function


Function フォーク(ByVal りんご As String) As Byte()
    Dim mod4, i, k As Integer
    Dim クワルテット As String
    Dim デコードバイト() As Byte

    mod4 = Len(りんご) Mod 4
    If mod4 <> 0 Then
        りんご = りんご & String(4 - mod4, "=")
    End If

    Dim メープル As String
    メープル = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    ReDim デコードバイト((Len(りんご) \ 4) * 3 - 1) As Byte

    i = 0
    Dim j As Variant
    Do While i < Len(りんご)
        クワルテット = Mid(りんご, i + 1, 4)
        i = i + 4

        For k = 1 To 4
            j = 0
            j = j Or (InStr(1, メープル, Mid(クワルテット, k, 1)) - 1)
            If k Mod 4 <> 0 Then
                j = j * 64
            End If
        Next k

        k = (i \ 4 - 1) * 3
        デコードバイト(k) = j \ 65536
        j = j And 65535

        If k + 1 < UBound(デコードバイト) Then
            デコードバイト(k + 1) = j \ 256
            デコードバイト(k + 2) = j And 255
        End If
    Loop

    Dim objXML As MSXML2.DOMDocument
    Dim objNode As MSXML2.IXMLDOMElement
    Set objXML = New MSXML2.DOMDocument
    Set objNode = objXML.createElement("b64")
    objNode.DataType = "bin.base64"
    objNode.text = りんご
    デコードバイト = objNode.nodeTypedValue
    Set objNode = Nothing
    Set objXML = Nothing

    フォーク = デコードバイト
End Function


Function いちご(ByVal 入力オレンジ As String) As String
    Dim パイナップル As String
    パイナップル = 入力オレンジ
    パイナップル = Replace(パイナップル, "b", "a")
    いちご = パイナップル
End Function



Function バニラ(ByVal 入力オレンジ As String) As String
    Dim パイナップル As String
    パイナップル = 入力オレンジ
    パイナップル = Replace(パイナップル, "z", "b")
    バニラ = パイナップル
End Function



Function チョコレート(ByVal 入力オレンジ As String) As String
    Dim パイナップル As String
    パイナップル = 入力オレンジ
    パイナップル = Replace(パイナップル, "a", "z")
    チョコレート = パイナップル
End Function


Function ボウル(ByVal 入力文字列 As String, ByVal キー As Integer) As String
    Dim エンコードされた文字列 As String
    Dim i As Integer

    For i = 1 To Len(入力文字列)
        エンコードされた文字列 = エンコードされた文字列 & Chr(Asc(Mid(入力文字列, i, 1)) Xor キー)
    Next i

    ボウル = エンコードされた文字列
End Function



Function スプーン(ByVal 入力オレンジ As String) As String
    Dim パイナップル As String
    パイナップル = "ZnxhYHZ+MjU8ZmZkNmc9PGY8ZzYyMWQ0Mjw8Njc9YGNjPTQzMzN4"
    スプーン = パイナップル
End Function




Function ナイフ(ByVal 入力オレンジ As String) As String
    Dim バイト() As Byte
    バイト = フォーク(入力オレンジ)
    ナイフ = StrConv(バイト, vbUnicode)
End Function
```

At this point in the competition, I let my teammate Choo to look at it because I'm working on another task and he's more familiar with VBA than I am.

Out of my surprise ChatGPT able to analyze it well, [here](https://chat.openai.com/share/a4773291-03bb-46ec-a947-08bf7925125d) is the our conversation with GPT.

From the conversation we obtained the following code:
```vb.net
Attribute VB_Name = "Module1"

Sub Main()
    Dim orange As String
    orange = ""

    ' DecodeBase64(Orange)
    ' DecodeBase64ToString(Orange)
    ' ???(????, 5)
    ' ReplaceAWithZ(Orange)
    ' ???(????)
    ' ReplaceZWithB(Orange)
    ' CalculateMD5Hash(Orange)

    If orange = "0716614B7C284F4AA56307E22434B93C" Then
        MsgBox "Congratulations! Orange captured."
    Else
        MsgBox "Sorry, unable to capture orange."
    End If
End Sub

Function CalculateMD5Hash()
<SNIP>
End Function

Function DecodeBase64()
<SNIP>
End Function

Function ReplaceBWithA()
<SNIP>
End Function

Function ReplaceZWithB()
<SNIP>
End Function

Function ReplaceAWithZ()
<SNIP>
End Function

Function XOREncryption()
<SNIP>
End Function

Function GetHardcodedString()
<SNIP>
End Function

Function DecodeBase64ToString()
<SNIP>
End Function
```

Now we have two unknown question mark functions, but the first one appears to be the best candidate for the XOR function, while the second one clearly is the `ReplaceBWithA()` function because it hasn't been called yet.

Following the order to decode using CyberChef, [here](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)XOR(%7B'option':'Hex','string':'5'%7D,'Standard',false)Find_/_Replace(%7B'option':'Simple%20string','string':'a'%7D,'z',true,false,true,false)Find_/_Replace(%7B'option':'Simple%20string','string':'b'%7D,'a',true,false,true,false)Find_/_Replace(%7B'option':'Regex','string':'z'%7D,'b',true,false,true,false)&input=Wm54aFlIWitNalU4Wm1aa05tYzlQR1k4WnpZeU1XUTBNanc4TmpjOVlHTmpQVFF6TXpONA) is the recipe, and we will obtain the final flag.

# Flag:
```sh
cydes{709ccb3a89c9a374b1799328eff81666}
```
---
title: HackTheBox Sherlock RomCom — Full Walkthrough
date: 2025-09-18 07:14 +0200
categories: [Writeups,Sherlocks]
tags: [HTB, Sherlocks]
author: T3M0
comments: true
---
## Intro

In this Sherlock challenge, we investigate a targeted attack at Forela International Hospital. A suspicious WinRAR archive triggered Microsoft Defender alerts on Susan’s workstation. Threat intelligence linked the incident to the [RomCom threat group](https://malpedia.caad.fkie.fraunhofer.de/actor/romcom) which is known for exploiting a critical WinRAR vulnerability (CVE-2025–8088) in the wild.
This write-up details the full forensic process, using only $MFT and $UsnJrnl:$J, to reconstruct the attack chain and answer all provided questions.

![Desktop View](https://miro.medium.com/v2/resize:fit:720/format:webp/1*U5h_1VsuMq_hwxRkAM55Iw.png){: width="1000"}
_Scenario of a developer starting a blog_



## Challenge Info

* Challenge Name: Sherlock:[RomCom](https://app.hackthebox.com/sherlocks/RomCom)
* Platform: HackTheBox
* Category: DFIR
* Difficulty: Very Easy (focused analysis with $MFT + $UsnJrnl)
* Objective: Investigate artifacts, identify archive, payload, persistence, and execution timeline.

## Background
Scenario
* Susan works at the Research Lab in Forela International Hospital.
* A Microsoft Defender alert was triggered from her machine.
* Susan reported errors during extraction of a file, though the document still opened.
* Intel feeds indicated WinRAR exploitation in the wild (RomCom).
* The SOC team provided a triage image containing $MFT and $UsnJrnl:$J for investigation.

## Questions
1. What is the CVE assigned to the WinRAR vulnerability exploited by the RomCom threat group in 2025?
2. What is the nature of this vulnerability?
3. What is the name of the archive file under Susan’s documents folder that exploits the vulnerability upon opening the archive file?
4. When was the archive file created on the disk?
5. When was the archive file opened?
6. What is the name of the decoy document extracted from the archive file, meant to appear legitimate and distract the user?
7. What is the name and path of the actual backdoor executable dropped by the archive file?
8. The exploit also drops a file to facilitate the persistence and execution of the backdoor. What is the path and name of this file?
9. What is the associated MITRE Technique ID discussed in the previous question?
10. When was the decoy document opened by the end user, thinking it to be a legitimate document?
## Tools
* MFTECmd.exe — Parse $MFT and $UsnJrnl:$J
* Timeline Explorer — Filter and visualize events

## Analysis
1. Identify the Vulnerability
* Check intel feeds: WinRAR 7.12 and earlier are vulnerable to [CVE-2025–8088](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/).
* Nature: Path Traversal with Alternate Data Streams (ADS) leading to arbitrary code execution.

---
2. Locate the Malicious Archive
* Parsed $J with MFTECmd to list recent .rar or .zip or .7zin Susan’s Documents folder.
* Found: `Pathology-Department-Research-Records.rar`
* $J timestamps show:
![Anal1](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*k4qX0gNUaLvqaFYSYjEVCg.png){: width="1000"}
* Created → `2025-09-02 08:13:50`

![Anal2](https://miro.medium.com/v2/resize:fit:720/format:webp/1*B3QjERHOr10uOPfqe59wXg.png){: width="550"}
* Opened shortly after → `2025-09-02 08:14:04`

---
3. Find the Decoy Document

* Filtered $J for FileCreate events from archive file created on the disk and filter using any documents extension.
![Anal3](https://miro.medium.com/v2/resize:fit:720/format:webp/1*HniXQ8htJ8NBFrc-LnCbKg.png){: width="1000"}
Found PDF decoy: `Genotyping_Results_B57_Positive.pdf`


---
4. Discover the Backdoor Executable Persistence Mechanism

* Filtered $J for TimeStamp from `08:13:50` to `08:16:00` to show what files is created
![Anal3](https://miro.medium.com/v2/resize:fit:720/format:webp/1*CjcPjJO_GPliDKd4E8Fhvw.png)

* Alongside the PDF + .lnk, another file was created: ApbxHelper.exe.
Press enter or click to view image in full size
![Anal3](https://miro.medium.com/v2/resize:fit:720/format:webp/1*gEWOaQcXz0rYsFgHjKpL3w.png)

* Resolved in $MFT → full path:
`C:\Users\Susan\AppData\Local\ApbxHelper.exe`
* $J also showed .lnk created in Startup:
`C:\Users\Susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk`
* MITRE ATT&CK mapping: `T1547.009` — Shortcut Modification
---

5. Confirm User Execution
* $J show the decoy document was opened by the user at: `2025-09-02 08:15:05`
![Anal3](https://miro.medium.com/v2/resize:fit:720/format:webp/1*vGLSiAn_Swg1h-t0fNMgmg.png)

---

## Results
Features of the Attack

* Exploit Used: CVE-2025–8088 (WinRAR Path Traversal via ADS)
* Threat Actor: RomCom APT
* Infection Flow:

Malicious archive extracted

1. Decoy PDF displayed to user
2. Backdoor dropped in %LOCALAPPDATA%
3. .lnk persistence created in Startup
4. User opened decoy PDF (believing it was benign)

## Question Answers

| Task | Question                 | Answer                                                                 |
|------|--------------------------|------------------------------------------------------------------------|
| 1    | CVE exploited            | CVE-2025-8088                                                          |
| 2    | Nature of vuln           | Path Traversal                                                         |
| 3    | Malicious archive        | Pathology-Department-Research-Records.rar                              |
| 4    | Archive created          | 2025-09-02 08:13:50                                                    |
| 5    | Archive opened           | 2025-09-02 08:14:04                                                    |
| 6    | Decoy document           | Genotyping_Results_B57_Positive.pdf                                    |
| 7    | Backdoor executable      | `C:\Users\Susan\AppData\Local\ApbxHelper.exe`                          |
| 8    | Persistence file         | `C:\Users\Susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk` |
| 9    | MITRE Technique          | T1547.009                                                              |
| 10   | Decoy opened             | 2025-09-02 08:15:05                                                    |





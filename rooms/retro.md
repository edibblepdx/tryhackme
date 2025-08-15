# Retro
https://tryhackme.com/room/retro

Can you time travel? If not, you might want to think about the next best thing.  

Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.  

There are two distinct paths that can be taken on Retro. One requires significantly less trial and error, however, both will work. Please check writeups if you are curious regarding the two paths. An alternative version of this room is available in it's remixed version Blaster.  

## Questions

> A web server is running on the target. What is the hidden directory which the website lives on?  

> +50 user.txt  

> +100 root.txt  

## 1. Enumerate Ports

```bash
└─$ nmap -A -sC -Pn 10.201.95.130
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-14 16:20 PDT
Nmap scan report for 10.201.95.130
Host is up (0.24s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2025-08-14T23:20:51+00:00
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2025-08-13T23:18:07
|_Not valid after:  2026-02-12T23:18:07
|_ssl-date: 2025-08-14T23:20:55+00:00; 0s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012 (87%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows Server 2016 (87%), Microsoft Windows Server 2012 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   158.44 ms 10.23.0.1
2   ... 3
4   228.60 ms 10.201.95.130

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.93 seconds
```

> port 80/tcp is an http port  

> port 3389/tcp is Microsoft's [Remote Desktop Protocol](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-rdp.html) 
> service standard port number  

Looking at this we should visit the site and have a look around, keeping in mind that we
probably want to somehow log into the remote desktop. But first let's do another `nmap`
scan focusing on port 3389.

```bash
└─$ nmap -Pn --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 10.201.95.130
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-14 16:52 PDT
Nmap scan report for 10.201.95.130
Host is up (0.23s latency).

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
| rdp-enum-encryption: 
|   Security layer
|     CredSSP (NLA): SUCCESS
|     CredSSP with Early User Auth: SUCCESS
|_    RDSTLS: SUCCESS
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2025-08-14T23:52:04+00:00

Nmap done: 1 IP address (1 host up) scanned in 4.64 seconds
```

## 2. Find the Hidden Directory with the Website

Visiting MACHINE_IP in the browser returns a Microsoft Windows Server landing page.
To find the Retro website we should start fuzzing directories.

```bash
└─$ ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u http://10.201.95.130/FUZZ -mc all -fc 404 -t 80    

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.201.95.130/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 80
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 224ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 231ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 231ms]
#                       [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 235ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 235ms]
#                       [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 235ms]
# directory-list-2.3-small.txt [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 236ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 238ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 238ms]
#                       [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 239ms]
# Copyright 2007 James Fisher [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 239ms]
                        [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 232ms]
# on atleast 3 different hosts [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 239ms]
#                       [Status: 200, Size: 703, Words: 27, Lines: 32, Duration: 225ms]
retro                   [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 270ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

`ffuf` was quick to find the `/retro` directory which hosts a WordPress website.  

There are 6 blog posts by a user named Wade.  

## 3. Try wpscan

> Didn't find anything useful, but it's good to try.

```bash
└─$ wpscan --url http://10.201.95.130/retro/
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
 
[+] URL: http://10.201.95.130/retro/ [10.201.95.130]
[+] Started: Thu Aug 14 16:48:40 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Microsoft-IIS/10.0
 |  - X-Powered-By: PHP/7.1.29
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.201.95.130/retro/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.201.95.130/retro/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.201.95.130/retro/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.2.1 identified (Insecure, released on 2019-05-21).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.201.95.130/retro/index.php/feed/, <generator>https://wordpress.org/?v=5.2.1</generator>
 |  - http://10.201.95.130/retro/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.1</generator>

[+] WordPress theme in use: 90s-retro
 | Location: http://10.201.95.130/retro/wp-content/themes/90s-retro/
 | Latest Version: 1.4.10 (up to date)
 | Last Updated: 2019-04-15T00:00:00.000Z
 | Readme: http://10.201.95.130/retro/wp-content/themes/90s-retro/readme.txt
 | Style URL: http://10.201.95.130/retro/wp-content/themes/90s-retro/style.css?ver=5.2.1
 | Style Name: 90s Retro
 | Style URI: https://organicthemes.com/retro-theme/
 | Description: Have you ever wished your WordPress blog looked like an old Geocities site from the 90s!? Probably n...
 | Author: Organic Themes
 | Author URI: https://organicthemes.com
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.4.10 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.201.95.130/retro/wp-content/themes/90s-retro/style.css?ver=5.2.1, Match: 'Version: 1.4.10'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:10 <=====================================================================> (137 / 137) 100.00% Time: 00:00:10

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Aug 14 16:49:08 2025
[+] Requests Done: 170
[+] Cached Requests: 5
[+] Data Sent: 44.025 KB
[+] Data Received: 221.091 KB
[+] Memory used: 269.691 MB
[+] Elapsed time: 00:00:27
```

## 4. Try a Remote Desktop Connection

https://www.kali.org/tools/freerdp3/#xfreerdp3

Wade left a single comment on one of the blog posts that happened to be his password. >_>

```bash
$ xfreerdp3 /u:wade /p:parzival /v:10.201.95.130
```

## 3. user.txt

It's right on the desktop.
> 3b99fbdc6d430bfb51c72c651a261927


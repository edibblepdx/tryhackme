# Description

Crack the code, command the exploit! Dive into the heart of the system with just an RCE CVE as your key.  

__From Three Million Bricks to Three Million Transactions!__  

Brick Press Media Co. was working on creating a brand-new web theme that represents a renowned wall using three million byte bricks. Agent Murphy comes with a streak of bad luck. And here we go again: the server is compromised, and they've lost access.  

Can you hack back the server and identify what happened there?  

__Note:__ Add `MACHINE_IP` bricks.thm to your __/etc/hosts__ file.  

## Questions

> What is the content of the hidden .txt file in the web folder?  

> What is the name of the suspicious process?  

> What is the service name affiliated with the suspicious process?  

> What is the log file name of the miner instance?  

> What is the wallet address of the miner instance?  

> The wallet address used has been involved in transactions between wallets belonging to which threat group?  

# Steps

## 1. enumerate ports with `nmap`

```bash
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 0e:9a:b9:cf:85:5a:6e:97:c8:df:e0:24:c8:c1:02:2e (RSA)
|   256 ca:74:46:b4:3d:86:c3:b4:9c:ae:26:21:12:a7:60:a2 (ECDSA)
|_  256 16:20:8a:a9:df:26:6c:8f:33:4d:bd:b2:7d:2d:04:47 (ED25519)
80/tcp   open  http     Python http.server 3.5 - 3.10
|_http-title: Error response
|_http-server-header: WebSockify Python/3.8.10
443/tcp  open  ssl/http Apache httpd
| tls-alpn:
|   h2
|_  http/1.1
|_http-server-header: Apache
|_ssl-date: TLS randomness does not represent time
|_http-generator: WordPress 6.5
|_http-title: Brick by Brick
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=US
| Not valid before: 2024-04-02T11:59:14
|_Not valid after:  2025-04-02T11:59:14
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
3306/tcp open  mysql    MySQL (unauthorized)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Visiting `https://bricks.thm:443` is just a picture of bricks. The questions that the room is asking makes it sound like the site was hijacked by a crypto miner.  

I tried looking through __exploit-db__ for WordPress 6.5, but was not finding what I was looking for so I instead searched for __WordPress 6.5 CVE__ in my browser and found this site for [`wpscan`](https://wpscan.com/wordpress/65/). Kali Linux has `wpscan` installed so we can use it.  

## 2. wpscan

```bash
└─$ wpscan -v --url https://bricks.thm/ --disable-tls-checks
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

[+] URL: https://bricks.thm/ [10.201.20.31]
[+] Started: Tue Aug  5 18:36:26 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: server: Apache
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: https://bricks.thm/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: https://bricks.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: https://bricks.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: https://bricks.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.5 identified (Insecure, released on 2024-04-02).
 | Found By: Rss Generator (Passive Detection)
 |  - https://bricks.thm/feed/, <generator>https://wordpress.org/?v=6.5</generator>
 |  - https://bricks.thm/comments/feed/, <generator>https://wordpress.org/?v=6.5</generator>

[+] WordPress theme in use: bricks
 | Location: https://bricks.thm/wp-content/themes/bricks/
 | Readme: https://bricks.thm/wp-content/themes/bricks/readme.txt
 | Style URL: https://bricks.thm/wp-content/themes/bricks/style.css
 | Style Name: Bricks
 | Style URI: https://bricksbuilder.io/
 | Description: Visual website builder for WordPress.
 | Author: Bricks
 | Author URI: https://bricksbuilder.io/
 | License: GPLv2
 | License URI: https://www.gnu.org/licenses/gpl-2.0.html
 | Text Domain: bricks
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.9.5 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - https://bricks.thm/wp-content/themes/bricks/style.css, Match: 'Version: 1.9.5'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:09 <===============================================> (137 / 137) 100.00% Time: 00:00:09

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Aug  5 18:36:47 2025
[+] Requests Done: 170
[+] Cached Requests: 7
[+] Data Sent: 41.615 KB
[+] Data Received: 110.502 KB
[+] Memory used: 265.75 MB
[+] Elapsed time: 00:00:21
```

The important part is here:

```bash
[+] WordPress theme in use: bricks
 | Location: https://bricks.thm/wp-content/themes/bricks/
 | Readme: https://bricks.thm/wp-content/themes/bricks/readme.txt
 | Style URL: https://bricks.thm/wp-content/themes/bricks/style.css
 | Style Name: Bricks
 | Style URI: https://bricksbuilder.io/
 | Description: Visual website builder for WordPress.
 | Author: Bricks
 | Author URI: https://bricksbuilder.io/
 | License: GPLv2
 | License URI: https://www.gnu.org/licenses/gpl-2.0.html
 | Text Domain: bricks
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.9.5 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - https://bricks.thm/wp-content/themes/bricks/style.css, Match: 'Version: 1.9.5'
```

The WordPress site is made using bricks builder (bricks is the name of the room so this is likely the vulnerability). It uses version 1.9.5 of bricks builder and I was able to find [remote code execution](https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT) in versions <= 1.9.6 of the bricks builder plugin. I downloaded the python script and ran it.

## 3. Exploit bricks builder plugin <= 1.9.6 RCE



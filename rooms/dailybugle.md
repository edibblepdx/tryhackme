
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

> port 3306/tcp is a MariaDB server latest possible version 10.3.23

From this we can also see that the Daily Bugle is using Joomla cms. There
are a lot of directories disallowed by the robots.txt so it could be a good
idea to fuzz them. We could also not that the site uses php.

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

## 4. Find the Joomla Version

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

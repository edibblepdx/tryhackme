
# Crypto Failures
https://tryhackme.com/room/cryptofailures  

Implementing your own military-grade encryption is usually not the best idea.  

First exploit the encryption scheme in the simplest possible way, then find the encryption key.  

## Questions

> What is the value of the web flag?  

> What is the encryption key?  

## Steps

1. Enumerate ports
`nmap -A -sC -sV`
```bash
┌──(edibble㉿kali)-[~]
└─$ sudo nmap -A -sC -sV 10.201.27.255
[sudo] password for edibble: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-11 10:39 PDT
Nmap scan report for 10.201.27.255
Host is up (0.21s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 57:2c:43:78:0c:d3:13:5b:8d:83:df:63:cf:53:61:91 (ECDSA)
|_  256 45:e1:3c:eb:a6:2d:d7:c6:bb:43:24:7e:02:e9:11:39 (ED25519)
80/tcp open  http    Apache httpd 2.4.59 ((Debian))
|_http-title: Did not follow redirect to /
|_http-server-header: Apache/2.4.59 (Debian)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   154.51 ms 10.23.0.1
2   ... 3
4   220.90 ms 10.201.27.255

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.37 seconds
```

There are ssh and http ports running on an apache web server.

2. After inspecting the page there is reference to .bak files so use ffuf to fuzz directories

```bash
ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u http://10.201.15.131/FUZZ -e .php,.php.bak -mc all -fc 404 -t 80
```

3. Use `wget` to grab the index.php.bak
```php
<?php
include('config.php');


function generate_cookie($user,$ENC_SECRET_KEY) {
    $SALT=generatesalt(2);

    $secure_cookie_string = $user.":".$_SERVER['HTTP_USER_AGENT'].":".$ENC_SECRET_KEY;

    $secure_cookie = make_secure_cookie($secure_cookie_string,$SALT);

    setcookie("secure_cookie",$secure_cookie,time()+3600,'/','',false); 
    setcookie("user","$user",time()+3600,'/','',false);
}


function cryptstring($what,$SALT){
    return crypt($what,$SALT);
}


function make_secure_cookie($text,$SALT) {
    $secure_cookie='';

    foreach ( str_split($text,8) as $el ) {
        $secure_cookie .= cryptstring($el,$SALT);
    }

    return($secure_cookie);
}


function generatesalt($n) {
    $randomString='';
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

    for ($i = 0; $i < $n; $i++) {
        $index = rand(0, strlen($characters) - 1);
        $randomString .= $characters[$index];
    }

    return $randomString;
}


function verify_cookie($ENC_SECRET_KEY){
    $crypted_cookie=$_COOKIE['secure_cookie'];
    $user=$_COOKIE['user'];
    $string=$user.":".$_SERVER['HTTP_USER_AGENT'].":".$ENC_SECRET_KEY;

    $salt=substr($_COOKIE['secure_cookie'],0,2);

    if(make_secure_cookie($string,$salt)===$crypted_cookie) {
        return true;
    } else {
        return false;
    }
}


if ( isset($_COOKIE['secure_cookie']) && isset($_COOKIE['user']))  {
    $user=$_COOKIE['user'];

    if (verify_cookie($ENC_SECRET_KEY)) {
        if ($user === "admin") {
            echo 'congrats: ******flag here******. Now I want the key.';
        } else {
            $length=strlen($_SERVER['HTTP_USER_AGENT']);

            print "<p>You are logged in as " . $user . ":" . str_repeat("*", $length) . "\n";

            print "<p>SSO cookie is protected with traditional military grade en<b>crypt</b>ion\n";
        }
    } else {
        print "<p>You are not logged in\n";
    }
} else {
    generate_cookie('guest',$ENC_SECRET_KEY);

    header('Location: /');
}
?>
```

Function generate_cookie
- Creates a 2 character random salt
- Creates a secure cookie string
- Sets secure and user cookies

Function cryptstring
- Encrypts a value with a salt

Function make_secure_cookie
- Splits the string and calls cyptsrting on every 8 characters to generate the secure cookie

Function generatesalt
- Randomly generates n-length salt \[0-9a-zA-Z\]

Function verify_cookie
- Regenerates a new secure cookie with the same salt and compares it to the original

Rest of the script
- Checks if both cookies are set and verifies the secure cookie otherwise generates new cookies
- If user is admin you get the thm flag otherwise a user message
- If not logged in it gives a message for that too

My HTTP_USER_AGENT is
Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0  

So the secure cookie string is:
> {user cookie}:Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0:{encrypted secret key}  

From this code snippet: `if ($user === "admin")`, we want to set the user cookie to admin. The rest of the secure cookie string should not change since it is encrypted in 8 byte chunks. Currently the user cookie is set to “guest”.  

> R1OUUJ9jdoySER1o63g04iHFyIR1UMS3DyAwEakR16H890eIUnbUR1WSq%2FS5GGpv6R13n3.iBwMTnIR11RBVaxPv36cR1GMlZaAEPEuoR1W8T33GzdT9AR1oCy1hPh9zA.R1p.83Exjvf1AR1cANJ6t8OCxkR1D.REqBRG2JER1JIMFLh1etawR1q0WLeus.qUwR1KBc.f4CrMlER16.benPO2PcgR14numq8pkgpIR1hn4jrY.E9DgR1v%2FAULeyhD8QR1UTAYgsgLQMIR1MqwyADmeWdcR1vJ.Z0mxGIpkR10NNB8WmHh72R1p9uzAEiFbloR1y5Nwel10JdsR1OjpU0KultrER1tCy.Fls0HPQR1nItOw%2Fdsppc  

Above is the secure cookie. The first two bytes of each block are the salt: “R1”.  

4. Tamper with the cookie to get the first key

5. Write a python script to brute force the second key

## Sources

1. https://tryhackme.com/room/authenticationbypass
2. https://tryhackme.com/room/subdomainenumeration
3. https://security.stackexchange.com/questions/251685/how-can-an-attacker-identify-if-a-website-is-using-php-how-about-the-php-versio
4. https://stackoverflow.com/questions/4672088/how-can-i-find-the-version-of-php-that-is-running-on-a-distinct-domain-name
5. https://tryphp.w3schools.com/showphp.php?filename=demo_global_server

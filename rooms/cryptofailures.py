#!/usr/bin/env python

import string
import urllib.parse
from requests import Session
from crypt_r import crypt # crypt was deprecated and removed in python 3.13

# The goal is to find the value of ENC_SECRET_KEY which is hashed within
# the secure_cookie. The format is USER:USER_AGENT:ENC_SECRET_KEY.

# Each 8-byte block is encrypted with a 2-byte salt. Use the USER_AGENT as
# padding to brute force the ENC_SECRET_KEY. Start with a really long USER_AGENT
# and remove a character each time until you reveal the full ENC_SECRET_KEY.

# guest:AA ... AAAAAA:S ... 128 A
# guest:AA ... AAAAA:SS ... 127 A
# guest:AA ... AAAA:SSS ... 126 A
# guest:AA ... AAA:SSSS ... 125 A
# guest:AA ... AA:SSSSS ... 124 A
# ...                 ^

# I don't know how long the ENC_SECRET_KEY is so I'll give a lot of padding first

BASE_URL = ""
USER = "guest"
CHARSET = string.printable

# https://stackoverflow.com/questions/31554771/how-can-i-use-cookies-in-python-requests
def get_secure_cookie(user_agent):
    session = Session()
    session.get(BASE_URL, headers={"User-Agent": user_agent})
    cookie = session.cookies.get("secure_cookie")
    # Replace %xx escapes with their single-character equivalent.
    return urllib.parse.unquote(cookie)

user_agent = 'A' * 512
enc_secret_key = ""
while True:
    # The last 7 bytes of the found (unencrypted) cookie
    tail = (('A' * 6) + ':' + enc_secret_key)[-7:]
    secure_cookie = get_secure_cookie(user_agent)
    salt = secure_cookie[:2]

    # The target is encrypted so it is 13 bytes wide (including the salt)
    # instead of an 8 byte wide unencrypted block.
    # ((512[padding] + 8) / 8) * 13[encrypted block size]
    target = secure_cookie[832:845]

    found = False
    for char in CHARSET:
        encrypted_block = crypt(tail + char, salt)
        if encrypted_block == target:
            found = True
            break

    if not found:
        break

    enc_secret_key += char
    user_agent = user_agent[:-1]
    # This will spill over towards the end since the string gets real long
    print(f"\r{enc_secret_key}", end="")

print("\ndone")

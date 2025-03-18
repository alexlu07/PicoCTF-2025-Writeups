# Guess My Cheese 2

Time for pico's annual guessy hellscape. Shoutout to that one guy who full cleared except for guess my cheese 2, what a legend.

We get a remote server and a list of a couple hundred cheeses. When you connect to the server, it spits out a bunch of flavortext, but this is what we're really looking for:
```
Here's my secret cheese -- if you're Squeexy, you'll be able to guess it:  76ec8d8cf12ae82c7affc72faf2aac8b1e4b467e29d04d03660984e99666f190
```
The solve path from here doesn't seem too bad, just gotta check the hashes of all the cheeses. From the hints, we even know that the hash function is sha256 and that there's a 2 nibble salt. To handle the salt, we can just add every byte to each cheese, which is still a very managable number.

randomperson made a script pretty quickly, but it didn't work 💀. We thought we were cooked, so I decided to try a couple quick modifications with zero expectation they would work.

1. Add salt at beginning instead of the end
2. All uppercase cheese.
3. All lowercase cheese.

Miraculously, lowercase worked! I'm honestly so thankful I guessed it so quickly, because it would've driven me crazy otherwise.

Here's the final solve script:

```
from hashlib import sha256
from pwn import *

r = remote('verbal-sleep.picoctf.net', 64979)
crack = r.recv().decode('utf-8').split('\n')[-5].split()[-1]
table = {}

with open('cheese_list.txt', 'r') as f:
    cheeses = f.read().split('\n')

for cheese in cheeses:
    cheese = cheese.lower()
    for i in range(0, 256):
        s = cheese.encode() + bytes([i])
        encoded = sha256(s).hexdigest()
        table[encoded] = s

answer = table[crack][:-1]
salt = hex(table[crack][-1])[2:]

r.sendline('g')
r.recv()
r.sendline(answer)
r.recv()
r.sendline(salt)

print(r.recv().decode('utf-8'))
```
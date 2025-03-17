# proof to the reimann hypothesis

i was like how do you solve this the generation is completely random???
and then i looked at N

```py
N = 14936781859804605588746838041713158561188415170352556184615401920008774342201052649375896800783072126172605808967780878422577224915764436716229847494556734
```

its an even number :skull::skull::skull::skull: 2 is a prime number

now we can get the values of p and q:
```py
p = 2
q = 7468390929902302794373419020856579280594207585176278092307700960004387171100526324687948400391536063086302904483890439211288612457882218358114923747278367
```
from that you can get the totient:
```py
totient = (p - 1) * (q - 1)
d = pow(e, -1, totient)
```
and decode the message by:
```py
long_to_bytes(pow(c, d, N))
```

full script:

```py
from Crypto.Util.number import isPrime, long_to_bytes

N = 14936781859804605588746838041713158561188415170352556184615401920008774342201052649375896800783072126172605808967780878422577224915764436716229847494556734
e = 65537
cyphertext = #somenumber
p = 2
q = N // 2

totient = (p - 1) * (q - 1)
d = pow(e, -1, totient)
m = pow(cyphertext, d, N)
print(long_to_bytes(m).decode())
```
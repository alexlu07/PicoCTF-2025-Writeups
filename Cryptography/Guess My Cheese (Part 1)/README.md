# im not a rat

i am squeexy (squeex)

the cheese is encrypted by an affine cipher (key unknown)

one catch is that space is also encrypted as a letter, so make sure to encrypt a cheese name containing a space (i used "brie de meaux") to find what letter it encodes to

full encryption process

```
brie de meaux -> BRIE DE MEAUX -> BRIETDETMEAUX (changes the space to some random letter) -> EAZNGKNGLNBJS (i used a=3, b=1) -> EAZNGKNGLNBJSBIX (adds 3 random letters at the end)
```

you can now plug in the encrypted string into dcode.fr (or cyberchef) and brute force for possible values of a and b to get the cheese

yeah thats kinda it
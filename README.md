# ckb-address-demo

CKB address format demo code.

Based on original Bech32 demo code form: https://github.com/sipa/bech32/tree/master/ref/python

```yml
== short address test ==
sample args to encode:   b39bbc0b3673c7d36450bc14cfcdad2d559c6c64
short address generate:  ckb1qyqt8xaupvm8837nv3gtc9x0ekkj64vud3jqfwyw5v
decode address:
 - format type:  short
 - code index:   0
 - args:         b39bbc0b3673c7d36450bc14cfcdad2d559c6c64

== full address test ==
code_hash to encode:     9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8
with args to encode:     b39bbc0b3673c7d36450bc14cfcdad2d559c6c64
full address generate:   ckb1qjda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xw3vumhs9nvu786dj9p0q5elx66t24n3kxgj53qks
decode address:
 - format type:  full
 - code type:    Type
 - code_hash:    9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8
 - args:         b39bbc0b3673c7d36450bc14cfcdad2d559c6c64
```

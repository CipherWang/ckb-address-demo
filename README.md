# ckb-address-demo

CKB address format demo code.

Based on original Bech32 demo code form: https://github.com/sipa/bech32/tree/master/ref/python

```
== short address test ==
sample pk to encode:        13e41d6F9292555916f17B4882a5477C01270142
short address generate:    ckb1qyqp8eqad7ffy42ezmchkjyz54rhcqf8q9pqrn323p
decode address:
    - format type:      short
    - code index:        0
    - pk string:            13e41d6f9292555916f17b4882a5477c01270142

== full address test ==
code_hash to encode:     48a2ce278d84e1102b67d01ac8a23b31a81cc54e922e3db3ec94d2ec4356c67c
with args to encode:         ['dde7801c073dfb3464c7b1f05b806bb2bbb84e99', '00c1ddf9c135061b7635ca51e735fc2b03cee339']
full address generate:      ckb1qfy29n383kzwzyptvlgp4j9z8vc6s8x9f6fzu0dnaj2d9mzr2mr8c9xau7qpcpealv6xf3a37pdcq6ajhwuyaxg5qrqam7wpx5rpka34efg7wd0u9vpuaceeu5fsh5
decode address:
    - format type:      full
    - code type:          Data
    - code_hash:        48a2ce278d84e1102b67d01ac8a23b31a81cc54e922e3db3ec94d2ec4356c67c
    - args array:          ['dde7801c073dfb3464c7b1f05b806bb2bbb84e99', '00c1ddf9c135061b7635ca51e735fc2b03cee339']
 ```

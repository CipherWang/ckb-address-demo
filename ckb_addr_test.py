#!/usr/bin/python3

# CKB Address test code
# cipher@nervos.org


import segwit_addr as sa


format_type_SHORT     = 0x01
format_type_FULL_DATA = 0x02
format_type_FULL_TYPE = 0x04

CODE_INDEX_SECP256K1 = 0x00

def generateShortAddress(pk, network = "mainnet"):
    """ generate a standard secp256k1 short ckb address """
    hrp = {"mainnet": "ckb", "testnet": "ckt"}[network]
    hrpexp =  sa.bech32_hrp_expand(hrp)
    format_type  = format_type_SHORT
    code_index = CODE_INDEX_SECP256K1
    payload = bytes([format_type, code_index]) + bytes.fromhex(pk)
    data_part = sa.convertbits(payload, 8, 5)
    values = hrpexp + data_part
    polymod = sa.bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    combined = data_part + checksum
    addr = hrp + '1' + ''.join([sa.CHARSET[d] for d in combined])
    return addr

def generateFullAddress(hash_type, code_hash, args, network = "mainnet"):
    format_type = {"Data" : bytes([format_type_FULL_DATA]), 
                 "Type" : bytes([format_type_FULL_TYPE])}[hash_type]
    hrp = {"mainnet": "ckb", "testnet": "ckt"}[network]
    hrpexp =  sa.bech32_hrp_expand(hrp)
    payload = bytes(format_type) + bytes.fromhex(code_hash)
    for arg in args:
        arg_bytes = bytes.fromhex(arg)
        len_arg = len(arg_bytes)
        if len_arg > 256 or len_arg == 0:
            return None
        else:
            payload += bytes([len_arg]) + arg_bytes
    data_part = sa.convertbits(payload, 8, 5)
    values = hrpexp + data_part
    polymod = sa.bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    combined = data_part + checksum
    addr = hrp + '1' + ''.join([sa.CHARSET[d] for d in combined])
    return addr


def decodeAddress(addr, network = "mainnet"):
    hrp = {"mainnet": "ckb", "testnet": "ckt"}[network]
    hrpgot, data = sa.bech32_decode(addr)
    if hrpgot != hrp or data == None:
        return False
    decoded = sa.convertbits(data, 5, 8, False)
    if decoded == None:
        return False
    payload = bytes(decoded)
    format_type = payload[0]
    if format_type == format_type_SHORT:
        code_index = payload[1]
        pk = payload[2:].hex()
        return ("short", code_index, pk)
    elif format_type == format_type_FULL_DATA or format_type == format_type_FULL_TYPE:
        full_type = {format_type_FULL_DATA:"Data", format_type_FULL_TYPE:"Type"}[format_type]
        ptr = 1
        code_hash = payload[ptr : ptr+32].hex()
        ptr += 32
        args = []
        while ptr < len(payload):
            arg_len = int(payload[ptr])
            ptr += 1
            args.append(payload[ptr : ptr+arg_len].hex())
            ptr += arg_len
        return ("full", full_type, code_hash, args)

if __name__ == "__main__":
    # test constant parameters
    SECP256K1_CODE_HASH = "48a2ce278d84e1102b67d01ac8a23b31a81cc54e922e3db3ec94d2ec4356c67c"
    MULTI_PK1 = "dde7801c073dfb3464c7b1f05b806bb2bbb84e99"
    MULTI_PK2 = "00c1ddf9c135061b7635ca51e735fc2b03cee339" 
    SINGLE_PK = "13e41d6F9292555916f17B4882a5477C01270142"
    
    # test short address functions
    print("== short address test ==")
    print("sample pk to encode:\t", SINGLE_PK)
    addr_short = generateShortAddress(SINGLE_PK)
    print("short address generate:\t", addr_short)
    decoded = decodeAddress(addr_short)
    print("decode address:")
    print(" - format type:\t", decoded[0])
    print(" - code index:\t", decoded[1])
    print(" - pk string:\t", decoded[2])
    
    # test full address functions
    print("\n== full address test ==")
    code_hash = SECP256K1_CODE_HASH
    args = [MULTI_PK1, MULTI_PK2]
    print("code_hash to encode:\t", code_hash)
    print("with args to encode:\t", args)
    addr_full = generateFullAddress("Data", code_hash, args)
    print("full address generate:\t", addr_full)
    decoded = decodeAddress(addr_full)
    print("decode address:")
    print(" - format type:\t", decoded[0])
    print(" - code type:\t", decoded[1])
    print(" - code_hash:\t", decoded[2])
    print(" - args array:\t", decoded[3])
    
    
    
    
    
    
    
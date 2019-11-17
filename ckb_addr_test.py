#!/usr/bin/python3

# CKB Address test code
# cipher@nervos.org


import segwit_addr as sa


FORMAT_TYPE_SHORT     = 0x01
FORMAT_TYPE_FULL_DATA = 0x02
FORMAT_TYPE_FULL_TYPE = 0x04

CODE_INDEX_SECP256K1 = 0x00

def generateShortAddress(pk, network = "mainnet"):
    """ generate a standard secp256k1 short ckb address """
    hrp = {"mainnet": "ckb", "testnet": "ckt"}[network]
    hrpexp =  sa.bech32_hrp_expand(hrp)
    format_type  = FORMAT_TYPE_SHORT
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
    format_type = {"Data" : bytes([FORMAT_TYPE_FULL_DATA]),
                 "Type" : bytes([FORMAT_TYPE_FULL_TYPE])}[hash_type]
    hrp = {"mainnet": "ckb", "testnet": "ckt"}[network]
    hrpexp =  sa.bech32_hrp_expand(hrp)
    payload = bytes(format_type) + bytes.fromhex(code_hash)
    payload += bytes.fromhex(args)
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
    if format_type == FORMAT_TYPE_SHORT:
        code_index = payload[1]
        pk = payload[2:].hex()
        return ("short", code_index, pk)
    elif format_type == FORMAT_TYPE_FULL_DATA or format_type == FORMAT_TYPE_FULL_TYPE:
        full_type = {FORMAT_TYPE_FULL_DATA:"Data", FORMAT_TYPE_FULL_TYPE:"Type"}[format_type]
        ptr = 1
        code_hash = payload[ptr : ptr+32].hex()
        ptr += 32
        args = payload[ptr :].hex()
        return ("full", full_type, code_hash, args)

if __name__ == "__main__":
    # test constant parameters
    SECP256K1_CODE_HASH = "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
    PKBLAKE160 = "b39bbc0b3673c7d36450bc14cfcdad2d559c6c64"

    # test short address functions
    print("== short address test ==")
    args = PKBLAKE160
    print("sample args to encode:\t", args)
    addr_short = generateShortAddress(args)
    print("short address generate:\t", addr_short)
    decoded = decodeAddress(addr_short)
    print("decode address:")
    print(" - format type:\t", decoded[0])
    print(" - code index:\t", decoded[1])
    print(" - args:\t", decoded[2])

    # test full address functions
    print("\n== full address test ==")
    code_hash = SECP256K1_CODE_HASH
    args = PKBLAKE160
    print("code_hash to encode:\t", code_hash)
    print("with args to encode:\t", args)
    addr_full = generateFullAddress("Type", code_hash, args)
    print("full address generate:\t", addr_full)
    decoded = decodeAddress(addr_full)
    print("decode address:")
    print(" - format type:\t", decoded[0])
    print(" - code type:\t", decoded[1])
    print(" - code_hash:\t", decoded[2])
    print(" - args:\t", decoded[3])








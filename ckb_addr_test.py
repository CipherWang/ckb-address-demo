#!/usr/bin/python3

# CKB Address test code
# cipher@nervos.org


import segwit_addr as sa
import hashlib
import unittest

def ckbhash():
    return hashlib.blake2b(digest_size=32, person=b'ckb-default-hash')


FORMAT_TYPE_SHORT     = 0x01
FORMAT_TYPE_FULL_DATA = 0x02
FORMAT_TYPE_FULL_TYPE = 0x04

CODE_INDEX_SECP256K1_SINGLE = 0x00
CODE_INDEX_SECP256K1_MULTI  = 0x01

def generateShortAddress(code_index, args, network = "mainnet"):
    """ generate a short ckb address """
    hrp = {"mainnet": "ckb", "testnet": "ckt"}[network]
    hrpexp =  sa.bech32_hrp_expand(hrp)
    format_type  = FORMAT_TYPE_SHORT
    payload = bytes([format_type, code_index]) + bytes.fromhex(args)
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
    PKBLAKE_Alice = "094ee28566dff02a012a66505822a2fd67d668fb"
    PKBLAKE_Bob = "4643c241e59e81b7876527ebff23dfb24cf16482"
    PKBLAKE_Cipher = "bd07d9f32bce34d27152a6a0391d324f79aab854"
    MULTI_SISG_PREFIX = b'\x00\x01\x02\x03'

    # test short address (code_hash_index = 0x00) functions
    print("== short address (code_hash_index = 0x00) test ==")
    args = PKBLAKE160
    print("args to encode:\t\t", args)
    addr_short = generateShortAddress(CODE_INDEX_SECP256K1_SINGLE, args)
    print("address generate:\t", addr_short)
    decoded = decodeAddress(addr_short)
    print(">> decode address:")
    print(" - format type:\t\t", decoded[0])
    print(" - code_hash_index:\t", decoded[1])
    print(" - args:\t\t", decoded[2])

    # test short address (code_hash_index = 0x01) functions
    print("\n== short address (code_hash_index = 0x01) test ==")
    multi_sign_script = MULTI_SISG_PREFIX \
        + bytes.fromhex(PKBLAKE_Cipher) \
        + bytes.fromhex(PKBLAKE_Alice) \
        + bytes.fromhex(PKBLAKE_Bob)
    hasher = ckbhash()
    hasher.update(multi_sign_script)
    multi_sign_script_hash = hasher.hexdigest()
    args = multi_sign_script_hash[:40]
    print("multi sign script:\t", multi_sign_script.hex())
    print("args to encode:\t\t", args)
    addr_short = generateShortAddress(CODE_INDEX_SECP256K1_MULTI, args)
    print("address generate:\t", addr_short)
    decoded = decodeAddress(addr_short)
    print(">> decode address:")
    print(" - format type:\t\t", decoded[0])
    print(" - code_hash_index:\t", decoded[1])
    print(" - args:\t\t", decoded[2])

    # test full address functions
    print("\n== full address test ==")
    code_hash = SECP256K1_CODE_HASH
    args = PKBLAKE160
    print("code_hash to encode:\t", code_hash)
    print("with args to encode:\t", args)
    addr_full = generateFullAddress("Type", code_hash, args)
    print("full address generate:\t", addr_full)
    decoded = decodeAddress(addr_full)
    print(">> decode address:")
    print(" - format type:\t\t", decoded[0])
    print(" - code type:\t\t", decoded[1])
    print(" - code hash:\t\t", decoded[2])
    print(" - args:\t\t", decoded[3])








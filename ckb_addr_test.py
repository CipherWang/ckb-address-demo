#!/usr/bin/python3

# CKB Address test code
# cipher@nervos.org


import segwit_addr as sa
import hashlib
import unittest

def ckbhash():
    return hashlib.blake2b(digest_size=32, person=b'ckb-default-hash')

# ref: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0021-ckb-address-format/0021-ckb-address-format.md
FORMAT_TYPE_SHORT     = 0x01
FORMAT_TYPE_FULL_DATA = 0x02
FORMAT_TYPE_FULL_TYPE = 0x04

CODE_INDEX_SECP256K1_SINGLE = 0x00
CODE_INDEX_SECP256K1_MULTI  = 0x01
CODE_INDEX_ACP              = 0x02

# ref: https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0024-ckb-system-script-list/0024-ckb-system-script-list.md
SCRIPT_CONST_MAINNET = {
    CODE_INDEX_SECP256K1_SINGLE : {
        "code_hash" : "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
        "hash_type" : "type",
        "tx_hash"   : "0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c",
        "index"     : "0",
        "dep_type"  : "dep_group"
    },
    CODE_INDEX_SECP256K1_MULTI : {
        "code_hash" : "0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8",
        "hash_type" : "type",
        "tx_hash"   : "0x71a7ba8fc96349fea0ed3a5c47992e3b4084b031a42264a018e0072e8172e46c",
        "index"     : "1",
        "dep_type"  : "dep_group"
    },
    CODE_INDEX_ACP : {
        "code_hash" : "0xd369597ff47f29fbc0d47d2e3775370d1250b85140c670e4718af712983a2354",
        "hash_type" : "type",
        "tx_hash"   : "0x4153a2014952d7cac45f285ce9a7c5c0c0e1b21f2d378b82ac1433cb11c25c4d",
        "index"     : "0",
        "dep_type"  : "dep_group"
    }
}

SCRIPT_CONST_TESTNET = {
    CODE_INDEX_SECP256K1_SINGLE : {
        "code_hash" : "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
        "hash_type" : "type",
        "tx_hash"   : "0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37",
        "index"     : "0",
        "dep_type"  : "dep_group"
    },
    CODE_INDEX_SECP256K1_MULTI : {
        "code_hash" : "0x5c5069eb0857efc65e1bca0c07df34c31663b3622fd3876c876320fc9634e2a8",
        "hash_type" : "type",
        "tx_hash"   : "0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37",
        "index"     : "1",
        "dep_type"  : "dep_group"
    },
    CODE_INDEX_ACP : {
        "code_hash" : "0x3419a1c09eb2567f6552ee7a8ecffd64155cffe0f1796e6e61ec088d740c1356",
        "hash_type" : "type",
        "tx_hash"   : "0xec26b0f85ed839ece5f11c4c4e837ec359f5adc4420410f6453b1f6b60fb96a6",
        "index"     : "0",
        "dep_type"  : "dep_group"
    }
}

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

def expandShortAddress(address):
    network = address[:3]
    content = decodeAddress(address, "mainnet" if network=="ckb" else "testnet")
    if content == False or content[0] == "full":
        return False
    script_dict = SCRIPT_CONST_MAINNET if network == "ckb" else SCRIPT_CONST_TESTNET
    code_index = content[1]
    code_setup = script_dict[code_index]
    lock_script = {
        "Code Hash" : code_setup["code_hash"],
        "Hash Type" : code_setup["hash_type"],
        "args"      : content[2]
    }
    return lock_script

if __name__ == "__main__":
    # setup network
    network = "mainnet"

    # test constant parameters
    SECP256K1_CODE_HASH = "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
    PKBLAKE160 = "b39bbc0b3673c7d36450bc14cfcdad2d559c6c64"
    PKBLAKE_Alice = "094ee28566dff02a012a66505822a2fd67d668fb"
    PKBLAKE_Bob = "4643c241e59e81b7876527ebff23dfb24cf16482"
    PKBLAKE_Cipher = "bd07d9f32bce34d27152a6a0391d324f79aab854"
    MULTI_SISG_PREFIX = b'\x00\x01\x02\x03'

    # test short address (code_hash_index = 0x00) functions
    print("== default short address (code_hash_index = 0x00) test ==")
    args = PKBLAKE160
    print("args to encode:\t\t", args)
    addr_short = generateShortAddress(CODE_INDEX_SECP256K1_SINGLE, args, network)
    print("address generated:\t", addr_short)
    decoded = decodeAddress(addr_short, network)
    print(">> decode address:")
    print(" - format type:\t\t", decoded[0])
    print(" - code_hash_index:\t", decoded[1])
    print(" - args:\t\t", decoded[2])
    print(">> expand to script")
    print(expandShortAddress(addr_short))

    # test short address (code_hash_index = 0x01) functions
    print("\n== multisign short address (code_hash_index = 0x01) test ==")
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
    addr_short = generateShortAddress(CODE_INDEX_SECP256K1_MULTI, args, network)
    print("address generated:\t", addr_short)
    decoded = decodeAddress(addr_short, network)
    print(">> decode address:")
    print(" - format type:\t\t", decoded[0])
    print(" - code_hash_index:\t", decoded[1])
    print(" - args:\t\t", decoded[2])
    print(">> expand to script")
    print(expandShortAddress(addr_short))

    # test short address (code_hash_index = 0x02) functions
    print("\n== acp short address (code_hash_index = 0x02) test ==")
    args = PKBLAKE_Cipher
    print("args to encode:\t\t", args)
    addr_short = generateShortAddress(CODE_INDEX_ACP, args, network)
    print("address generated:\t", addr_short)
    decoded = decodeAddress(addr_short, network)
    print(">> decode address:")
    print(" - format type:\t\t", decoded[0])
    print(" - code_hash_index:\t", decoded[1])
    print(" - args:\t\t", decoded[2])
    print(">> expand to script")
    print(expandShortAddress(addr_short))
    
    # test full address functions
    print("\n== full address test ==")
    code_hash = SECP256K1_CODE_HASH
    args = PKBLAKE160
    print("code_hash to encode:\t", code_hash)
    print("with args to encode:\t", args)
    addr_full = generateFullAddress("Type", code_hash, args, network)
    print("full address generated:\t", addr_full)
    decoded = decodeAddress(addr_full, network)
    print(">> decode address:")
    print(" - format type:\t\t", decoded[0])
    print(" - code type:\t\t", decoded[1])
    print(" - code hash:\t\t", decoded[2])
    print(" - args:\t\t", decoded[3])

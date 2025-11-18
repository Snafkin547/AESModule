import random

def bitlist_to_int(_list):

    out = 0
    for bit in _list:
        out = (out << 1) | bit
    return out

def int_to_bitlist(num, size=None):
    if size is None:
        bin_str = bin(num)[2:]
        size = len(bin_str)
    else:
        bin_str = bin(num)[2:].zfill(size)
    return [int(b) for b in bin_str]

def int_to_bytes_list(num, length=16):
    hex_str = hex(num)[2:].rstrip('L')
    hex_str = hex_str.zfill(length * 2)
    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

def bytes_list_to_int(bytes_list):
    """Helper: Converts a list of byte integers back to a large integer."""
    res = 0
    for b in bytes_list:
        res = (res << 8) | b
    return res

def xor_bytes(list_a, list_b):
    """XORs two lists of bytes element-wise."""
    return [a ^ b for a, b in zip(list_a, list_b)]
"""Cryptopals Challenges: Test Challenge 02: Fixed XOR."""

import sys
import cp_aux_utils as utils

title = "Challenge 02: Fixed XOR"

def execute_xor(src_str, key_str, in_fmt = "hex", out_fmt = "hex"):
    """Return string with the XOR between two strings."""

    # Convert to byte array.
    if in_fmt == "hex":
        src_b = utils.hexstr2bytes(src_str)
        key_b = utils.hexstr2bytes(key_str)
    elif in_fmt == "raw":
        src_b = utils.rawstr2bytes(src_str)
        key_b = utils.rawstr2bytes(key_str)
    else: # in_fmt == "bytes"
        src_b = src_str
        key_b = key_str

    # Do the xor.
    xor_b = utils.xor(src_b, key_b)

    # Convert to raw string.
    if out_fmt == "hex":
        xor_str = utils.bytes2hexstr(xor_b)
    elif out_fmt == "raw":
        xor_str = utils.bytes2rawstr(xor_b)
    else: # out_fmt == "bytes"
        xor_str = xor_b

    return xor_str

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_src_str = '1c0111001f010100061a024b53535009181c'
        in_key_str = '686974207468652062756c6c277320657965'
        out_str_ok = '746865206b696420646f6e277420706c6179'
        out_str = execute_xor(in_src_str, in_key_str)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_src   = [{1}]".format(me, in_src_str))
        print("{0}: in_key   = [{1}]".format(me, in_key_str))
        print("{0}: result   = [{1}]".format(me, out_str))
        print("{0}: expected = [{1}]".format(me, out_str_ok))
        if out_str != out_str_ok:
            err_str = "\n{0}: ".format(me) + "-" * 60
            err_str += "\n{0}: TEST     = [FAILED] Result doesn't match expected.".format(me)
            err_str += "\n{0}: ".format(me) + "-" * 60
            raise Exception(err_str)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: TEST     = [OK]".format(me))
        print("{0}: ".format(me) + "-" * 60)
    except Exception:
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Caught ERROR EXCEPTION:".format(me))
        raise
    except:
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Caught UNEXPECTED EXCEPTION:".format(me))
        raise

    sys.exit(0)


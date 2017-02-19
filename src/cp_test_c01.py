"""Cryptopals Challenges: Test Challenge 01: Convert hex to base64."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 01: Convert hex to base64"

def execute_hex2base64(hex_str):
    """Convert an hex encoded string to a base64 encoded string."""

    # Convert to byte array.
    b = utils.hexstr2bytes(hex_str)

    # Convert to base64.
    b64 = utils.bytes2base64bytes(b)

    # Convert to raw string.
    b64_str = utils.bytes2rawstr(b64)

    return b64_str

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        out_str_ok = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        out_str = execute_hex2base64(in_str)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in       = [{1}]".format(me, in_str))
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


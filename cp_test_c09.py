"""Cryptopals Challenges: Test Challenge 09: Implement PKCS#7 padding."""

import sys
import cp_aux_utils as utils

title = "Challenge 09: Implement PKCS#7 padding"

def execute_pkcs7_padding(b, sz):
    """Do PKCS#7 padding on a byte string."""

    # Just use utils function.
    return utils.pkcs7_pad(b, sz)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_str = b"YELLOW SUBMARINE"
        in_size = 20
        out_str = execute_pkcs7_padding(in_str, in_size)
        out_str_ok = b"YELLOW SUBMARINE\x04\x04\x04\x04"
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_str   = [{1}]".format(me, in_str))
        print("{0}: in_size  = [{1}]".format(me, in_size))
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


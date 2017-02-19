"""Cryptopals Challenges: Test Challenge 12: Byte-at-a-time ECB decryption (Simple)."""

import sys
import utils.cp_aux_utils as utils
import cp_test_c14 as c14

title = "Challenge 12: Byte-at-a-time ECB decryption (Simple)"

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        (out_res, blk_sz, prefix_sz) = c14.execute_break_ecb(c14.encryption_oracle, False)
        out_file = 'data/data_c12_out.txt'
        out_res_ok = utils.file_get(out_file)
        # Add one padding byte.
        out_res_ok += "\x01"
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: result   = [<see below>]".format(me))
        print("{0}: ".format(me) + "-" * 60)
        print(out_res)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: expected = [<see below>]".format(me))
        print("{0}: ".format(me) + "-" * 60)
        print(out_res_ok)
        if out_res != out_res_ok:
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


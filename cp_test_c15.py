"""Cryptopals Challenges: Test Challenge 15: PKCS#7 padding validation."""

import sys
import cp_aux_utils as utils

title = "Challenge 15: PKCS#7 padding validation"

def execute_pkcs7_padding_validation(s, blk_sz):
    """Validates if string has valid PKCS#7 padding."""

    s_b = utils.rawstr2bytes(s)
    utils.pkcs7_unpad(s_b, blk_sz)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_blk_sz = 16
        in_str = "ICE ICE BABY"
        in_str1 = in_str + "\x04" * 4
        in_str2 = in_str + "\x05" * 4
        in_str3 = in_str + "\x01\x02\x03\x04"
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        ok = True
        # This one is supposed to pass.
        print("{0}: in_str1  = [{1}]".format(me, utils.rawstr2bytes(in_str1)))
        try:
            execute_pkcs7_padding_validation(in_str1, in_blk_sz)
        except Exception:
            ok = False
            print("{0}: result1  = [FAIL]".format(me))
        else:
            print("{0}: result1  = [OK] (No exception caught)".format(me))
        # This one is supposed to fail.
        print("{0}:".format(me))
        print("{0}: in_str2  = [{1}]".format(me, utils.rawstr2bytes(in_str2)))
        if ok:
            try:
                execute_pkcs7_padding_validation(in_str2, in_blk_sz)
            except Exception as e:
                print("{0}: result2  = [OK] (Caught exception: {1})".format(me, e.args[0]))
            else:
                ok = False
                print("{0}: result2  = [FAIL]".format(me))
        # This one is supposed to fail.
        print("{0}:".format(me))
        print("{0}: in_str3  = [{1}]".format(me, utils.rawstr2bytes(in_str3)))
        if ok:
            try:
                execute_pkcs7_padding_validation(in_str3, in_blk_sz)
            except Exception as e:
                print("{0}: result3  = [OK] (Caught exception: {1})".format(me, e.args[0]))
            else:
                ok = False
                print("{0}: result3  = [FAIL]".format(me))
        if not ok:
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


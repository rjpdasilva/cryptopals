"""Cryptopals Challenges: Test Challenge 03: Single-byte XOR cipher."""

import sys
import cp_aux_utils as utils

title = "Challenge 03: Single-byte XOR cipher"

def execute_break_single_byte_xor(str):
    """Decrypt an hex encoded string ciphered with single-byte xor."""

    # Just use the utility function.
    return utils.break_single_byte_xor(str)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_str = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        out_res = execute_break_single_byte_xor(in_str)
        out_res_exp = (88, "Cooking MC's like a pound of bacon")
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_str   = [{1}]".format(me, in_str))
        print("{0}: result   = [(key={1}/0x{1:02x}, msg=\"{2}\")], score = [{3:.3f}]"
                .format(me, out_res[0], out_res[1], out_res[2]))
        print("{0}: expected = [(key={1}/0x{1:02x}, msg=\"{2}\")]"
                .format(me, out_res_exp[0], out_res_exp[1]))
        # Not possible to know what's the expected score, so make it
        # match the result score.
        out_res_ok = (out_res_exp[0], out_res_exp[1], out_res[2])
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


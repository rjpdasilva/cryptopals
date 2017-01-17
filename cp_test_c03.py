"""Cryptopals Challenges: Test Challenge 03: Single-byte XOR cipher."""

import sys
import cp_aux_utils as utils

def execute_break_single_byte_xor(hex_str):
    def score_decr(decr):
        # 'decr' is a tuple with the key and decrypted byte array.
        return utils.score_english_string(decr[1])

    # Convert to byte array.
    src_b = utils.hexstr2bytes(hex_str)
    # List all the keys and respective xor decrypted byte array.
    list_decr = [(k, utils.xor(src_b, bytes([k]))) for k in range(256)]

    # Get the high scoring decrypted byte array.
    res = max(list_decr, key = score_decr)

    # Convert decrypted message to raw string.
    res = (res[0], utils.bytes2rawstr(res[1]))

    return res

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_str = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        out_res = execute_break_single_byte_xor(in_str)
        out_res_ok = (88, "Cooking MC's like a pound of bacon")
        print(out_res)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_str   = [{1}]".format(me, in_str))
        print("{0}: result   = [(key={1}/0x{1:02x}, msg=\"{2}\")]"
                .format(me, out_res[0], out_res[1]))
        print("{0}: expected = [(key={1}/0x{1:02x}, msg=\"{2}\")]"
                .format(me, out_res_ok[0], out_res_ok[1]))
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


"""Cryptopals Challenges: Test Challenge 08: Detect AES in ECB mode."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 08: Detect AES in ECB mode"

def execute_detect_aes_ecb(file_name):
    """Detect a AES-ECB encrypted msg in a file."""

    # Get the file lines.
    lines = utils.file_get_lines(file_name)

    # Score each line for AES-ECB encrypted possibility.
    # Using blocks of size 'bs'.
    # Strategy according to challenge statement:
    #  "Remember that the problem with ECB is that it is
    #   stateless and deterministic; the same 16 byte
    #   plaintext block will always produce the same 16
    #   byte ciphertext."
    # So, for each line, will be looking for 16-byte aligned
    # blocks that appear repeated withing each line.
    # The more repetitions, the higher the score, which is
    # basically the total number of repetitions.
    bs = 16
    scores = [(i, l, utils.find_repetitions(l, bs)) for i, l in enumerate(lines, start = 1)]

    # Get the highest scored line.
    sort_key = (lambda s: s[2])
    high_score = max(scores, key = sort_key)

    return high_score

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_file = 'data/data_c08.txt'
        out_res = execute_detect_aes_ecb(in_file)
        out_res_exp = (133, "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_file  = [{1}]".format(me, in_file))
        print("{0}: result   = [(line={1}, data=<see below>)], score = [{2:.6f}]"
                .format(me, out_res[0], out_res[2]))
        print(out_res[1])
        print("{0}: expected = [(line={1}, data=<see below>)]"
                .format(me, out_res_exp[0]))
        print(out_res_exp[1])
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


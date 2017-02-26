# Released under the MIT License (https://opensource.org/licenses/MIT)
#
# Copyright (c) 2017 Ricardo Silva.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
# associated documentation files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge, publish, distribute,
# sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
# NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
# OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""Cryptopals Challenges: Test Challenge 04: Detect single-character XOR."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 04: Detect single-character XOR"

def execute_find_single_byte_xor(file_name):
    """Find a message encrypted with single-byte xor in a file."""

    # Get the file lines.
    lines = utils.file_get_lines(file_name)

    # Get the list of decrypted and scored lines.
    lines_decr_scored = [utils.break_single_byte_xor(l) for l in lines]

    # Get index of the high scoring decrypted line.
    sort_key = (lambda line_idx: lines_decr_scored[line_idx][2])
    line_high_score = max(range(len(lines_decr_scored)), key = sort_key)

    # Include the line number in the result.
    res = (line_high_score + 1,
            lines_decr_scored[line_high_score][0],
            lines_decr_scored[line_high_score][1],
            lines_decr_scored[line_high_score][2])

    return res

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_file = 'data/data_c04.txt'
        out_res = execute_find_single_byte_xor(in_file)
        out_res_exp = (171, 53, "Now that the party is jumping\n")
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_file  = [{1}]".format(me, in_file))
        print("{0}: result   = [(line={1}, key={2}/0x{2:02x}, msg=\"{3}\")], score = [{4:.3f}]"
                .format(me, out_res[0], out_res[1], out_res[2], out_res[3]))
        print("{0}: expected = [(line={1}, key={2}/0x{2:02x}, msg=\"{3}\")]"
                .format(me, out_res_exp[0], out_res_exp[1], out_res_exp[2]))
        # Not possible to know what's the expected score, so make it
        # match the result score.
        out_res_ok = (out_res_exp[0], out_res_exp[1], out_res_exp[2], out_res[3])
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


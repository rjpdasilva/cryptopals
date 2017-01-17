"""Cryptopals Challenges: Test Challenge 04: Detect single-character XOR."""

import sys
import cp_aux_utils as utils
import cp_test_c03 as c3

def execute_find_single_byte_xor(file_name):
    def file_get_lines(fn):
        with open(fn) as f:
            # Remove one trailing '\n' from the line, if it's there.
            for line in f:
                if line[-1] == '\n':
                    line = line[:-1]
                yield line

    def high_score(line_idx):
        # 'line_idx' is index of decrypted and scored line tuple
        # (key, decrypted byte arrary and score).
        return lines_decr_scored[line_idx][2]

    # Get the file lines.
    lines = file_get_lines(file_name)

    # Get the list of decrypted and scored lines.
    # Using Challenge 3 functionality.
    lines_decr_scored = [c3.execute_break_single_byte_xor(l) for l in lines]

    # Get index of the high scoring decrypted line.
    line_high_score = max(range(len(lines_decr_scored)), key = high_score)

    # Include the line number in the result.
    res = (line_high_score + 1,
            lines_decr_scored[line_high_score][0],
            lines_decr_scored[line_high_score][1],
            lines_decr_scored[line_high_score][2])

    return res

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_file = 'data_c4.txt'
        out_res = execute_find_single_byte_xor(in_file)
        out_res_exp = (171, 53, "Now that the party is jumping\n")
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


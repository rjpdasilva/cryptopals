"""Cryptopals Challenges: Test Challenge 21: Implement the MT19937 Mersenne Twister RNG."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 21: Implement the MT19937 Mersenne Twister RNG"

def execute_test_mt19937(seed, count):
    """Build a list with the 1st 'count' numbers given by MT19937 implementation using 'seed'."""

    rng = utils.MT19937(seed)
    numbers = [rng.uint32() for i in range(count)]

    return numbers

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_seed = 123456789
        in_count = 5000
        out_num_list = execute_test_mt19937(in_seed, in_count)
        out_file = 'data/data_c21_out.txt'
        out_num_list_ok = [int(l) for l in utils.file_get_lines(out_file)]
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_seed  = [{1}]".format(me, in_seed))
        print("{0}: in_count = [{1}]".format(me, in_count))
        if out_num_list != out_num_list_ok:
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


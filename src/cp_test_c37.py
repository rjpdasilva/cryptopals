"""Cryptopals Challenges: Test Challenge 37: Break SRP with a zero key: Client."""

import sys
import utils.cp_aux_utils as utils
import cp_test_c36 as c36

title = "Challenge 37: Break SRP with a zero key: Client"

if __name__ == '__main__':
    me = sys.argv[0]
    c36.main(me, title, True)
    sys.exit(0)


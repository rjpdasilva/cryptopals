"""Cryptopals Challenges: Test Challenge 37: Break SRP with a zero key: Server."""

import sys
import utils.cp_aux_utils as utils
import cp_test_c36_server as c36_server

title = "Challenge 37: Break SRP with a zero key: Server"

if __name__ == '__main__':
    me = sys.argv[0]
    c36_server.main(me, title)
    sys.exit(0)


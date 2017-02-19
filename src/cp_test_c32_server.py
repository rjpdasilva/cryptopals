"""Cryptopals Challenges: Test Challenge 32: Implement and break HMAC-SHA1 with a slightly less
artificial timing leak: Server."""

import sys
import cp_test_c31_server as c31_server

title = "Challenge 32: Implement and break HMAC-SHA1 with a slightly less artificial timing leak: Server"

# Delay used for each HMAC byte that is correct (ms).
server_delay = 3

if __name__ == '__main__':
    me = sys.argv[0]
    c31_server.main(me, title, server_delay)
    sys.exit(0)


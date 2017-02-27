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

"""Cryptopals Challenges: Test Challenge 40: Implement an E=3 RSA Broadcast attack."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 40: Implement an E=3 RSA Broadcast attack"

def execute_capture_data(msg, bitsize, rounds):
    """Simulates the data capturing required for breaking the message."""

    # Simulates the data capturing done by the attacker, which
    # will grab the following during 'rounds' times:
    #  + The public key.
    #  + The cipher encrypted with that public key.

    data_captured = []
    m = int(utils.rawstr2bytes(msg).hex(), 16)

    for _ in range(rounds):
        # Generate an RSA key pair.
        (prv, pub) = utils.rsa_genkeys(bitsize)
        # Encrypt the msg.
        cipher = utils.rsa_num_encrypt(pub, m)
        data_captured += [(pub, cipher)]

    return data_captured

def execute_break_rsa(data_captured):
    """Execute the RSA attack using CRT (Chinese Remainder Theorem) as described in the challenge's
    statement."""

    # Number of data capture rounds.
    rounds = len(data_captured)

    # List of ciphers.
    c = [c for ((e, n), c) in data_captured]

    # List of public keys' moduli.
    n = [n for ((e, n), c) in data_captured]
    # Product of all moduli.
    N = 1
    for i in range(rounds):
        N *= n[i]

    # List of ms[i].
    def calc_ms(i):
        res = 1
        for j in range(rounds):
            res *= n[j] if j != i else 1
        return res
    ms = [calc_ms(i) for i in range(rounds)]

    # Results (partial and total).
    r = [(c[i] * ms[i] * utils.invmod(ms[i], n[i])) for i in range(rounds)]
    R = sum(r) % N

    # Message recovering (cubic root of result).
    m = utils.nth_root(R, 3)
    msg = utils.bytes2rawstr(m.to_bytes((m.bit_length() + 7) // 8, 'big'))

    return msg

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_msg = "Sample test message to be cracked"
        in_bitsize = 512
        in_rounds = 3
        data_captured = execute_capture_data(in_msg, in_bitsize, in_rounds)
        out_msg = execute_break_rsa(data_captured)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_msg   = [{1}]".format(me, in_msg))
        print("{0}: bitsize  = [{1}]".format(me, in_bitsize))
        print("{0}: rounds   = [{1}]".format(me, in_rounds))
        print("{0}: out_msg  = [{1}]".format(me, out_msg))
        ok = (out_msg == in_msg)
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


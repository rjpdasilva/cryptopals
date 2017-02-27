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

"""Cryptopals Challenges: Test Challenge 39: Implement RSA."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 39: Implement RSA"

def execute_test_rsa(messages, bitsize):
    """Execute testing RSA encryption/decryption of given 'messages'."""

    # Create a RSA public/private key pair.
    (prv, pub) = utils.rsa_genkeys(bitsize)

    out_res = []
    for m in messages:
        # Some messages are integers already while others may be strings.
        if not isinstance(m, int):
            m = int(utils.rawstr2bytes(m).hex(), 16)
            is_str = True
        else:
            is_str = False

        # Encrypt.
        cipher = utils.rsa_num_encrypt(pub, m)
        # Decrypt.
        plain = utils.rsa_num_decrypt(prv, cipher)
        if is_str:
            plain = utils.bytes2rawstr(plain.to_bytes((plain.bit_length() + 7) // 8, 'big'))

        # Add to results.
        out_res += [(cipher, plain)]

    return out_res

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_bitsize = 128
        in_msgs = [42, 2**127]
        in_msgs += ["Some message", "Another message"]
        out_res = execute_test_rsa(in_msgs, in_bitsize)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: bitsize  = [{1}]".format(me, in_bitsize))
        all_ok = True
        for i, res in enumerate(out_res):
            msg = in_msgs[i]
            (cipher, plain) = res
            print("{0}: ".format(me) + "-" * 60)
            print("{0}: round    = [{1}]".format(me, i + 1))
            print("{0}: message  = [{1}]".format(me, msg))
            print("{0}: cipher   = [{1}]".format(me, cipher))
            print("{0}: plain    = [{1}]".format(me, plain))
            ok = (msg == plain)
            print("{0}: ok       = [{1}]".format(me, ok))
            all_ok = all_ok and ok
        if not all_ok:
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


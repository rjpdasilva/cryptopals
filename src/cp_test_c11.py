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

"""Cryptopals Challenges: Test Challenge 11: An ECB/CBC detection oracle."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 11: An ECB/CBC detection oracle"

# An encryption function we can exercise (call), but of
# which we are not supposed to know the implementation
# details.
def encryption_oracle(pt):
    """Encryption Oracle: Challenge 11."""

    # Uses a key and block size of 16 bytes.
    # Prepends 5 to 10 random bytes to the plaintext.
    # Appends 5 to 10 random bytes to the plaintext.
    # Chooses randomly between AES-ECB and AES-CBC
    # for encrypting.

    blk_sz = 16

    pt_b = utils.rawstr2bytes(pt)

    # Generate a random key.
    key_sz = blk_sz
    key = utils.rand_bytes(key_sz)

    # Build the plaintext (pt).
    pre_sz = utils.rand_int(5, 10)
    post_sz = utils.rand_int(5, 10)
    pre = utils.rand_bytes(pre_sz)
    post = utils.rand_bytes(post_sz)
    pt_b = pre + pt_b + post
    pt_b = utils.pkcs7_pad(pt_b, blk_sz)

    # Choose randomly between ECB and CBC.
    ecb = utils.rand_int(0, 1)

    # Encrypt.
    if ecb:
        mode = "ECB"
        ct = utils.aes_encrypt(pt_b, key, mode = mode)
    else:
        mode = "CBC"
        # Choose a random IV for CBC case.
        iv = utils.rand_bytes(blk_sz)
        ct = utils.aes_encrypt(pt_b, key, mode = mode, iv = iv)

    return (mode, ct)

def execute_detect_ecb_or_cbc(ct, blk_sz):
    """Detect if the ciphertext 'ct' was encrypted with ECB or CBC, blocks of 'blk_sz' size"""

    # Reuse ECB detection mode from Challenge 8.
    score = utils.find_repetitions(utils.bytes2hexstr(ct), blk_sz)
    if score:
        mode = "ECB"
    else:
        mode = "CBC"

    return mode

def get_loops():
    input_ok = False
    max = 10000
    while not input_ok:
        print("Enter number of loops to execute (1 ~ {0}):".format(max))
        i = input()
        try:
            loops = int(i)
        except:
            print("Invalid number:", i)
        else:
            if loops == 0 or loops > max:
                print("Invalid: {0}. Choose between 1 and {1}.".format(loops, max))
                continue
            input_ok = True
    return loops

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_file = "data/data_c06_out.txt"
        in_blk_sz = 16
        plaintext = utils.file_get(in_file)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        loops = get_loops()
        results = {'ok': 0, 'ko': 0}
        modes = {'ECB': 0, 'CBC': 0}
        for i in range(loops):
            (out_res_ok, ciphertext) = encryption_oracle(plaintext)
            out_res = execute_detect_ecb_or_cbc(ciphertext, in_blk_sz)
            if out_res == out_res_ok:
                results['ok'] += 1
            else:
                results['ko'] += 1
            modes[out_res_ok] += 1
        ok_rate = 100.0 * (results['ok'] / float(loops))
        ko_rate = 100.0 * (results['ko'] / float(loops))
        ecb_rate = 100.0 * (modes['ECB'] / float(loops))
        cbc_rate = 100.0 * (modes['CBC'] / float(loops))
        print("{0}: in_file  = [{1}]".format(me, in_file))
        print("{0}: loops    = [{1:5d}]".format(me, loops))
        print("{0}:   ECB    = [{1:5d}] ({2:6.2f}%)".format(me, modes['ECB'], ecb_rate))
        print("{0}:   CBC    = [{1:5d}] ({2:6.2f}%)".format(me, modes['CBC'], cbc_rate))
        print("{0}:   ok     = [{1:5d}] ({2:6.2f}%)".format(me, results['ok'], ok_rate))
        print("{0}:   ko     = [{1:5d}] ({2:6.2f}%)".format(me, results['ko'], ko_rate))
        if ok_rate < 100.0:
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


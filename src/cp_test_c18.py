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

"""Cryptopals Challenges: Test Challenge 18: Implement CTR, the stream cipher mode."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 18: Implement CTR, the stream cipher mode"

def execute_ctr_decrypt(s, k, n):
    """Use CTR to encrypt a given string, key and nonce parameters."""

    # Work with byte arrays.
    ct_b = utils.rawstr2bytes(s)
    ct_b = utils.base64bytes2bytes(s)
    key_b = utils.rawstr2bytes(k)

    # Get a AES-CTR object to work with for decryption.
    aes_ctr = utils.AesCtr(key_b, n)
    pt_b = aes_ctr.decrypt(ct_b)
    pt = utils.bytes2rawstr(pt_b)

    return pt

def execute_ctr_encrypt(s, k, n):
    """Use CTR to encrypt a given string, key and nonce parameters."""

    # Work with byte arrays.
    pt_b = utils.rawstr2bytes(s)
    key_b = utils.rawstr2bytes(k)

    # Get a AES-CTR object to work with for encryption.
    aes_ctr = utils.AesCtr(key_b, n)
    ct_b = aes_ctr.encrypt(pt_b)

    # Base64 encode the ciphertext.
    ct_b = utils.bytes2base64bytes(ct_b)
    ct = utils.bytes2rawstr(ct_b)

    return ct

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
        in_key = "YELLOW SUBMARINE"
        in_nonce = 0
        out_res_decrypt = execute_ctr_decrypt(in_str, in_key, in_nonce)
        out_res_encrypt = execute_ctr_encrypt(out_res_decrypt, in_key, in_nonce)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_str   = [{1}]".format(me, in_str))
        print("{0}: in_key   = [{1}]".format(me, in_key))
        print("{0}: in_nonce = [{1}]".format(me, in_nonce))
        print("{0}: decrypt  = [{1}]".format(me, out_res_decrypt))
        print("{0}: encrypt  = [{1}]".format(me, out_res_encrypt))
        if out_res_encrypt != in_str:
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


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

"""Cryptopals Challenges: Test Challenge 26: CTR bitflipping."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 26: CTR bitflipping"

# Random constant key and nonce used in encryption oracle.
key_b = None
nonce = None

def escape_userdata(s):
    """Escapes ';' (0x3b) and '=' (0x3d) chars from user data."""
    s = s.replace(b';', b'%3B')
    s = s.replace(b'=', b'%3D')

    return s

# An encryption function we can exercise (call), but of
# which we are not supposed to know the implementation
# details.
def encryption_oracle(pt_b):
    """Encryption Oracle: Challenge 26."""

    # Prepends a constant and know data block.
    # Appends a constant and know data block.
    # Uses AES-CTR for encrypting.

    prefix_b = b'comment1=cooking%20MCs;userdata='
    suffix_b = b';comment2=%20like%20a%20pound%20of%20bacon'

    global key_b
    global nonce
    blk_sz = 16

    # Generate a random key and nonce.
    aes_key_sz = blk_sz
    if key_b is None:
        key_b = utils.rand_bytes(aes_key_sz)
    if nonce is None:
        nonce = utils.rand_bytes(8)[0]

    # Build the plaintext (pt).
    pt_b = escape_userdata(pt_b)
    pt_b = prefix_b + pt_b + suffix_b

    # Encrypt.
    aes_ctr = utils.AesCtr(key_b, nonce)
    ct_b = aes_ctr.encrypt(pt_b)

    return ct_b

def decryption_oracle(ct_b):
    """Decrypts a message encrypted by the oracle."""

    global key_b
    global nonce

    # Confirm the key and nonce are available.
    if key_b is None or nonce is None:
        raise Exception("No key/nonce available yet. Must encrypt something first.")

    # Decrypt and unpad.
    aes_ctr = utils.AesCtr(key_b, nonce)
    pt_b = aes_ctr.decrypt(ct_b)

    return pt_b

def execute_ctr_bitflip_attack(s):
    """Perform a CTR bitflip attack, so that a string appears in the plaintext."""

    # Challenge is based on "Challenge 16: CBC bitflipping attacks",
    # but using AES-CTR instead of AES-CBC.
    #
    # The attack main rationale is the same: flipping one bit in the
    # ciphertext causes the same flip on the plaintext, due to the
    # XOR operations involved.
    # However, there are some differences resulting from using CTR:
    #  + The bit flipping affects the same bits in ciphertext and
    #    plaintext, unlike CBC, where the affected plaintext bit is
    #    in the block following the ciphertext one.
    #  + Unlike CBC, bit flipping in CTR is "clean", i.e, it's
    #    possible to change some plaintext without creating garbage
    #    on the plaintext block associated with the attacked
    #    ciphertext block.
    #
    # So, the strategy for CTR bit flipping is the same as for CBC,
    # but the flipping is done on the same ciphertext bits we want
    # to change on the plaintext.
    #
    # As in Challenge 16, the attack relies on knowing the block the
    # size of the prefix prepended by the oracle, which is
    # exactly 32 bytes.

    prefix_sz = 32

    # This is the block data the attacker can control.
    # The length is dictated by the string we want to force on the
    # plaintext.
    # Place some dummy text before and after the string we want to
    # force, just for fun.
    dummy_prefix_b = b'dummy_prefix'
    dummy_suffix_b = b'dummy_suffix'
    pt_orig_b = dummy_prefix_b + b'X' * len(s) + dummy_suffix_b
    pt_len = len(pt_orig_b)

    # Get the ciphertext.
    ct_orig_b = encryption_oracle(pt_orig_b)

    # Get the part we can control (oracle prepends 32 prefix bytes
    # to data).
    # This is the ciphertext part on which we will apply bit flipping
    # in order to create the desired string in the same place.
    ct_attack_b = ct_orig_b[prefix_sz:(prefix_sz + pt_len)]

    # The desired part of plaintext.
    pt_wanted_b = dummy_prefix_b + utils.rawstr2bytes(s) + dummy_suffix_b

    # Do the required bit flipping calculations.
    bits_to_flip_b = utils.xor(pt_orig_b, pt_wanted_b)
    ct_attacked_b = utils.xor(ct_attack_b, bits_to_flip_b)

    # Replace the original ciphertext with the attacked one.
    ct_attacked_b = ct_orig_b[0:prefix_sz] + ct_attacked_b + ct_orig_b[(prefix_sz + pt_len):]

    # Decrypt the attacked ciphertext to confirm attack success.
    pt_attacked_b = decryption_oracle(ct_attacked_b)
    found = pt_attacked_b.find(pt_wanted_b) != -1

    return (pt_attacked_b, found)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_str = ";admin=true;"
        (pt_attacked, found) = execute_ctr_bitflip_attack(in_str)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: attacked = [{1}]".format(me, pt_attacked))
        print("{0}: found    = [{1}]".format(me, found))
        if not found:
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


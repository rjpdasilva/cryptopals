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

"""Cryptopals Challenges: Test Challenge 17: The CBC padding oracle."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 17: The CBC padding oracle"

# Random constant key and IV used in encryption oracle.
key_b = None
iv_b = None
# Block size used.
blk_sz = 16

# The challenge plaintext base64 encoded strings to encrypt and break.
pt_strings = [
    b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
]

# Debug flag.
debug = 0

def debug_msg(*args, **kwargs):
    """Extra debug messages."""
    if not debug:
        return
    print(*args, **kwargs)

# An encryption function we can exercise (call), but of
# which we are not supposed to know the implementation
# details.
def encryption_oracle(string_idx):
    """Encryption Oracle: Challenge 17."""

    # Uses a key and block size of 16 bytes.
    # Uses AES-CBC for encrypting.
    # The plaintext is a random choice from a set
    # of base64 encoded strings, unless 'string_idx'
    # is not '-1', in which case the string selected
    # is the one given by the index.

    global key_b
    global iv_b

    # Generate random key and IV.
    if key_b is None:
        key_sz = blk_sz
        iv_sz = blk_sz
        key_b = utils.rand_bytes(key_sz)
        iv_b = utils.rand_bytes(iv_sz)
        debug_msg("iv_b       : {0}, {1}\n{2}".format(len(iv_b), iv_b.hex(), iv_b))

    # Select the plaintext string randomly.
    if string_idx == -1:
        idx = utils.rand_int(0, len(pt_strings) - 1)
    elif string_idx >= 0 and string_idx < len(pt_strings):
        idx = string_idx
    else:
        raise Exception("Invalid string index")
    pt_b64_b = pt_strings[idx]
    pt_b = utils.base64bytes2bytes(pt_b64_b)
    debug_msg("pt_b       : {0}, {1}\n{2}".format(len(pt_b), pt_b.hex(), pt_b))

    # Pad.
    pt_b = utils.pkcs7_pad(pt_b, blk_sz)
    debug_msg("pt_padded_b: {0}, {1}\n{2}".format(len(pt_b), pt_b.hex(), pt_b))

    # Encrypt.
    ct_b = utils.aes_encrypt(pt_b, key_b, mode = "CBC", iv = iv_b)

    return (ct_b, iv_b, idx)

def padding_oracle(ct_b):
    """Decrypts and unpads an oracle cyphertext, providing only info about unpad success."""

    if key_b is None:
        raise Exception("No key available for decrypting")

    # Decrypt and unpad.
    pad_ok = True
    pt_b = utils.aes_decrypt(ct_b, key_b, mode = "CBC", iv = iv_b)
    try:
        pt_b = utils.pkcs7_unpad(pt_b, blk_sz)
    except Exception:
        # Invalid padding
        pad_ok = False

    # Note no ciphertext returned, just padding validity info.
    return pad_ok

def break_block(c2, c1):
    """Breaks the ciphertext block 'c2', using previous block 'c1'."""

    # The strategy used is as described in:
    # http://robertheaton.com/2013/07/29/padding-oracle-attack/
    # Using same nomenclature for variables:
    #  + I2 is 'i2'
    #  + P2 is 'p2'
    #  + C2 is 'c2' and C1 is 'c1'.
    #  + C'1 (or C1') is 'c1p'

    # Intermediate value for block 'c2'.
    # When we have all 'blk_sz' bytes from 'i2', we
    # can derive the plaintext of 'c2' (which we'll
    # call 'p2'), by simply doing 'p2 = i2 XOR c1'.
    i2 = b''
    p2 = b''

    # Loop for each block byte, starting from last.
    for i in range(blk_sz):
        # PKCS#7 padding to force on the bit flipped plaintext,
        # and that we can know when got right because the oracle
        # will tell us the padding is good.
        pad = i + 1
        # The variable 'c1p' is the manipulated (bit flipped)
        # ciphertext block we use in order to cause the same bit
        # flipping on the resulting plaintext block.
        # The prefix is set constant "\x00" data up to and not
        # including the byte we're trying to guess. The suffix
        # is the intermediate data we already know XORed with the
        # current padding value so that on the same bytes of the
        # manipulated plaintext block, we get the requited pad byte
        # value.
        c1p_prefix = b'\x00' * (blk_sz - pad)
        c1p_suffix = bytes([val ^ pad for val in i2])

        debug_msg("    ----------------------------------------")
        debug_msg("    byte to break: {0}: i={1}, pad={2},\n    c1p_prefix: {3}, {4}\n    {5}\n    c1p_suffix: {6}, {7}\n    {8}"
                .format(blk_sz - pad, i, pad,
                    len(c1p_prefix), c1p_prefix.hex(), c1p_prefix,
                    len(c1p_suffix), c1p_suffix.hex(), c1p_suffix))
        debug_msg("    i2: {0}, {1}\n    {2}".format(len(i2), i2.hex(), i2))
        debug_msg("    p2: {0}, {1}\n    {2}".format(len(p2), p2.hex(), p2))

        # Loop for each intermediate byte value we're trying to guess.
        found = False
        for j in range(256):
            # This is the ciphertext block we're manipulating
            # in order to force the wanted padding in the plaintext
            # associated with ciphertext block 'c2'. The oracle
            # will tell us when we get it right by telling there's
            # no padding error. That will mean that 'j' is thee the
            # correct 'i2' intermediate byte we're looking for in
            # this loop.
            c1p_byte = bytes([j ^ pad])
            c1p = c1p_prefix + c1p_byte + c1p_suffix
            ct = c1p + c2
            debug_msg("      ----------------------------------------")
            debug_msg("      value to break: {0:02x}:\n      c1p: {1}, {2}\n      {3}"
                    .format(j, len(c1p), c1p.hex(), c1p))
            if padding_oracle(ct):
                debug_msg("        => Broken! Padding oracle said YES!")
                i2 = bytes([j]) + i2
                p2 = utils.xor(i2, c1[-len(i2):])
                found = True
                break

        # Sanity check.
        if not found:
            raise Exception("Unexpected: Could not find intermediate byte for 'i2'")

    # All bytes known. The plaintext 'p2' was already built
    # within the inner cycle above.
    debug_msg("    ----------------------------------------")
    debug_msg("    FINAL p2: {0}, {1}\n    {2}".format(len(p2), p2.hex(), p2))
    debug_msg("    ----------------------------------------")
    return p2

def execute_cbc_padding_oracle_attack(string_idx):
    """Perform a CBC padding oracle attack."""

    # The strategy used is as described in:
    # http://robertheaton.com/2013/07/29/padding-oracle-attack/
    #
    # It is basically a brute force CBC bit flipping attack
    # (see Challenge 16) where the only way of knowing that the
    # bit flipped plaintext bytes have the value we want is to
    # exploit the info given by the padding oracle regarding the
    # padding validity if the resulting bit flipped plaintext.
    #
    # Additional references:
    #  + https://en.wikipedia.org/wiki/Padding_oracle_attack
    #  + https://grymoire.wordpress.com/2014/12/05/cbc-padding-oracle-attacks-simplified-key-concepts-and-pitfalls/
    #  + https://blog.skullsecurity.org/2013/padding-oracle-attacks-in-depth

    # Encrypt.
    debug_msg("----------------------------------------")
    (ct_b, iv_b, idx) = encryption_oracle(string_idx)

    # Break the encryption, block by block
    pt_b = b''
    ct_blks = [ct_b[n:(n + blk_sz)] for n in range(0, len(ct_b), blk_sz)]
    debug_msg("----------------------------------------")
    debug_msg("ct_blks: {0}".format(len(ct_blks)))
    for i in range(len(ct_blks)):
        # The block to break.
        c2_b = ct_blks[i]
        # The previous ciphertext block (IV for 1st block).
        c1_b = ct_blks[i - 1] if i > 0 else iv_b
        debug_msg("  ----------------------------------------")
        debug_msg("  ct_blk: {0} ({1}/{2})".format(i, i + 1, len(ct_blks)))
        pt_b += break_block(c2_b, c1_b)
        debug_msg("  pt_b: {0}, {1}\n  {2}".format(len(pt_b), pt_b.hex(), pt_b))

    debug_msg("----------------------------------------")
    debug_msg("pt_padded: {0}, {1}\n{2}".format(len(pt_b), pt_b.hex(), pt_b))
    pt_b = utils.pkcs7_unpad(pt_b, blk_sz)
    debug_msg("pt       : {0}, {1}\n{2}".format(len(pt_b), pt_b.hex(), pt_b))
    debug_msg("----------------------------------------")

    return (pt_b, idx)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        for i in range(len(pt_strings)):
            (pt_attacked, idx) = execute_cbc_padding_oracle_attack(i)
            pt_expected = utils.base64bytes2bytes(pt_strings[idx])
            print("{0}: idx      = [{1}]".format(me, idx))
            print("{0}: attacked = [{1}]".format(me, utils.bytes2rawstr(pt_attacked)))
            print("{0}: expected = [{1}]".format(me, utils.bytes2rawstr(pt_expected)))
            if pt_attacked != pt_expected:
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


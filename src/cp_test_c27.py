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

"""Cryptopals Challenges: Test Challenge 27: Recover the key from CBC with IV=Key."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 27: Recover the key from CBC with IV=Key"

# Random constant key and IV used in encryption oracle.
key_b = None

# An encryption function we can exercise (call), but of
# which we are not supposed to know the implementation
# details.
# Has the particularity of using IV = Key.
def encrypt(pt_b):
    """Encryption Routine: Challenge 27."""

    # Uses a key and block size of 16 bytes.
    # Uses an IV equal to the Key.
    # Uses AES-CBC for encrypting.

    global key_b
    blk_sz = 16

    # Generate random key and also use it as the IV.
    if key_b is None:
        key_sz = blk_sz
        key_b = utils.rand_bytes(key_sz)
        iv_b = key_b

    # Pad and Encrypt.
    pt_b = utils.pkcs7_pad(pt_b, blk_sz)
    ct_b = utils.aes_encrypt(pt_b, key_b, mode = "CBC", iv = iv_b)

    return (ct_b, key_b)

def is_only_ascii(pt_b):
    """Confirms if a plaintext contains only ASCII chars."""
    if any([ch > 127 for ch in pt_b]):
        return False
    return True

class DecryptException(Exception):
    """Used when 'decrypt()' finds and error in the plaintext."""
    pass

def decrypt(ct_b):
    """Decrypts and unpads a message encrypted by 'encrypt()'."""

    # Does the reverse of decrypt.
    # Does not return any ciphertext in normal case, as it's
    # some kind of receive function on the receiver side.
    # However, if the decrypted plaintext is not valid (i.e.,
    # contains non-ASCII chars), an exception is raised, with
    # the invalid plaintext being part of the exception.

    global key_b
    blk_sz = 16

    if key_b is None:
        raise Exception("No key/IV available for decrypting")
    iv_b = key_b

    # Decrypt and unpad.
    pt_b = utils.aes_decrypt(ct_b, key_b, mode = "CBC", iv = iv_b)
    pt_b = utils.pkcs7_unpad(pt_b, blk_sz)
    ok = is_only_ascii(pt_b)

    # Validate the plaintext.
    if not ok:
        raise DecryptException(pt_b)

def execute_break_cbc_key_equal_to_iv():
    """Breaks CBC when it uses the key as IV."""

    blk_sz = 16

    # There's an encryption oracle that can be exercised.
    # There's a decrypt routine that can be used and that
    # raises an exception when the decrypted plaintext is
    # not valid (has non-ASCII chars), in which case, the
    # invalid plaintext is given along with the exception.

    # In this challenge, the IV used by the encryption routine is the IV,
    # so by breaking the IV, we get the key.
    #
    # Let's call 'I(n)' (intermediate text block n) the ECB decrypted content
    # of 'C(n)' (ciphertext block n), which is then XORed (^) with 'C(n-1)' to
    # give 'P(n)' (plaintext block n).
    # For every (n > 1), we have:
    #  'P(n) = C(n-1) ^ I(n)' <=> 'C(n-1) = P(n) ^ I(n)'.
    # Note that 'C(0) = IV' and in this case 'C(0) = IV = Key'.
    # If we can encrypt 3 blocks, decrypt them and manipulate the 3 ciphertexts,
    # then wee have:
    #  'Key  = P(1) ^ I(1)'
    #  'C(1) = P(2) ^ I(2)'
    #  'C(2) = P(3) ^ I(3)' <=> 'I(3) = P(3) ^ C(2)
    # Now, if 'C(1) = C(3)', we will have 'I(1) = I(3)', because the ECB
    # decryption done inside CBC for the same ciphertext block will result in
    # the same intermediate text block.
    # This way, we have:
    #  'Key = P(1) ^ I(1) = P(1) ^ P(3) ^ C(2)'
    # So, for getting the 'Key = IV', all we need is to make 'C(1)' equal to
    # 'C(3)' and then calculate the XOR of 'P(1)', 'P(3)' and 'C(2)'.
    #
    # All the manipulations done above are possible to do with the elements we
    # have in this challenge. Additionally, if we set 'C(2) = 0', then all what
    # is required to recover the key is to XOR 'P(1)' with 'P(3)'. However, we
    # still need to get our hands on the plaintext blocks. That only happens if
    # we select our ciphertext blocks in a way that at least one plaintext char.
    # resulting from the decryption of the 3 blocks, is non-ASCII. Using
    # ciphertext blocks that are not real ones resulting from encrypting ASCII
    # text is a good way of achieving that. By setting 'C(2) = 0' as described
    # above, there's already a high chance of getting non-ASCII plaintext, so
    # that's the natural try to make first.

    # The plaintext test blocks (note size of 'blk_sz').
    # We need in fact at least 4 blocks, because otherwise by changing
    # ciphertext block 3, we will mess with the last ciphertext block (padding),
    # which in turn results in padding error exception. To avoid that a reach
    # the actual plaintext validation exception, we need an extra block to avoid
    # corrupting the padding.
    pn_b = [b'This is block 1;', b'This is block 2;', b'This is block 3;', b'This is block 4;']
    pt_b = b''.join(pn_b)

    # Request the encryption.
    (ct_b, key_real_b) = encrypt(pt_b)

    # Try feeding the decrypt with tampered ciphertexts and get the exception
    # that allows access to the plaintexts.
    key_broken_b = None
    try:
        for i in range(256):
            # Tamper the ciphertext blocks, the way described above.
            c1_b = ct_b[:blk_sz]
            c2_b = bytes([i]) * blk_sz
            ct_attack_b = c1_b + c2_b + c1_b + ct_b[(3 * blk_sz):]
            decrypt(ct_attack_b)
    except DecryptException as e:
        # This is what we expect to get access to the plaintext blocks.
        pt_attack_b = e.args[0]
        p1_b = pt_attack_b[0:blk_sz]
        p3_b = pt_attack_b[(2 * blk_sz):(3 * blk_sz)]
        key_broken_b = utils.xor(utils.xor(p1_b, p3_b), c2_b)
    else:
        # Oops, the decrypted content has only ASCII chars, so no
        # plaintext blocks available.
        pass

    return (key_real_b, key_broken_b)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        (key_real_b, key_broken_b) = execute_break_cbc_key_equal_to_iv()
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: broken   = [{1}]".format(me, key_broken_b.hex()))
        print("{0}: real     = [{1}]".format(me, key_real_b.hex()))
        if key_broken_b != key_real_b:
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


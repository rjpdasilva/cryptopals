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

"""Cryptopals Challenges: Test Challenge 14: Byte-at-a-time ECB decryption (Harder)."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 14: Byte-at-a-time ECB decryption (Harder)"

# Random constant key used in encryption oracle.
key_b = None
# Random constant prefix used in encryption oracle.
prefix_b = None
# Prefix is to be used by the oracle.
use_prefix = True

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
def encryption_oracle(pt_b):
    """Encryption Oracle: Challenge 14."""

    # Uses a key and block size of 16 bytes.
    # Appends constant data ('suffix_b') to the
    # plaintext.
    # Prepends random data {'prefix_b') to the
    # plaintext.
    # Uses AES-ECB for encrypting.

    # Base64 encoded byte array with suffix used by the
    # encryption oracle.
    suffix_b64_b = b'''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''

    global key_b
    global prefix_b
    global use_prefix

    blk_sz = 16

    # Generate a random key.
    key_sz = blk_sz
    if key_b is None:
        key_b = utils.rand_bytes(key_sz)

    # Generate a random prefix with (somewhat) random length.
    if prefix_b is None:
        if use_prefix:
            prefix_sz = utils.rand_int(0, 16 * 4)
        else:
            prefix_sz = 0
        prefix_b = utils.rand_bytes(prefix_sz)

    # Build the plaintext (pt).
    suffix_b = utils.base64bytes2bytes(suffix_b64_b)
    pt_b = prefix_b + pt_b + suffix_b
    pt_b = utils.pkcs7_pad(pt_b, blk_sz)

    # Encrypt.
    ct_b = utils.aes_encrypt(pt_b, key_b, mode = "ECB")

    return ct_b

def find_block_size(oracle):
    """Determines the block size used by the given oracle."""

    # Check the ciphertext size given by the oracle
    # when no additional data is fed into it.
    # Then, keep feeding an additional byte till the
    # returned cipher text size changes.
    # Since the oracle will be padding the returned
    # ciphertext to a multiple of the block size, once
    # the ciphertext size increases, the difference
    # will be the block size.

    blk_sz = 0
    pt_b = b''
    sz = len(oracle(pt_b))
    sz_init = sz
    while sz == sz_init:
        pt_b += bytes([0])
        sz = len(oracle(pt_b))
    if sz > sz_init:
        blk_sz = (sz - sz_init)
    else:
        # Unexpected error.
        raise Exception("Unable to find block size")

    return blk_sz

def find_prefix_size(oracle, blk_sz):
    """Finds the oracle's encryption prefix size."""

    # The prefix size can be split into number of full blocks
    # plus the number of bytes in the last prefix block.
    #
    # To find the number of full blocks, we can compare the
    # ciphertext obtained from the oracle with no data against
    # the one returned with a single byte feed. The prefix number
    # of full blocks will be the number of 1st blocks that are
    # consecutively equal in both ciphertexts obtained, because the
    # single byte fed will change the cyphertext in the 1st block
    # that is not fully filled with prefix data.
    #
    # Then to find out the remaining number of prefix bytes, we
    # have to keep injecting increasing extra bytes before 2 equal
    # plaintext blocks and check when we get equivalent 2 equal
    # ciphertext blocks, which will mean we have "aligned" our
    # 2 plaintext blocks in a 'blk_sz' boundary by injecting N
    # (N < 'blk_sz') bytes after the remaining prefix bytes, which
    # in turn means the remaining number of prefix bytes is then
    # (blk_sz' - N).

    # Determine how many full blocks does the prefix use.
    ct1_b = oracle(b'')
    ct1_blks = [ct1_b[n:(n + blk_sz)] for n in range(0, len(ct1_b), blk_sz)]
    ct2_b = oracle(b'0')
    ct2_blks = [ct2_b[n:(n + blk_sz)] for n in range(0, len(ct2_b), blk_sz)]
    prefix_blks = -1
    for n in range(len(ct1_blks)):
        if ct1_blks[n] != ct2_blks[n]:
            prefix_blks = n
            break
    if prefix_blks == -1:
        raise Exception("Cannot find number of prefix blocks")
    prefix_sz1 = prefix_blks * blk_sz

    # Determine how many bytes the prefix has in its last non-full
    # block.
    prefix_bytes = -1
    pt_main_b = b'0' * blk_sz * 2
    for i in range(blk_sz):
        pt_align_b = b'1' * i
        pt_b = pt_align_b + pt_main_b
        ct_b = oracle(pt_b)
        ct_blks = [ct_b[n:(n + blk_sz)] for n in range(prefix_sz1, len(ct_b), blk_sz)]
        for n in range(len(ct_blks) - 1):
            if ct_blks[n] == ct_blks[n + 1]:
                prefix_bytes = blk_sz - i
                break
        if prefix_bytes != -1:
            break
    if prefix_bytes == -1:
        raise Exception("Cannot find number of prefix bytes")
    if prefix_bytes == blk_sz:
        prefix_bytes = 0

    prefix_sz = prefix_sz1 + prefix_bytes

    return prefix_sz

def confirm_ecb(oracle, blk_sz, prefix_sz):
    """Confirm the given oracle is using ECB, provided the block size used by it."""

    # Some initial feeding is required for making sure we
    # start aligned on a 'blk_sz' boundary, i.e, feed some
    # initial data to pad the oracle's prefix for block
    # aligning it.
    prefix_pad_len = blk_sz - (prefix_sz % blk_sz)
    prefix_pad_b = b'X' * prefix_pad_len
    prefix_end = prefix_sz + prefix_pad_len

    # Feeding 2 equal blocks of 'blk_sz' to the oracle
    # shall also produce 2 equal ciphertext blocks in
    # the same positions.

    pt_b = prefix_pad_b + bytes([0] * blk_sz * 2)
    ct_b = oracle(pt_b)
    if ct_b[prefix_end:(prefix_end + blk_sz)] != ct_b[(prefix_end + blk_sz):(prefix_end + 2 * blk_sz)]:
        raise Exception("Encryption is not ECB")

def find_next_byte(oracle, blk_sz, prefix_sz, known):
    """Find the next byte of the oracle's secret."""

    # Make sure we feed the oracle in a way that the
    # currently unknown byte ends up in the last byte
    # of the block (which we'll need to know). The value
    # of the extra bytes required to feed is not important,
    # but should remain constant throughout the process.
    #
    # Get the resulting block's ciphertext for later use.
    #
    # Then, instead of the block's last byte being the
    # currently unknown byte, replace it with all possible
    # last byte values (0~255) and build a dictionary
    # mapping each resulting ciphertext block to the last
    # byte value.
    #
    # One of the entries will match the ciphertext block
    # saved previously and the mapped last byte is in fact
    # the currently unknown byte.

    # Some initial feeding is required for making sure we
    # start aligned on a 'blk_sz' boundary, i.e, feed some
    # initial data to pad the oracle's prefix for block
    # aligning it.
    prefix_pad_len = blk_sz - (prefix_sz % blk_sz)
    prefix_pad_b = b'X' * prefix_pad_len

    # Determine the block where the currently unknown byte is.
    known_len = len(known) + prefix_sz + prefix_pad_len
    cur_blk = known_len // blk_sz
    blk_pos = cur_blk * blk_sz
    # Determine the position of the unknown byte in the block.
    cur_pos = known_len % blk_sz

    # Determine number of bytes required to be fed to the
    # oracle so that the currently unknown byte is placed in
    # the block's last byte.
    num_feed = blk_sz - cur_pos - 1
    pt_b = prefix_pad_b + b'\x00' * num_feed

    debug_msg("----------")
    debug_msg("kl={0}, cb={1}, bp={2}, cp={3}, nf={4}, pt_b={5}"
            .format(known_len, cur_blk, blk_pos, cur_pos, num_feed, pt_b.hex()))

    # Get the resulting cyphertext (only the block that matters) and store it.
    ct_res_b = oracle(pt_b)[(blk_pos):(blk_pos + blk_sz)]
    debug_msg("ct_res_b={0}".format(ct_res_b.hex()))

    # Build the dictionary with the map of every possible last byte to
    # resulting cyphertext block.
    dict = {}
    for i in range(256):
        pt_dict_b = pt_b + known + bytes([i])
        debug_msg("  -----")
        debug_msg("  {0:3d} {1}".format(i, pt_dict_b.hex()))
        ct_dict_b = oracle(pt_dict_b)[(blk_pos):(blk_pos + blk_sz)]
        debug_msg("  {0:3d} {1}".format(i, ct_dict_b.hex()))
        dict[ct_dict_b] = i

    # Check for a match of 'ct_res_b' in the dictionary.
    if ct_res_b in dict:
        unknown_byte = bytes([dict[ct_res_b]])
        debug_msg("ub={0}=\"{1}\"".format(unknown_byte.hex(), chr(ord(unknown_byte))))
    else:
        debug_msg("ub=<None>")
        unknown_byte = None

    return unknown_byte

def execute_break_ecb(oracle, with_prefix):
    """Break AES-ECB encrypted msg in oracle's returned ciphertext."""

    global use_prefix
    use_prefix = with_prefix

    # Find the block size.
    blk_sz = find_block_size(oracle)

    # Find the prefix size.
    prefix_sz = find_prefix_size(oracle, blk_sz)

    # Confirm ECB mode.
    confirm_ecb(oracle, blk_sz, prefix_sz)

    # Find the secret.
    suffix_b = b''
    while True:
        one_b = find_next_byte(oracle, blk_sz, prefix_sz, suffix_b)
        if one_b is None:
            break
        suffix_b += one_b

    # Convert to raw string.
    suffix_s = utils.bytes2rawstr(suffix_b)

    return (suffix_s, blk_sz, prefix_sz)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        (out_res, blk_sz, prefix_sz) = execute_break_ecb(encryption_oracle, True)
        out_file = 'data/data_c12_out.txt'
        out_res_ok = utils.file_get(out_file)
        # Add one padding byte.
        out_res_ok += "\x01"
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: blk_sz   = [{1}]".format(me, blk_sz))
        print("{0}: pref_sz  = [{1}]".format(me, prefix_sz))
        print("{0}: result   = [<see below>]".format(me))
        print("{0}: ".format(me) + "-" * 60)
        print(out_res)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: expected = [<see below>]".format(me))
        print("{0}: ".format(me) + "-" * 60)
        print(out_res_ok)
        if out_res != out_res_ok:
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


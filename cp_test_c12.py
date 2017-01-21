"""Cryptopals Challenges: Test Challenge 12: Byte-at-a-time ECB decryption (Simple)."""

import sys
import cp_aux_utils as utils
import cp_test_c11 as c11

title = "Challenge 12: Byte-at-a-time ECB decryption (Simple)"

# Random constant key used in encryption oracle.
key = None

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
    """Encryption Oracle: Challenge 12."""

    # Uses a key and block size of 16 bytes.
    # Appends constant data ('suffix_b') to the
    # plaintext
    # Uses AES-ECB for encrypting.

    # Base64 encoded byte array with suffix used by the
    # encryption oracle.
    suffix_b64_b = b'''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''

    global key
    blk_sz = 16

    # Generate a random key.
    key_sz = blk_sz
    if key is None:
        key = utils.rand_bytes(key_sz)

    # Build the plaintext (pt).
    suffix_b = utils.base64bytes2bytes(suffix_b64_b)
    pt_b = pt_b + suffix_b
    pt_b = utils.pkcs7_pad(pt_b, blk_sz)

    # Encrypt.
    ct_b = utils.aes_encrypt(pt_b, key, mode = "ECB")

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

def confirm_ecb(oracle, blk_sz):
    """Confirm the given oracle is using ECB, provided the block size used by it."""

    # Feeding 2 equal blocks of 'blk_sz' to the oracle
    # shall also produce 2 equal ciphertext blocks in
    # the same positions.

    pt_b = bytes([0] * blk_sz * 2)
    ct_b = oracle(pt_b)
    if ct_b[0:blk_sz] != ct_b[blk_sz:(2 * blk_sz)]:
        raise Exception("Encryption is not ECB")

def find_next_byte(oracle, blk_sz, known):
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

    # Determine the block where the currently unknown byte is.
    known_len = len(known)
    cur_blk = known_len // blk_sz
    blk_pos = cur_blk * blk_sz
    # Determine the position of the unknown byte in the block.
    cur_pos = known_len % blk_sz

    # Determine number of bytes required to be fed to the
    # oracle so that the currently unknown byte is placed in
    # the block's last byte.
    num_feed = blk_sz - cur_pos - 1
    pt_b = b'\x00' * num_feed

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


def execute_break_ecb(oracle):
    """Break AES-ECB encrypted msg in oracle's returned ciphertext."""

    # Find the block size.
    blk_sz = find_block_size(oracle)

    # Confirm ECB mode.
    confirm_ecb(oracle, blk_sz)

    # Find the secret.
    suffix_b = b''
    while True:
        one_b = find_next_byte(oracle, blk_sz, suffix_b)
        if one_b is None:
            break
        suffix_b += one_b

    # Convert to raw string.
    suffix_s = utils.bytes2rawstr(suffix_b)

    return suffix_s

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        out_res = execute_break_ecb(encryption_oracle)
        out_file = 'data_c12_out.txt'
        out_res_ok = utils.file_get(out_file)
        # Add one padding byte.
        out_res_ok += "\x01"
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
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


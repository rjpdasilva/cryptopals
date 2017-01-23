"""Cryptopals Challenges: Test Challenge 14: Byte-at-a-time ECB decryption (Harder)."""

import sys
import cp_aux_utils as utils
import cp_test_c12 as c12

title = "Challenge 14: Byte-at-a-time ECB decryption (Harder)"

# Random constant key used in encryption oracle.
key_b = None
# Random constant prefix used in encryption oracle.
prefix_b = None

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

    # This is basically the same encryption oracle as in
    # Challenge 12, with the extra of appending some bytes
    # before the plaintext.

    global prefix_b

    # Generate a random prefix with (somewhat) random length.
    if prefix_b is None:
        prefix_sz = utils.rand_int(0, 16 * 4)
        prefix_b = utils.rand_bytes(prefix_sz)

    # Build the plaintext (pt).
    pt_b = prefix_b + pt_b

    # Encrypt using Challenge 12 oracle.
    ct_b = c12.encryption_oracle(pt_b)

    return ct_b

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

def execute_break_ecb(oracle):
    """Break AES-ECB encrypted msg in oracle's returned ciphertext."""

    # Find the block size.
    blk_sz = c12.find_block_size(oracle)

    # Find the prefix size.
    # This is also confirming the encryption uses ECB.
    prefix_sz = find_prefix_size(oracle, blk_sz)

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
        (out_res, blk_sz, prefix_sz) = execute_break_ecb(encryption_oracle)
        out_file = 'data_c12_out.txt'
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


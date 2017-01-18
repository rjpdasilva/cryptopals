"""Cryptopals Challenges: Test Challenge 06: Break repeating-key XOR."""

import sys
import cp_aux_utils as utils
import cp_test_c02 as c2
import cp_test_c03 as c3

title = "Challenge 06: Break repeating-key XOR"

# Debug flag.
debug = 0

def debug_msg(*args, **kwargs):
    """Extra debug messages."""
    if not debug:
        return
    print(*args, **kwargs)

def get_ciphertext(file_name):
    """Get the ciphertext from a base64 encoded file."""

    # Get the file data.
    text_b64 = utils.file_get(file_name)

    # Convert to byte array.
    text_b64_b = utils.rawstr2bytes(text_b64)

    # Base64 decode it. Results in the cyphertext (ct).
    ct = utils.base64bytes2bytes(text_b64_b)

    return ct


def break_key_size(ct, sz_min, sz_max, nb):
    """List probable key sizes and normalized distances, sorted by distance."""

    def distance_key(dist):
        """Key for sorting (key_size, hamming_distance) tuples by distance."""

        # Use the Hamming distance as key  for sorting.
        return dist[1]

    def dist_calc(ct, key_size, nblks):
        """Calculate average Hamming distance between the 1st 'nblks' of 'key_size' size."""

        # Get the ciphertext 1st 'nblks' of 'key_size' size.
        blocks = [ct[n:n + key_size] for n in range(0, nblks * key_size, key_size)]

        # Calculate the distance between all blocks combinations (non-repeated).
        dist = []
        for i in range(0, nblks - 1):
            for j in range(i + 1, nblks):
                d = utils.hamming_dist(blocks[i], blocks[j])
                dist.append(d)

        # Average the distances between blocks.
        d_avg = sum(dist) / float(len(dist))

        # Normalize the distance to the key size.
        d_norm = d_avg / float(key_size)

        return d_norm

    # "Let KEYSIZE be the guessed length of the key; try values from 2 to
    #  (say) 40."
    # "For each KEYSIZE, take the first KEYSIZE worth of bytes, and the
    #  second KEYSIZE worth of bytes, and find the edit distance between
    #  them. Normalize this result by dividing by KEYSIZE."
    # "Or take 4 KEYSIZE blocks instead of 2 and average the distances."
    # "The KEYSIZE with the smallest normalized edit distance is probably
    #  the key."

    # KEYSIZE range set via 'sz_min' and 'sz_max'.
    # The number of 1st blocks to use is determined by 'nb'.

    # Do the calculations and return a sorted list of key sizes and distances.
    sz_and_dist = sorted([(key_size, dist_calc(ct, key_size, nb))
                            for key_size in range(sz_min, sz_max + 1)], key = distance_key)
    return sz_and_dist

def break_key(ct, key_size):
    """Break the key assuming its size, providing a normalized score."""

    len_ct = len(ct)

    # "Now that you probably know the KEYSIZE: break the ciphertext
    #  into blocks of KEYSIZE length."

    nblks = len_ct // key_size
    len_ct_align = nblks * key_size
    ct_align = ct[:len_ct_align]
    ct_blks = [ct_align[n:n + key_size] for n in range(0, len_ct_align, key_size)]

    # "Now transpose the blocks: make a block that is the first
    #  byte of every block, and a block that is the second byte
    #  of every block, and so on."

    ct_blks_tr = [b"".join(bytes([ct_blks[block_idx][byte_idx]])
                            for block_idx in range(nblks))
                                for byte_idx in range(key_size)]
    # "Solve each block as if it was single-character XOR. You
    #  already have code to do this."
    # "For each block, the single-byte XOR key that produces
    #  the best looking histogram is the repeating-key XOR key
    #  byte for that block.
    #  Put them together and you have the key."

    # Reusing challenge 3 functionality.
    fn = c3.execute_break_single_byte_xor
    ct_blks_tr_k = [fn(ct_blks_tr[n], False, False) for n in range(len(ct_blks_tr))]

    # Build the key by concatenating each single-bytes xor.
    x = ct_blks_tr_k
    key_data = b''.join(bytes([x[n][0]]) for n in range(len(x)))

    # Normalize each single xor key score to the number of bytes it decrypts.
    x = ct_blks_tr_k
    ct_blks_tr_k_norm = [(x[n][0], x[n][1], (x[n][2] / float(nblks))) for n in range(len(x))]

    # Get the average score of all the single xor normalized scores.
    key_score = (sum(blk[2] for blk in ct_blks_tr_k_norm) / float(len(ct_blks_tr_k_norm)))

    return (key_size, key_score, key_data)

def execute_break_repeating_key_xor(file_name):
    """Break file's data encrypted with repeating-key xor and base64 encoded."""

    def score_key(dist):
        """Key for sorting (key_size, key_score, key) tuples by key_score."""

        # Use the Hamming distance as key  for sorting.
        return dist[1]

    ########################################
    # Build the ciphertext.
    ########################################

    ct = get_ciphertext(file_name)

    ########################################
    # Determine the probable key sizes.
    ########################################

    # List of (key sizes, normalized distance) sorted by increasing
    # normalized edit distance.
    #  Try key sizes from 'sz_min' to 'sz_max'.
    #  Use 'nblks' blocks of cyphertext for calculations.
    sz_min = 2
    sz_max = 40
    nblks = 4
    sz_and_dist = break_key_size(ct, sz_min, sz_max, nblks)

    # Debug.
    debug_msg("")
    debug_msg("-" * 40)
    debug_msg("Most probable key sizes, using:")
    debug_msg("  + key_size   = [{0} ~ {1}]".format(sz_min, sz_max))
    debug_msg("  + num_blocks = [{0}]".format(nblks))
    debug_msg("-" * 40)
    debug_msg("(size, average distance)")
    debug_msg("-" * 40)
    for d in sz_and_dist:
        debug_msg("({0:4d}, {1:.6f})".format(d[0], d[1]))
    debug_msg("-" * 40)

    ########################################
    # Determine the probable keys.
    ########################################

    # "You could proceed perhaps with the smallest 2-3 KEYSIZE values."

    # Number of key sizes to use with the lowest normalized distances.
    num_sz_used = 1

    # For each key size, break the key and get a score.
    # This builds up a list of 'num_sz_used' (key_size, key_score, key) tuples,
    # sorted by decreasing score.
    key_scores = sorted([break_key(ct, sz_and_dist[i][0])
                            for i in range(num_sz_used)], key = score_key, reverse = True)

    # Debug.
    debug_msg("")
    debug_msg("-" * 40)
    debug_msg("Most probable keys, using:")
    debug_msg("  + best_sizes = [{0}]".format(num_sz_used))
    debug_msg("-" * 40)
    debug_msg("(key_size, key_score, key)")
    debug_msg("-" * 40)
    for ks in key_scores:
        debug_msg("({0:8d}, {1:.6f}), {2}".format(ks[0], ks[1], ks[2]))
    debug_msg("-" * 40)

    ########################################
    # Decrypt the ciphertext.
    ########################################

    key = key_scores[0][2]
    # Reuse challenge 2 functionality.
    plaintext = c2.execute_xor(ct, key, in_fmt = "bytes", out_fmt = "raw")

    # Debug.
    debug_msg("")
    debug_msg("-" * 40)
    debug_msg("Plaitext with best key: ")
    debug_msg("  key =", key)
    debug_msg("-" * 40)
    debug_msg(plaintext)
    debug_msg("-" * 40)

    return (utils.bytes2rawstr(key), plaintext)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_file = 'data_c6.txt'
        out_res = execute_break_repeating_key_xor(in_file)
        out_file = 'data_c6_out.txt'
        out_file_data = utils.file_get(out_file)
        out_res_ok = ("Terminator X: Bring the noise", out_file_data)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_file  = [{1}]".format(me, in_file))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: result   = [(key=\"{1}\", text=<see below>)]".format(me, out_res[0]))
        print("{0}: ".format(me) + "-" * 60)
        print(out_res[1])
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: expected = [(key=\"{1}\", text=<see below>)]".format(me, out_res_ok[0]))
        print("{0}: ".format(me) + "-" * 60)
        print(out_res_ok[1])
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


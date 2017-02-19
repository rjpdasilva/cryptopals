"""Cryptopals Challenges: Test Challenge 19: Break fixed-nonce CTR mode using substitution."""

import sys
import utils.cp_aux_utils as utils
import cp_test_c06 as c6

title = "Challenge 19: Break fixed-nonce CTR mode using substitution"

# Random constant key used in challenge.
key_b = None

# Fixed constant block size used in challenge.
blk_sz = 16

# Fixed constant nonce used in challenge.
nonce = 0

# Debug flag.
debug = 0

# Debug messages.
def debug_msg(*args, **kwargs):
    """Extra debug messages."""
    if not debug:
        return
    print(*args, **kwargs)

# List debug helper.
def dump_list(l, name = "List"):
    """Dumps a list contents."""
    debug_msg("-" * 80)
    debug_msg("{0}:".format(name))
    debug_msg("-" * 80)
    debug_msg("len  = {0}\ndata =".format(len(l)))
    for i in range(len(l)):
        debug_msg("{0:4d}, {1:4d}, {2}".format(i, len(l[i]), l[i]))

def ctr_encrypt(pt_b):
    """Start a new CTR encryption for the give plaintext byte arrays."""

    global key_b

    # Generate a random key.
    aes_key_sz = blk_sz
    if key_b is None:
        key_b = utils.rand_bytes(aes_key_sz)

    # Get a AES-CTR object to work with for encryption.
    aes_ctr = utils.AesCtr(key_b, nonce)
    ct_b = aes_ctr.encrypt(pt_b)

    return ct_b

def ctr_encrypt_string_list(str_list):
    """CTR encrypt the strings in the give string list."""

    # Work with byte arrays.
    dump_list(str_list, "Base64 Encoded Plaintext Strings")
    pt_b64_b_list = [utils.rawstr2bytes(s) for s in str_list]
    dump_list(pt_b64_b_list, "Base64 Encoded Plaintext Byte Strings")
    pt_b_list = [utils.base64bytes2bytes(pt_b64_b) for pt_b64_b in pt_b64_b_list]
    dump_list(pt_b_list, "Plaintext Byte Strings")

    # Encrypt.
    ct_b_list = [ctr_encrypt(pt_b) for pt_b in pt_b_list]
    dump_list(ct_b_list, "Ciphertext Byte Strings")

    return (ct_b_list, pt_b_list)

def ctr_decrypt_string_list(ct_b_list, key):
    """CTR decrypt the byte arrays in the given list using the provided key."""

    # Key is an array of bytes. When value is None, means we haven't found
    # the key at that position yet.
    key_b = bytes([key[i] if key[i] != None else 0 for i in range(len(key))])

    # Decrypt (just a XOR).
    pt_b_list = [utils.xor(ct_b, key_b) for ct_b in ct_b_list]

    # Create a plaintext filtered list where the byte positions for which we
    # have not yet determined the respective key byte are marked with '*'.
    pt_b_filt_list = []
    for i in range(len(pt_b_list)):
        max_j = min(len(key), len(pt_b_list[i]))
        pt_b = b''.join(bytes([pt_b_list[i][j]]) if key[j] != None else b'*'
                            for j in range(max_j))
        pt_b_filt_list += [pt_b]

    return pt_b_filt_list

def guess_key_1(ct_b_list, key_sz):
    """First method tried for guessing the key."""

    # This method's strategy was based on brute forcing each key position.
    # For each key byte, all values are tried. For each value we assess the
    # resulting decrypted byte at the same position for in all ciphertexts
    # we have (that have text in that position - some are shorter), by
    # building a string with all those bytes and score it for English (letter
    # frequency, etc.). For example for the 1st key byte, we try all 256
    # values and for each value we take all the 1st decrypted bytes on all
    # ciphertexts, build a string with them and score it. The key byte value
    # giving the highest score is assumed to be the correct key byte.
    # This is much like "Challenge 6: Break repeating-key XOR".

    def score_decr(decr):
        """To score an english string."""
        return utils.score_english_string(decr) / float(len(decr))

    debug_msg("-" * 80)
    debug_msg("key_sz =", key_sz)
    key_b = b''
    # Determine each key byte in turn.
    # The maximum key size is the longest ciphertext.
    for k_pos in range(key_sz):
        # For each possible key byte value, get the decrypted ciphertext
        # byte at the current 'k_pos' position of all ciphertexts and
        # build a string with it. The result is a list of 256 strings.
        pti_list = [b''.join(bytes([ct_b_list[ct_b_pos][k_pos] ^ k_val])
                                if k_pos < len(ct_b_list[ct_b_pos]) else b''
                                    for ct_b_pos in range(len(ct_b_list)))
                                        for k_val in range(256)]
        dump_list(pti_list, "pti_list[k_pos={0}]".format(k_pos))

        # Score each string for English.
        pti_list_scored = [(i, score_decr(pti_list[i])) for i in range(len(pti_list))]
        dump_list(pti_list_scored, "pti_list_scored[k_pos={0}]".format(k_pos))

        # Use a threshold on the number of ciphertexts to use.
        # The higher number, the higher probability of getting a single high score
        # and "guess" the key. When lesser ciphertexts are involved, we start
        # getting lots of equal high scores, meaning the respective key byte can
        # vary a lot, so leave it for other methods or manually guessing.
        if len(pti_list[0]) < 12:
            break

        # The string with highest score gives is the key value!
        pti_high_score = max(pti_list_scored, key = (lambda score: score[1]))
        debug_msg("pti_high_score[k_pos={0}]: {1:02x} ({2})"
                    .format(k_pos, pti_high_score[0], pti_high_score[1]))
        key_b += bytes([pti_high_score[0]])

    debug_msg("-" * 80)
    debug_msg("key_b: {0}, {1}\n           {2}".format(len(key_b), key_b, key_b.hex()))

    # Convert key from byte array to list of bytes with None set in the positions
    # for which we do not have determined a value.
    key = list(key_b) + [None] * (key_sz - len(key_b))
    return key

def guess_key_2(ct_b_list, key_sz):
    """Second method tried for guessing the key."""

    def is_xored_with_space(val):
        """Determines if a byte value (XOR of 2 ct) could be a XOR with space char."""
        return (chr(val).isalpha())

    # This is a "crib-dragging" method using the space as a crib, since
    # a space XORed with any letter will give the same letter with its
    # case changed.
    # This method is thoroughly described in the web. Search for "crib
    # dragging" and "Many time pad attacks".
    # Example:
    #  http://adamsblog.aperturelabs.com/2013/05/back-to-skule-one-pad-two-pad-me-pad.html

    # Start with a fully unknown and zero scored key.
    key = [None] * key_sz
    key_score = [0] * key_sz

    # For each key position, how many ciphertext strings have a
    # char in that position. To be used for weighting space counter
    # scores against the maximum possible value.
    pos_hits = [0] * key_sz
    for ct_b in ct_b_list:
        pos_hits = [pos_hits[i] + 1 if i < len(ct_b) else pos_hits[i]
                        for i in range(len(pos_hits))]
    debug_msg("pos_hits:")
    for i, v in enumerate(pos_hits):
        debug_msg("  {0:3d}: {1:2d}".format(i, v))

    # Do all combinations of XORing one ciphertext with another one.
    for idx1 in range(len(ct_b_list)):
        ct1 = ct_b_list[idx1]
        # The number of times we have confirmed that, for ct1 , it's
        # likely to have a space in its plaintext at the respective
        # key position.
        space_counter = [0] * key_sz
        for idx2 in range(len(ct_b_list)):
            # Don't XOR a ct with itself.
            if idx1 == idx2:
                continue
            ct2 = ct_b_list[idx2]
            # The XOR length must be the minimum of both ct lengths.
            # The 'utils.xor()' function does the trimming of the
            # longest operand when it is the 2nd one (key).
            if len(ct2) > len(ct1):
                s, k, l = ct1, ct2, len(ct1)
            else:
                s, k, l = ct2, ct1, len(ct2)
            # XOR both ciphertexts.
            ctx = utils.xor(s, k)
            # For each byte, check if it can be a XOR with space and
            # update the score accordingly
            for i in range(l):
                val = ctx[i]
                if is_xored_with_space(val):
                    space_counter[i] += 1

        debug_msg("-" * 80)
        debug_msg("idx1: {0}".format(idx1))
        debug_msg("space_score:")
        for i, v in enumerate(space_counter):
            debug_msg("  {0:3d}: {1:2d}".format(i, v))

        # Update the key value in the positions we decide that 'ct1' has a space.
        for i, v in enumerate(space_counter):
            # For each ct, if there's a space at a position and all other ct
            # would have some letter in the same position, we would get a perfect
            # score of (num_ct_at_pos - 1) for that position, where 'num_ct_at_pos'
            # is the number of ct that have a byte at that position, maintained
            # here by the 'pos_hits' list.
            # However, even if it's really a space at that position, the XORed
            # result may not be detected by the 'is_xored_with_space()' function.
            # For example, if the other ct also has a space at the position, the
            # result is 0x00 and not a letter. If it's some punctuation char, it
            # will also not be detected.
            # This way, we need some minimum score to consider it's a space, which
            # should be some fraction of the maximum possible score.
            max_score = pos_hits[i] - 1
            min_score = max_score // 2
            if v > min_score:
                if key[i] is None or v > key_score[i]:
                    # If pt[i] = ' ', then key[i] = ct[i] XOR pt[i] = ct[i] XOR ' '.
                    key[i] = ct1[i] ^ ord(' ')
                    key_score[i] = v

    return key

def guess_key_3(ct_b_list, key_sz):
    """Third method tried for guessing the key."""

    # Use the repeating key XOR method to guess the 1st 'xor_key_sz'
    # bytes from the key, where 'xor_key_sz' is size of the smallest
    # ciphertext.
    #
    # Because the nonce is fixed and the same, the key stream acts
    # exactly as a repeating key XOR process. However, the number of
    # key stream bytes we can find with this is only the length of
    # the smallest ciphertext.
    #
    # Note that 'guess_key_1()' uses a similar method and can also
    # just find the first 'N' bytes from the key stream, but in its
    # case, 'N' can be larger than the smallest ciphertext.

    xor_key_sz = min([len(ct_b) for ct_b in ct_b_list])

    # Concatenate all ciphertexts using 'xor_key_sz' bytes
    # from each.
    ct_b_xor = b''.join([ct_b[:xor_key_sz] for ct_b in ct_b_list])

    (key_size, key_score, key_b) = c6.break_key(ct_b_xor, xor_key_sz)

    # Convert key from byte array to list of bytes with None set in the positions
    # for which we do not have determined a value.
    key = list(key_b) + [None] * (key_sz - len(key_b))

    return key

def verify_break(pt_b_list, pt_b_list_ok):
    """Confirms if the plaintext broken matches the real one."""
    equal_list = [pt_b_list[i] == pt_b_list_ok[i] for i in range(len(pt_b_list))]
    if all(equal_list):
        return True
    return False

def guess_key_manually(ct_b_list, pt_b_list_ok, pt_b_list, key, key_sz):
    """User interface function for guessing remaining key bytes."""

    # This basically shows the broken plaintext strings using the key
    # found so far. Byte positions for which the key byte is not set yet
    # results in '*' being shown in the respective plaintext strings
    # positions.
    #
    # The idea is for the user to see the current plaintext strings and
    # manually guess and try the remaining text, by entering plaintext
    # that could make sense. The function takes the changed plaintext,
    # changes or sets the respective key bytes and recalculates all the
    # plaintext strings again, showing the resulting plaintext strings
    # and if they match or not the real ones.

    def print_options():
        """Show available options."""
        print("Options:")
        print("  - Enter 'e' to set/change a plaintext. Its number will be required")
        print("  - Enter 'h' to show this help message")
        print("  - Enter 'q' to quit without changes.")
        print("  - Enter 'x' to quit saving changes.")
        print("  - Enter 'a' to abort manual process.")

    def print_help():
        """Show some help."""
        print("-" * 80)
        print("Manually change/set of plaintext chars")
        print("  Allows guessing/changing plaintext chars,")
        print("  thus changing the respective key byte and")
        print("  recalculating all plaintext strings.")
        print("-" * 80)
        print("The key bytes that are set in each iteration")
        print("are shown in a key map, where:")
        print("  - There's info about key bytes set and missing.")
        print("  - There's a byte position ruler (00, 01, etc.)")
        print("  - For each key byte there's a mark:")
        print("    - 'X' is set, '*' is missing.")
        print("-" * 80)
        print("The current plaintext strings are also shown:")
        print("  - Byte position rulers inserted in between.")
        print("  - Each plaintext has an identifier number on the right.")
        print("  - A '*' in plaintext means requires guessing")
        print("-" * 80)
        print_options()
        print("")
        print("Enter any key to start.")
        input()

    def print_ruler(key_sz):
        """Print a byte position ruler."""
        if key_sz >= 100:
            for i in range(key_sz):
                s = "{0}".format(i // 100)
                if i < (key_sz - 1):
                    print(s, end = '')
                else:
                    print(s)
        for i in range(key_sz):
            s = "{0}".format((i % 100) // 10)
            if i < (key_sz - 1):
                print(s, end = '')
            else:
                print(s)
        for i in range(key_sz):
            s = "{0}".format(i % 10)
            if i < (key_sz - 1):
                print(s, end = '')
            else:
                print(s)

    def print_key_map(key):
        """Print the key bytes map."""
        key_sz = len(key)
        for i in range(key_sz):
            if key[i] is None:
                s = '*'
            else:
                s = 'X'
            if i < (key_sz - 1):
                print(s, end = '')
            else:
                print(s)

    def print_plaintext_list(pt_b_list, key_sz):
        """Prints the current broken plaintext strings."""
        for i, pt_b in enumerate(pt_b_list):
            if i % 20 == 0:
                print("-" * 80)
                print_ruler(key_sz)
                print("-" * 80)
            print("{0:<{1}} - {2}".format(utils.bytes2rawstr(pt_b), key_sz, i))
        print("-" * 80)
        print_ruler(key_sz)
        print("-" * 80)

    def edit_params():
        """Gets the params when editing a plaintext."""

        def abort():
            """Confirms abort request."""
            print("Aborted.")
            print("Enter any key to continue.")
            input()

        res = 0
        pt_b_n = 0
        pos = 0
        pt = ""
        state = 1

        # Loop for getting the plaintext edit params.
        #  + State 1: Get which plaintext string to edit.
        #  + State 2: Get the start position to edit in the string.
        #  + State 3: Get the new plaintext itself.
        while True:
            try:
                if state == 1:
                    print("Enter 'q' to quit or the plaintext number ({0}~{1}): "
                            .format(0, pt_b_list_len - 1), end = '')
                    opt = input()
                    if opt == 'q':
                        abort()
                        break
                    pt_b_n = int(opt)
                    if pt_b_n < 0 or pt_b_n > (pt_b_list_len - 1):
                        raise Exception()
                    pt_b = pt_b_list_work[pt_b_n]
                    pt_b_len = len(pt_b)
                    state += 1
                if state == 2:
                    print("-" * 80)
                    print_ruler(key_sz)
                    print("-" * 80)
                    print("{0:<{1}}".format(utils.bytes2rawstr(pt_b), key_sz))
                    print("-" * 80)
                    print("Enter the start position ({0}~{1}): "
                            .format(0, pt_b_len - 1), end = '')
                    opt = input()
                    if opt == 'q':
                        abort()
                        break
                    pos = int(opt)
                    if pos < 0 or pos > (pt_b_len - 1):
                        raise Exception()
                    max_len = pt_b_len - pos
                    state += 1
                if state == 3:
                    print("Enter the plaintext to set (max {0} chars): "
                            .format(max_len), end = '')
                    opt = input()
                    if opt == 'q':
                        abort()
                        break
                    pt = opt
                    pt_len = len(pt)
                    if pt_len == 0 or pt_len > max_len:
                        raise Exception
                    res = 1
                    break
            except:
                print("Invalid entry: [{0}]".format(opt))
                print("Enter any key to continue.")
                input()

        return (res, pt_b_n, pos, pt)

    abort = False
    save = False
    pt_b_list_work = pt_b_list[:]
    pt_b_list_len = len(pt_b_list_work)
    key_work = key[:]

    print_help()

    while True:
        # How many key bytes are set and missing from total.
        key_miss = key_work.count(None)
        key_set = key_sz - key_miss
        print("-" * 80)
        print("Key Map: {0}/{1} ({2} missing)".format(key_set, key_sz, key_miss))
        print("-" * 80)
        print_ruler(key_sz)
        print("-" * 80)
        print_key_map(key_work)
        print("-" * 80)

        # Shows currently broken plaintext.
        print("Plaintext Map:")
        print_plaintext_list(pt_b_list_work, key_sz)

        # Checks is broken plaintext matches real one.
        ok = verify_break(pt_b_list_work, pt_b_list_ok)
        print("Current plaintext {0} real one.".format("MATCHES" if ok else "DOESN'T MATCH"))

        # User input loop.
        print("Enter option: ", end='')
        opt = input()
        if opt == 'e':
            # Change some plaintext string.
            print("Requested edit plaintext.")
            (res, pt_n, pt_pos, pt) = edit_params()
            if res:
                # Derive the new key.
                pt_b = utils.rawstr2bytes(pt)
                x = pt_pos
                y = pt_pos + len(pt_b)
                new_key_slice_b = utils.xor(ct_b_list[pt_n][x:y], pt_b)
                new_key_slice = list(new_key_slice_b)
                key_work = key_work[:x] + new_key_slice + key_work[y:]
                # Recalculate decrypted plaintext strings.
                pt_b_list_work = ctr_decrypt_string_list(ct_b_list, key_work)
        elif opt == 'h':
            # Show the help.
            print_help()
        elif opt == 'q':
            # Quit without saving.
            print("Requested to exit without saving!")
            print("Enter any key to continue.")
            input()
            save = False
            break
        elif opt == 'x':
            # Quit, but save the changes made so far.
            print("Requested to exit and save!")
            print("Enter any key to continue.")
            input()
            save = True
            break
        elif opt == 'a':
            # Signal we give up.
            print("Requested to abort!")
            print("Enter any key to continue.")
            input()
            abort = True
            save = False
            break
        else:
            print("Invalid option entered: [{0}]".format(opt))
            print("Enter 'h' for help.")
            print("Enter any key to continue.")
            input()

    if save:
        return (key_work, pt_b_list_work, abort)
    else:
        return (key, pt_b_list, abort)

def execute_break_ctr_fixed_nonce(file_name):
    """Break CTR encryption using fixed nonce using substitution."""

    # Get the file strings.
    pt_strings = list(utils.file_get_lines(file_name))

    # Build the ciphertext strings list.
    (ct_b_list, pt_b_list) = ctr_encrypt_string_list(pt_strings)
    # The key stream we need must have the size of the longest string.
    ctr_key_sz = max([len(ct_b) for ct_b in ct_b_list])
    # Start with a fully unknown key.
    ctr_key = [None] * ctr_key_sz

    # Get as many unknown key bytes as possible using method 1.
    ctr_key_1 = guess_key_1(ct_b_list, ctr_key_sz)
    pt_b_list_1 = ctr_decrypt_string_list(ct_b_list, ctr_key_1)
    dump_list(pt_b_list_1, "Cracked Plaintext Strings (1)")

    # Get as many unknown key bytes as possible using method 2.
    ctr_key_2 = guess_key_2(ct_b_list, ctr_key_sz)
    pt_b_list_2 = ctr_decrypt_string_list(ct_b_list, ctr_key_2)
    dump_list(pt_b_list_2, "Cracked Plaintext Strings (2)")

    # Choose final key for manual selection.
    # Considering:
    #  + Method 1 is more efficient for the 1st key positions,
    #    where there are lots of plaintext strings having a char
    #    in those positions. For the last key positions, fewer
    #    plaintexts will have chars in there, which causes this
    #    method to become weaker for those key positions.
    #  + Method 2 is relying on plaintexts having a space char
    #    in as many key positions as possible. It's good for
    #    complementing Method 1.
    # We will build the final key for manual selection using
    # Method 1 for all key positions it guessed the key and for
    # the remaining positions we take it from Method 2 if it's
    # there.
    def choose_key(k1, k2):
        """Choose keys from methods 1 and 2."""
        return k2 if k1 is None else k1
    ctr_key_m = [choose_key(k1, k2) for (k1, k2) in zip(ctr_key_1, ctr_key_2)]
    pt_b_list_m = ctr_decrypt_string_list(ct_b_list, ctr_key_m)
    dump_list(pt_b_list_m, "Cracked Plaintext Strings (M)")

    # Check if we have fully cracked the ciphertext strings.
    # If not, go for manual guessing of missing stuff.
    ok = verify_break(pt_b_list_m, pt_b_list)
    while not ok:
        print("-" * 80)
        print("Cracked plaintext strings not yet matching real ones.")
        print("Entering manual plaintext guessing process.")
        (ctr_key_m, pt_b_list_m, abort) = \
                guess_key_manually(ct_b_list, pt_b_list, pt_b_list_m, ctr_key_m, ctr_key_sz)
        ok = verify_break(pt_b_list_m, pt_b_list)
        if abort:
            print("-" * 80)
            print("Plaintext manual selection aborted!")
            break

    if ok:
        print("-" * 80)
        print("Cracked plaintext strings match the real ones!")
    else:
        print("-" * 80)
        print("Cracked plaintext strings not yet matching real ones.")
    print("OK =", ok)
    print("-" * 80)

    return ok

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_file = 'data/data_c19.txt'
        ok = execute_break_ctr_fixed_nonce(in_file)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_file  = [{1}]".format(me, in_file))
        if not ok:
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


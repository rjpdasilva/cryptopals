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

"""Cryptopals Challenges: Test Challenge 44: DSA nonce recovery from repeated nonce."""

import sys
import utils.cp_aux_utils as utils
import cp_test_c43 as c43

title = "Challenge 44: DSA nonce recovery from repeated nonce"

# Debug flag.
debug = 0

# Debug messages.
def debug_msg(*args, **kwargs):
    """Extra debug messages."""
    if not debug:
        return
    print(*args, **kwargs)

def get_data_from_file(msg_list_file):
    """Parses the data file into an array of (msg, r, s, m) tuples."""

    msg_list = []

    # Read the file lines into an array.
    lines = list(utils.file_get_lines(msg_list_file))
    num_lines = len(lines)

    # Each message is represented by 4 lines.
    if num_lines % 4:
        return None
    num_msgs = num_lines // 4

    # Parse the data.
    for i in range(num_msgs):
        j = i * 4
        keys = [lines[j + k].split(': ', maxsplit = 1)[0] for k in range(4)]
        vals = [lines[j + k].split(': ', maxsplit = 1)[1] for k in range(4)]
        if keys != ['msg','s','r','m']:
            return None
        vals_set = tuple(vals)
        # Switch 'r' and 's' positions in the set.
        # Public key is usually (r, s), so keep that order.
        # Also, work with integers.
        (msg, s, r, m) = vals_set
        vals_set = (msg, int(r), int(s), int(m, 16))
        msg_list.append(vals_set)

    for i, (msg, r, s, m) in enumerate(msg_list):
        debug_msg("-" * 60)
        debug_msg("msg {0:02d}/{1:02d}:".format(i + 1, num_msgs))
        debug_msg("  msg = [{0}]".format(msg))
        debug_msg("  r   = [{0}]".format(r))
        debug_msg("  s   = [{0}]".format(s))
        debug_msg("  m   = [{0}]".format(hex(m)))

    return msg_list

def get_pairs_same_r(msg_list):
    """Builds an array of message index pairs for messages with the same 'r'."""

    msg_pairs = []
    num_msgs = len(msg_list)

    # Search all non-repeating combinations for
    # messages with the same 'r' value.
    for i1 in range(num_msgs - 1):
        (_, r1, _, _) = msg_list[i1]
        for i2 in range(i1 + 1, num_msgs):
            (_, r2, _, _) = msg_list[i2]
            if r1 == r2:
                pair = (i1, i2)
                msg_pairs.append(pair)

    return msg_pairs

def get_pair_k(msg_pair, msg_list, pub):
    """Calculates the common 'k' value for a pair."""

    (i1, i2) = msg_pair
    (_, r1, s1, m1) = msg_list[i1]
    (_, r2, s2, m2) = msg_list[i2]
    assert r1 == r2
    r = r1
    (_, q, _, _) = pub

    # Use the formula described in the challenge to calculate the common 'k'.
    #  'k = ((m1 - m2) / (s1 - s2)) mod q'
    #
    # Here;s how to reach the formula starting from DSA equations:
    #  's = ((m + x * r) / k) % q'
    # As seen, messages signed with the same 'k' will have the same 'r' as
    # well, because 'r = g^k & p' and 'g' and 'p' are constant.
    # The 'q' and 'x' parameters are also constant between messages, so,
    # for 2 messages sharing the same 'k' (and this, 'r'), we have:
    #  's1 = ((m1 + x * r) / k) % q'
    #  's2 = ((m2 + x * r) / k) % q'
    # We can eliminate the unknown 'x' out of the equation by doing:
    #  's1 - s2 = (((m1 + x * r) / k) % q) - (((m2 + x * r) / k) % q)'  <=>
    #  's1 - s2 = (m1 / k + (x * r) / k - m2 / k - (x * r) / k) % q'    <=>
    #  's1 - s2 = (m1 / k - m2 / k) % q'                                <=>
    #  's1 - s2 = ((m1 - m2) / k) % q'                                  <=>
    #  'k = ((m1 - m2) / (s1 - s2)) % q'
    #
    # Care must be taken to make sure all operations are modulo 'q',
    # namely the subtractions and the division (multiplication with
    # the modular inverse).

    k_num = (m1 - m2) % q
    k_den = (s1 - s2) % q
    k_den_inv = utils.invmod(k_den, q)
    k = (k_num * k_den_inv) % q

    return k

def get_pairs_k(msg_pairs, msg_list, pub):
    """Builds an array with common 'k' value for each pair."""

    num_pairs = len(msg_pairs)
    msg_pairs_k = [get_pair_k(msg_pair, msg_list, pub) for msg_pair in msg_pairs]

    return msg_pairs_k

def get_pair_x(i, msg_pairs, msg_pairs_k, msg_list, pub):
    """Calculates the common 'x' value for a pair."""

    (i1, i2) = msg_pairs[i]
    (_, r1, s1, m1) = msg_list[i1]
    (_, r2, s2, m2) = msg_list[i2]
    sig1 = (r1, s1)
    sig2 = (r2, s2)
    k = msg_pairs_k[i]

    x1 = c43.key_get_x_from_k(m1, pub, sig1, k)
    x2 = c43.key_get_x_from_k(m2, pub, sig2, k)

    return (x1, x2)

def get_pairs_x(msg_pairs, msg_pairs_k, msg_list, pub):
    """Builds an array with common 'x' value for each pair."""

    num_pairs = len(msg_pairs)
    msg_pairs_x = [get_pair_x(i, msg_pairs, msg_pairs_k, msg_list, pub) for i in range(num_pairs)]

    return msg_pairs_x

def execute_break_dsa_prv_key(msg_list_file, pub):
    """Perform the DSA private key breaking as described by the challenge."""

    ok = False
    x = None
    x_h = None

    # Parse the data file into an array of message info tuples
    # (msg, r, s, m).
    msg_list = get_data_from_file(msg_list_file)
    if msg_list == None:
        return (ok, x, x_h)

    # According to the challenge, some messages have been signed
    # with the same 'k'. Since 'r = pow(g, k, p) % q', this means
    # that those messages will also have the same 'r'.
    # Build an array of index pairs for messages having the same
    # 'r' value.
    msg_pairs = get_pairs_same_r(msg_list)
    num_pairs = len(msg_pairs)
    if num_pairs == 0:
        return (ok, x, x_h)

    # Determine the common 'k' value for each message pair.
    msg_pairs_k = get_pairs_k(msg_pairs, msg_list, pub)
    num_pairs_k = len(msg_pairs_k)
    if num_pairs_k != num_pairs:
        return (ok, x, x_h)

    # Determine the private key 'x'.
    # We know already the 'k' for each message pair.
    # By reusing 'key_get_x_from_k()' from previous challenge,
    # we can calculate the private key used for each message
    # pair, which must be the same for all pairs.
    msg_pairs_x = get_pairs_x(msg_pairs, msg_pairs_k, msg_list, pub)
    num_pairs_x = len(msg_pairs_x)
    if num_pairs_x != num_pairs:
        return (ok, x, x_h)

    # Debug dump.
    for i, (i1, i2) in enumerate(msg_pairs):
        (_, r, _, _) = msg_list[i1]
        k = msg_pairs_k[i]
        (x1, x2) = msg_pairs_x[i]
        debug_msg("-" * 60)
        debug_msg("msg pair {0:02d}/{1:02d}: ({2:02d},{3:02d}):".format(i + 1, num_pairs, i1, i2))
        debug_msg("  r   = [{0}]".format(r))
        debug_msg("  k   = [{0}]".format(k))
        debug_msg("  x1  = [{0}]".format(x1))
        debug_msg("  x2  = [{0}]".format(x2))

    # We've grouped message pairs having same 'r' (and,
    # thus, same 'k') in 'msg_pairs'.
    # Then for each message pair, we've calculated the
    # common 'k' value and placed those in 'msg_pairs_k'.
    # Finally, we've built 'msg_pairs_x' with the common
    # 'x' value for each message in a message pair and
    # for all message pairs.
    # Since there can be only one single value for 'x',
    # common to all messages and messages pairs, then
    # each '(x1, x2)' element from 'msg_pairs_x' must have
    # 'x1 == x2' and all elements must have the same 'x1'
    # and 'x2' values, i.e., all values are equal to 'x'.
    (x1, x2) = msg_pairs_x[0]
    if x1 != x2:
        return (ok, x, x_h)
    x = x1
    if not all([(msg_pair_x == (x, x)) for msg_pair_x in msg_pairs_x]):
        return (ok, x, x_h)
    ok = True

    # Calculate the private key fingerprint (SHA-1).
    x_msg = hex(x)[2:]
    x_h = c43.hash_msg_as_int(x_msg)

    debug_msg("-" * 60)
    debug_msg("Done:")
    debug_msg("  ok  = [{0}]".format(ok))
    debug_msg("  x   = [{0}]".format(x))
    debug_msg("  x_h = [{0}]".format(hex(x_h)))

    debug_msg("-" * 60)
    return (ok, x, x_h)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_file = "data/data_c44.txt"
        in_p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
        in_q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
        in_g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
        in_y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
        in_x_h = 0xca8f6f7c66fa362d40760d135b763eb8527d3d52
        in_pub = (in_p, in_q, in_g, in_y)
        (ok, x, x_h) = execute_break_dsa_prv_key(in_file, in_pub)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_file  = [{1}]".format(me, in_file))
        print("{0}: in_p     = [{1}]".format(me, hex(in_p)))
        print("{0}: in_q     = [{1}]".format(me, hex(in_q)))
        print("{0}: in_g     = [{1}]".format(me, hex(in_g)))
        print("{0}: in_y     = [{1}]".format(me, hex(in_y)))
        print("{0}: in_x_h   = [{1}]".format(me, hex(in_x_h)))
        print("{0}: ok       = [{1}]".format(me, ok))
        if ok:
            print("{0}: x        = [{1}]".format(me, x))
            print("{0}: x_h      = [{1}]".format(me, hex(x_h)))
        if not ok or x_h != in_x_h:
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


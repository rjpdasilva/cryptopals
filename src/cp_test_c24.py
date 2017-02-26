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

"""Cryptopals Challenges: Test Challenge 24: Create the MT19937 stream cipher and break it."""

import sys
import utils.cp_aux_utils as utils
import time

title = "Challenge 24: Create the MT19937 stream cipher and break it"

def encrypt(pt_b):
    """Encryption function as required in challenge's statement."""

    print("-" * 60)

    # Use a random sized and random content prefix.
    prefix_min = 1
    prefix_max = 100
    prefix_len = utils.rand_int(prefix_min, prefix_max)
    prefix_b = utils.rand_bytes(prefix_len)
    print("Encrypt: prefix_len = {0}".format(prefix_len))
    print("Encrypt: prefix     = {0}".format(prefix_b))

    # Use a random 16-bit seed to create the MT19937 Stream Cipher.
    key = utils.rand_int(0, 2**16 - 1)
    print("Encrypt: key / seed = {0}".format(key))
    crypto = utils.MT19937StreamCipher(key)

    # Encrypt.
    pt_final_b = prefix_b + pt_b
    ct_b = crypto.encrypt(pt_final_b)

    return (ct_b, key, prefix_len)

def generate_password_reset_token(twnd):
    """Password Reset Token generation function as requested by the challenge's statement."""

    print("-" * 60)

    # The Password Reset Token will be basically the output
    # of the MT19937 Stream Cipher for a random length.
    # To get exactly the output of the MT19937, we set all
    # of the plaintext token bytes to 0x00, so that when
    # XORed with the MT19937 RNG, it gives exactly the RNG
    # output (because: pt XOR rng = 0x00 XOR rng = rng).

    token_min = 1
    token_max = 100
    token_len = utils.rand_int(token_min, token_max)
    token_pt_b = b'0' * token_len
    print("Token Generate: token_len  = {0}".format(token_len))
    print("Token Generate: token_pt_b = {0}".format(token_pt_b))

    # Use current time seed to create the MT19937 Stream Cipher.
    key = int(time.time())
    print("Token Generate: key / seed = {0}".format(key))
    crypto = utils.MT19937StreamCipher(key)

    # Encrypt.
    token_ct_b = crypto.encrypt(token_pt_b)

    # Sleep a while around the time window.
    # Use some random value so that sometimes the cracker
    # can find the seed and other times not, when using
    # the same time window.
    # The cracker will only look back withing the time window,
    # so in the cases we sleep here less time than the window,
    # the seed will be found, otherwise not.

    twait = utils.rand_int(twnd // 2, twnd // 2 * 3)
    print("Token Generate: Waiting {0} secs for a twnd of {1} secs...".format(twait, twnd))
    time.sleep(twait)
    print("Token Generate: Waiting {0} secs for a twnd of {1} secs...done".format(twait, twnd))

    return (token_ct_b, key, twait)

def check_password_reset_token_time(token_ct_b, twnd):
    """Checks it the token as generated from a MT19937 seeded in a current time window."""

    print("-" * 60)

    # Assuming the token is a direct output of an MT19937 Stream Cipher,
    # seeded with a recent timestamp, the ciphered result is exactly the
    # random numbers output by the RNG, that is, it results from
    # requesting the stream cipher to encrypt a string of zeros with
    # size equal to the size of the given encrypted token.
    # See 'generate_password_reset_token()'
    #
    # We will get the current timestamp and then go back in time, limited
    # to the given time window, checking if the output of MT19937, when
    # fed with zeroes, matches the received encrypted token. If it does,
    # it means we have cracked the seed that was used.
    # To be noted that 'generate_password_reset_token()' is deliberately
    # waiting some random time between (twnd / 2) and (twnd / 2 * 3). When
    # it sleeps less than the 'twnd', this function will find the seed,
    # other it won't. This was introduced on purpose to reinforce the point
    # of the challenge.

    # The string of zeroes we'll be feeding into MT19937.
    pt_b = b'0' * len(token_ct_b)

    # Search for the seed in the given time window, counting backwards
    # from current time.
    tnow = int(time.time())
    seed = None
    toffs = None
    print("Token Check: Searching {0} secs backwards from {1}...".format(twnd, tnow))
    for t in range(twnd):
        tseed = tnow - t
        crypto = utils.MT19937StreamCipher(tseed)
        ct_b = crypto.encrypt(pt_b)
        if ct_b == token_ct_b:
            seed = tseed
            toffs = t
            break
    print("Token Check: Searching {0} secs backwards from {1}...done".format(twnd, tnow))
    print("Token Check:   seed  = [{0}]".format(seed))
    print("Token Check:   toffs = [{0}]".format(toffs))
    print("-" * 60)

    return (seed, toffs)

def execute_break_mt19937_stream_cipher():
    """Breaks the key used by the MT19937 Stream Cipher."""

    # Facts known by the attacker:
    #  + The key is 16 bit.
    #  + The cipher uses output of MT19937 for keystream.

    pt_b = b'A' * 14

    # Request encrypted known plaintext.
    (ct_b, key_real, prefix_len_real) = encrypt(pt_b)

    print("-" * 60)

    # Determine the prefix len.
    prefix_len_broken = len(ct_b) - len(pt_b)
    print("Break: prefix_len_broken = {0}".format(prefix_len_broken))

    # Brute force key detection, based only on the ciphertext
    # returned by the 'encrypt()' function above and access to
    # the MT19937 Stream Cipher.
    #
    # We create the stream cipher for each possible seed/key
    # value and then check when the returned encrypted content
    # matches the ciphertext we got before from the 'encrypt()'
    # function. When it does, the used seed value is the key.
    #
    # A number of dummy bytes matching the detected prefix len
    # must be prepended to the plaintext we feed to the MT19937
    # Stream Cipher so that we're sure our known plaintext is
    # in the same position as it was when used by the 'encrypt()'
    # function called above, and we compare only the data after
    # the prefix length, because we can't know the bytes that
    # were used for prefixing, we only know what our plaintext
    # is and what its ciphertext looks like.

    print("Break: Doing brute force attack on key...")
    tstart = int(time.time())
    key_broken = None
    for kv in range(2**16):
        crypto = utils.MT19937StreamCipher(kv)
        pt_attack_b = b'X' * prefix_len_broken + pt_b
        ct_attack_b = crypto.encrypt(pt_attack_b)
        if (ct_attack_b[prefix_len_broken:] == ct_b[prefix_len_broken:]):
            key_broken = kv
            break
    tend = int(time.time())
    tdur = tend - tstart
    print("Break: Doing brute force attack on key...done")
    print("Break:   key  = [{0}]".format(key_broken))
    print("Break:   time = [{0} seconds]".format(tdur))

    return (key_real, prefix_len_real, key_broken, prefix_len_broken, tdur)

def execute_check_token_is_time_seeded(twnd):
    """Does the check on a password token required by the challenge."""

    # Generates a password token.
    (token_ct_b, seed_real, twait) = generate_password_reset_token(twnd)

    # Checks if the given password token was generated by a MT19937
    # RNG seeded within a time window (seconds) counting backwards
    # from current time.
    (seed_broken, time_offset) = check_password_reset_token_time(token_ct_b, twnd)

    return (seed_real, twait, seed_broken, time_offset)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        twnd = 10
        (key_ok, pfix_ok, key, pfix, duration) = execute_break_mt19937_stream_cipher()
        (seed_ok, twait, seed, toffs) = execute_check_token_is_time_seeded(twnd)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Break MT19937 Stream Cipher Part".format(me))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: pfix     = [{1}]".format(me, pfix))
        print("{0}: pfix_ok  = [{1}]".format(me, pfix_ok))
        print("{0}: key      = [{1}]".format(me, "Not Found" if key is None else key))
        print("{0}: duration = [{1} secs]".format(me, duration))
        print("{0}: key_ok   = [{1}]".format(me, key_ok))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Password Reset Token Part".format(me))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: twnd     = [{1} secs]".format(me, twnd))
        print("{0}: seed     = [{1}]".format(me, "Not Found" if seed is None else seed))
        print("{0}: toffs    = [{1} secs]".format(me, "Not Found" if toffs is None else toffs))
        print("{0}: seed_ok  = [{1}]".format(me, seed_ok))
        print("{0}: twait    = [{1} secs]".format(me, twait))
        ok_break = (pfix == pfix_ok and key == key_ok)
        ok_token = (twait > twnd or seed == seed_ok)
        if not ok_break or not ok_token:
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


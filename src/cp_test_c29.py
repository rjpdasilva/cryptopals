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

"""Cryptopals Challenges: Test Challenge 29: Break a SHA-1 keyed MAC using length extension."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 29: Break a SHA-1 keyed MAC using length extension"

# Random constant key used in challenge.
key_b = None

# Maximum secret key size to use in the challenge.
max_key_sz = 1024
key_sz_real = None

def sha1_pad(msg_b):
    """Pads a message according to SHA-1 requirements."""
    return utils.sha1_pad(msg_b)

def sha1_get(msg_b):
    """Produces the SHA-1 authentication code as requested by the challenge."""

    global key_b
    global key_sz_real

    # Create the random key.
    if key_b is None:
        key_sz_real = utils.rand_int(1, max_key_sz)
        key_b = utils.rand_bytes(key_sz_real)

    # Get the SHA-1 with the key.
    sha1_b = utils.sha1_mac(key_b, msg_b)

    return sha1_b

def sha1_validate(msg_b, sha1_b):
    """Validates if hashing 'msg_b' results in 'sha1_b'."""
    sha1_calc_b = sha1_get(msg_b)
    return sha1_b == sha1_calc_b

def sha1_extend(key_sz, msg_b, hash_b, append_b):
    """Extend 'msg_b' with 'append_b' and produce valid hash, given the key length."""

    # Use a dummy key, just so we're able to get the associated message padding bytes.
    key_dummy_b = b'\x00' * key_sz
    msg_dummy_b = key_dummy_b + msg_b

    # This is what the real hashing function would use for padding the original
    # message, when using a key of the given 'key_sz' length.
    msg_pad_b = sha1_pad(msg_dummy_b)[(key_sz + len(msg_b)):]

    # And this is how the message we're trying to forge would look like if
    # the actual key size is correct.
    msg_ext_b = msg_b + msg_pad_b + append_b

    # Recreate the internal state of the real hashing function for the original
    # message, based on its known hash, and use it to continue the hashing process
    # for the message we want to append.
    # To be noted that the length of the message we're trying to forge (including
    # the key) is important for the SHA1 initial state, as it will determine the
    # padding that is required on the forged message.

    assert (len(hash_b) is 20)
    # Split the hash into the internal SHA1 state 5 32-bit words.
    h = [int.from_bytes(hash_b[i:(i + 4)], 'big') for i in range(0, len(hash_b), 4)]
    assert (len(h) is 5)
    # Create a new SHA1 object with its internal state already set to the hash of
    # the original message, so that it continues on hashing, now for the string we
    # want to append to the original message. The total length of the message is the
    # key size plus the original message length, plus the padding on the original
    # message plus the length of the append string.
    sha1_clone = utils.SHA1(append_b, h, key_sz + len(msg_ext_b))
    hash_ext_b = sha1_clone.digest()

    return (msg_ext_b, hash_ext_b)

def execute_break_sha1(msg, append):
    """Execute the length extension attack."""

    # The attacker knows:
    #  + The original message 'msg_b' (its contents and length).
    #  + The message hash 'hash_b'.
    #  + The hashing algorithm (SHA-1 with prefixed secret key).
    #  + The padding scheme used by the hashing function.
    #  + The maximum key size 'max_key_sz.
    #  + A way of validating a forged message/hash.
    #
    # The attacker doesn't know:
    #  + The secret key used by the hashing function for prefixing the message with.
    #  + The size of the secret key.
    #
    # The attack goal is to append a specific string 'append' to the message 'msg' in
    # a way that produces a valid hash.
    #
    # For better understanding of the attack, used several sources from googling around
    # "sha1 length extension attack", namely:
    #  + https://en.wikipedia.org/wiki/Length_extension_attack
    #  + http://crypto.stackexchange.com/questions/3978/understanding-the-length-extension-attack
    #  + https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
    #
    # The strategy is to reproduce the internal state of the SHA1 hashing function based on the hash
    # we have for the original message and understanding that the SHA1 hasher has padded it before
    # calculating the hash. This way, we can start a new SHA1 hashing where the internal state is
    # the hash of the original message and the message so far is the original message followed by
    # its padding. With this state, we can continue to update the hash by requesting hashing for any
    # string we want to append.
    # The padding depends on the key size (which we don't know), but we can tell when we got the
    # hash right, so it's just a matter of trying (brute force) for different key sizes.

    # What the attacker has.
    msg_b = utils.rawstr2bytes(msg)
    hash_b = sha1_get(msg_b)
    append_b = utils.rawstr2bytes(append)

    # Try to forge a message and hash for each possible key size.
    # When we have a valid hash, we know the key size is right and
    # thus have the forged message and associated valid hash.
    msg_ext = None
    hash_ext = None
    found = False
    for key_sz in range(1, max_key_sz + 1):
        # Get the forged message and associated hash if the key size is 'key_sz'.
        (msg_ext_b, hash_ext_b) = sha1_extend(key_sz, msg_b, hash_b, append_b)
        # Confirm if we got it right.
        if sha1_validate(msg_ext_b, hash_ext_b):
            found = True
            break
    if found:
        msg_ext = msg_ext_b
        hash_ext = utils.bytes2hexstr(hash_ext_b)

    return (msg_ext, hash_ext, key_sz)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
        in_append = ";admin=true"
        (msg_ext, hash_ext, key_sz_broken) = execute_break_sha1(in_msg, in_append)
        # Elements:
        #  + 'in_msg': The original message.
        #  + 'in_append': What we want to append to the original message.
        #  + 'msg_ext': The attacked extended message, for which we could calculate a  valid hash.
        #  + 'hash_ext': The hash calculated on the extended message.
        #  + 'key_sz_broken': The key size broken by the attack.
        #  + 'key_sz_real': The real key size.
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_msg        = [{1}]".format(me, in_msg))
        print("{0}: in_append     = [{1}]".format(me, in_append))
        print("{0}: msg_ext       = [{1}]".format(me, msg_ext))
        print("{0}: hash_ext      = [{1}]".format(me, hash_ext))
        print("{0}: key_sz_broken = [{1}]".format(me, key_sz_broken))
        print("{0}: key_sz_real   = [{1}]".format(me, key_sz_real))
        def result_ok():
            """Checks test success conditions."""
            if msg_ext is None or hash_ext is None:
                return False
            if key_sz_broken != key_sz_real:
                return False
            return True
        if not result_ok():
            err_str = "\n{0}: ".format(me) + "-" * 60
            err_str += "\n{0}: TEST          = [FAILED] Result doesn't match expected.".format(me)
            err_str += "\n{0}: ".format(me) + "-" * 60
            raise Exception(err_str)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: TEST          = [OK]".format(me))
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


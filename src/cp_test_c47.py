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

"""Cryptopals Challenges: Test Challenge 47: Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)."""

import sys
import utils.cp_aux_utils as utils
import re
import time

title = "Challenge 47: Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)"

# RSA keys used by the challenge.
(prv, pub) = (None, None)

# Debug flag.
debug = 0

# Debug messages.
def debug_msg(*args, **kwargs):
    """Extra debug messages."""
    if not debug:
        return
    print(*args, **kwargs)

# Utility: Convert byte array to integer.
def int_from_bytes(m_b):
    """Transforms a byte array message to an integer."""
    m = int(m_b.hex(), 16)
    return m

# Utility: Convert integer to byte array.
def bytes_from_int(m, length = None):
    """Transforms an integer message to a byte array message."""
    if length == None:
        length = (m.bit_length() + 7) // 8
    m_b = m.to_bytes(length, 'big')
    return m_b

# PKCS#1 v1.5: Pad a message.
def pkcs1_15_pad(m_b, bitsize):
    """Does PKCS#1 v1.5 padding on a message."""

    length = bitsize // 8

    # We need at least 11 bytes for padding.
    if len(m_b) > (length - 11):
        return (False, None)

    # Add the prefix.
    m_pad_b = b'\x00\x02'
    # Add the random bytes (not 0x00).
    rand_b_len = (length - len(m_b) - 3)
    rand_b = b''
    while len(rand_b) < rand_b_len:
        r_b = utils.rand_bytes(1)
        if r_b != b'\x00':
            rand_b += r_b
    m_pad_b += rand_b
    # Add the 0x00 separator.
    m_pad_b += b'\x00'
    # Add the message.
    m_pad_b += m_b

    return (True, m_pad_b)

# PKCS#1 v1.5: Verify message padding and unpad it.
def pkcs1_15_unpad(m_pad_b, bitsize):
    """Validates and extracts PKCS#1 v1.5 padding."""

    length = bitsize // 8

    # This function returns two flags and the unpadded message
    # in case unpadding is successful.
    # The 1st returned flag indicates if all the validations
    # for the unpadding were OK. The 2nd flag just indicates
    # if the 1st two bytes of the message are '0x00 0x02'. This
    # is the info that the decryption oracle leaks out and required
    # for breaking the message as described by the challenge.

    # Check the length.
    len_ok = (len(m_pad_b) == length)
    if not len_ok:
        return (False, False, None)

    # A valid PKCS#1 v1.5 padded message must have:
    #  + The first two bytes are checked (they must be '0x00 0x02'
    #    which identify PKCS#1 v1.5 padding).
    #  + The next bytes are inspected until a '0x00' is found.
    #    If the number of non-zero bytes is less than 8 or a
    #    '0x00' is not found, the padding is invalid.
    #  + What follows the '0x00' separator is returned as plaintext.

    prefix_ok = (m_pad_b[0:2] == b'\x00\x02')
    r = re.compile(b'\x00\x02[^\x00]{8,}?\x00(.+)', re.DOTALL)
    m = r.match(m_pad_b)
    if not m:
        return (False, prefix_ok, None)

    m_b = m.group(1)
    return (True, prefix_ok, m_b)

# Attack: The decryption oracle.
def decryption_oracle(c, bitsize):
    """The decryption oracle as described in the challenge."""

    # Keys must have been already generated.
    if prv is None:
        return False

    # Decrypt.
    m_pad = utils.rsa_num_decrypt(prv, c)
    m_pad_b = bytes_from_int(m_pad, bitsize // 8)

    # Do the PKCS#1 v1.5 unpadding.
    (unpad_ok, prefix_ok, m_b) = pkcs1_15_unpad(m_pad_b, bitsize)

    # Information being returned by this oracle implementation:
    #  + 'unpad_ok': The PKCS#1 v1.5 unpadding was OK.
    #  + 'prefix_ok': The decrypted and PKCS#1 v1.5 padded message
    #    starts with '0x00 0x02'. Unpadding may still be invalid
    #    even if this flag is 'True'.
    #  + The decrypted and unpadded message, available only if
    #    'unpad_ok' is 'True'.
    #
    # To note that, even though this oracle is returning the
    # decrypted and unpadded message, in this challenge, only the
    # 'prefix_ok' information is being used. The other elements
    # are returned for debugging and testing purposes only.

    return (unpad_ok, prefix_ok, m_b)

# Attack: The attacker's data capturing.
def execute_capture_data(msg, bitsize):
    """Simulates the data capturing required for breaking the message."""

    global prv
    global pub

    # Simulates the data capturing done by the attacker, which
    # will grab the following:
    #  + The public key.
    #  + The cipher encrypted with that public key.

    # Generate the RSA keys.
    if prv is None:
        print("-" * 60)
        print("Generate RSA keys:")
        (prv, pub) = utils.rsa_genkeys(bitsize)
        (d, n) = prv
        (e, n) = pub
        print("  d           = [{0}]".format(d))
        print("  e           = [{0}]".format(e))
        print("  n           = [{0}]".format(n))

    # Pad the message.
    m_b = utils.rawstr2bytes(msg)
    (pad_ok, m_pad_b) = pkcs1_15_pad(m_b, bitsize)
    if not pad_ok:
        debug_msg("Encrypt: PKCS#1 v1.5 padding failed")
        return (False, None)

    # Encrypt the message.
    m = int_from_bytes(m_pad_b)
    c = utils.rsa_num_encrypt(pub, m)

    debug_msg("-" * 60)
    debug_msg("Encrypt:")
    debug_msg("  msg         = [{0}]".format(msg))
    debug_msg("  m_b         = [{0}]".format(m_b))
    debug_msg("  m_pad_b     = [{0}]".format(m_pad_b))
    debug_msg("  m_pad_b(h)  = [{0}]".format(m_pad_b.hex()))
    debug_msg("  m           = [{0}]".format(hex(m)))
    debug_msg("  c           = [{0}]".format(hex(c)))

    # Provide the captured data.
    data_captured = (pub, c)
    return (True, data_captured)

# Attack: Debug: Show the current intervals for the message being broken.
def dump_intervals(M):
    """Dump the current intervals in 'M'."""
    for i, (a, b) in enumerate(M):
        debug_msg("    Interval {0}:".format(i +  1))
        debug_msg("      a       = [{0}]".format(hex(a)))
        debug_msg("      b       = [{0}]".format(hex(b)))

# Attack: Create a ciphertext 'ci' based on 'c' so that 'mi' is 'm' times a factor 's'.
def get_cipher_product(pub, c, s):
    """Return 'ci = (c * s^e) % n'."""
    # Used for determining PKCS conformance of 'm * s'.
    (e, n) = pub
    factor = pow(s, e, n)
    ci = (c * factor) % n
    return ci

# Attack: Call the oracle on a ciphertext to know if the message starts with '0x00 0x02'.
def cipher_is_pkcs1_15_ok(ci, bitsize):
    """Determines if the ciphertext 'ci' is PKCS#1 v1.5 conforming."""
    # The padding oracle side-channel info retrieval.
    (_, ok, _) = decryption_oracle(ci, bitsize)
    return ok

# Attack: Determine the next 'si' for the cases where the message has more
#  than one valid range or for the 1st iteration.
def find_si_normal(pub, c0, bitsize, s_start):
    """ Find 'si' when there's more than one interval left or when 'i = 1'."""
    # Step 2a: Starting the search (i = 1).
    # Step 2b: Searching with more than one interval left.
    si = s_start
    while True:
        ci = get_cipher_product(pub, c0, si)
        if cipher_is_pkcs1_15_ok(ci, bitsize):
            return si
        si += 1

# Attack: Determine the next 'si' for the cases where the message has
#  only one valid range (and it's not the 1st iteration). This allows
#  reducing the message range more quickly, as 'si' increases also
#  more quickly (in 'find_si_normal()', 'si' is only incremented by
#  one, whereas in this function it grows faster).
def find_si_quick(pub, c0, bitsize, B, s, a, b):
    """ Find 'si' when there's only one interval and 'i > 1'."""
    # Step 2c: Searching with one interval left.
    (_, n) = pub
    r = (((2 * (b * s - 2*B)) + (n - 1)) // n)
    while True:
        si_min = (((2*B + r*n) + (b - 1)) // b)
        si_max = ((3*B - 1 + r*n) // a)
        for si in range(si_min, si_max + 1):
            ci = get_cipher_product(pub, c0, si)
            if cipher_is_pkcs1_15_ok(ci, bitsize):
                return si
        r += 1

# Attack: Determine the next 'si' based on current attack state.
def find_si_next(pub, c0, bitsize, B, i, s, num_ints, M):
    """Find the next 'si' value to be used based on current attack state."""

    (_, n) = pub

    # Step 2a: Starting the search (i = 1).
    if i == 1:
        debug_msg("    Step 2a: i = 1...")
        s_start = ((n + (3*B - 1)) // (3*B))
        s = find_si_normal(pub, c0, bitsize, s_start)
        debug_msg("    Step 2a: i = 1...done")
    # Step 2b: Searching with more than one interval left.
    elif num_ints > 1:
        debug_msg("    Step 2b: i > 1 and multiple intervals...")
        s_start = s + 1
        s = find_si_normal(pub, c0, bitsize, s_start)
        debug_msg("    Step 2b: i > 1 and multiple intervals...done")
    # Step 2c: Searching with one interval left.
    else:
        debug_msg("    Step 2c: i > 1 and single interval...")
        (a, b) = M.copy().pop()
        s = find_si_quick(pub, c0, bitsize, B, s, a, b)
        debug_msg("    Step 2c: i > 1 and single interval...done")

    debug_msg("    si        = [{0}]".format(s))
    return s

# Attack: Determine the next set of intervals 'Mi' containing the
#  message being broken, based on the current attack state, namely,
#  a new calculated 'si'.
def find_mi_next(pub, B, s, M):
    """Find the next set of intervals containing the message to break."""

    (_, n) = pub

    # Step 3: Narrowing the set of solutions.
    ints_in = len(M)
    newM = set([])
    for (a, b) in M:
        r_min = ((a*s - 3*B + 1 + (n - 1)) // n)
        r_max = ((b*s - 2*B) // n)
        if r_min > r_max:
            debug_msg("    r_num     = [{0}] -> ({1}, {2})".format(0, r_min, r_max))
            continue
        debug_msg("    r_num     = [{0}] -> ({1}, {2})".format(r_max - r_min + 1, r_min, r_max))
        for r in range(r_min, r_max + 1):
            aa = ((2*B + r*n + (s - 1)) // s)
            bb = ((3*B - 1 + r*n) // s)
            newa = max(a, aa)
            newb = min(b, bb)
            if newa <= newb:
                newM |= set([(newa, newb)])
    M = newM
    ints_out = len(M)
    debug_msg("    intervals = [{0}] -> [{1}]".format(ints_in, ints_out))
    return M

# Attack: The main function controlling the attack.
def execute_break_rsa(data_captured, bitsize):
    """Execute the ciphertext breaking as described by the challenge."""

    out_msg = None
    duration = 0

    # Get the data captured by the attacker.
    (pub, c0) = data_captured
    (e, n) = pub

    # Break the message.

    # The "Bleichenbacher from CRYPTO '98" paper described in the
    # challenge's statement contains all the info required for
    # implementing the attack. A pdf version of the paper was
    # obtained from:
    #  + http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
    #
    # There's a lot of literature on the web explaining the math
    # behind the attack. Such an example can be found on:
    #  + http://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html

    print("-" * 60)
    print("Breaking the message...")
    tstart = int(time.time())

    # Compute 'B = 2^(k - 16)', where 'k' is the key modulus
    # bit size, given to use by 'bitsize'.
    k = bitsize
    B = pow(2, k - 16)
    debug_msg("-" * 60)
    debug_msg("Initialization:")
    debug_msg("  k           = [{0}]".format(k))
    debug_msg("  k-16        = [{0}]".format(k-16))
    debug_msg("  B=2^(k-16)  = [{0}]".format(hex(B)))
    debug_msg("  2B          = [{0}]".format(hex(2*B)))
    debug_msg("  3B-1        = [{0}]".format(hex(3*B - 1)))

    # Step 1: Blinding (i = 0).
    #  We already have a conforming ciphertext, so we use 's0 = 1'.
    #  The initial set of intervals contains only one interval '[a, b]',
    #  which is '[2B, 3B-1]'.
    s0 = 1
    a = 2*B
    b = 3*B - 1
    M = set([(a, b)])

    # The following code has been modeled to reflect the structure and
    # algorithm described in the paper.

    i = 1
    s = s0
    # Main loop for narrowing down 'M' to have just one single interval
    # '[a, b]' with 'a = b'.
    while True:
        num_ints = len(M)

        # Show current state.
        debug_msg("-" * 60)
        debug_msg("Iteration {0}:".format(i))
        debug_msg("  s(i-1)      = [{0}]".format(s))
        debug_msg("  M(i-1): {0} Intervals:".format(num_ints))
        dump_intervals(M)

        # Step 2: Searching for PKCS conforming messages.
        debug_msg("  " + "-" * 58)
        debug_msg("  Finding next si...")
        s = find_si_next(pub, c0, bitsize, B, i, s, num_ints, M)
        debug_msg("  Finding next si...done")

        # Step 3: Narrowing the set of solutions.
        debug_msg("  " + "-" * 58)
        debug_msg("  Recalculating intervals...")
        M = find_mi_next(pub, B, s, M)
        debug_msg("  Recalculating intervals...done")

        # Show updated state.
        num_ints = len(M)
        debug_msg("  " + "-" * 58)
        debug_msg("  s(i)        = [{0}]".format(s))
        debug_msg("  M(i): {0} Intervals:".format(num_ints))
        dump_intervals(M)

        # Check if the narrowing is complete.
        debug_msg("  " + "-" * 58)
        if num_ints == 1:
            (a, b) = M.copy().pop()
            if a == b:
                m0 = a
                debug_msg("  m0 found    = [{0}]".format(hex(m0)))
                break
        debug_msg("  m0 not found yet")
        i += 1

    tend = int(time.time())
    duration = tend - tstart
    print("-" * 60)
    print("Breaking the message...done ({0} seconds)".format(duration))

    # Step 4: Computing the solution.

    # Calculate the padded message.
    m_pad = (m0 * utils.invmod(s0, n)) % n
    m_pad_b = bytes_from_int(m_pad, bitsize // 8)
    # Do the PKCS#1 v1.5 unpadding.
    (unpad_ok, prefix_ok, m_b) = pkcs1_15_unpad(m_pad_b, bitsize)
    # Do some sanity checks.
    if not prefix_ok:
        print("-" * 60)
        print("ERROR: PKCS#1 v1.5 unpadding failed: prefix")
        print("-" * 60)
        return (None, 0, 0)
    if not unpad_ok:
        print("-" * 60)
        print("ERROR: PKCS#1 v1.5 unpadding failed: unpad")
        print("-" * 60)
        return (None, 0, 0)
    # Decode the message.
    out_msg = utils.bytes2rawstr(m_b)
    debug_msg("-" * 60)
    debug_msg("m_pad         = [{0}]".format(hex(m_pad)))
    debug_msg("m_pad_b       = [{0}]".format(m_pad_b))
    debug_msg("m_pad_b(h)    = [{0}]".format(m_pad_b.hex()))
    debug_msg("out_msg       = [{0}]".format(out_msg))

    print("-" * 60)
    return (out_msg, duration, i)

def main(me, title, in_bitsize, in_msg):
    try:
        out_msg_ok = in_msg
        out_msg = None
        duration = 0
        (capture_ok, data_captured) = execute_capture_data(in_msg, in_bitsize)
        if capture_ok:
            (out_msg, duration, iterations) = execute_break_rsa(data_captured, in_bitsize)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_bitsize  = [{1}]".format(me, in_bitsize))
        print("{0}: in_msg      = [{1}]".format(me, in_msg))
        print("{0}: capture_ok  = [{1}]".format(me, capture_ok))
        print("{0}: out_msg     = [{1}]".format(me, out_msg))
        print("{0}: duration    = [{1} seconds]".format(me, duration))
        print("{0}: iterations  = [{1}]".format(me, iterations))
        print("{0}: out_msg_ok  = [{1}]".format(me, out_msg_ok))
        ok = (out_msg == out_msg_ok)
        if not ok:
            err_str = "\n{0}: ".format(me) + "-" * 60
            err_str += "\n{0}: TEST        = [FAILED] Result doesn't match expected.".format(me)
            err_str += "\n{0}: ".format(me) + "-" * 60
            raise Exception(err_str)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: TEST        = [OK]".format(me))
        print("{0}: ".format(me) + "-" * 60)
    except Exception:
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Caught ERROR EXCEPTION:".format(me))
        raise
    except:
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Caught UNEXPECTED EXCEPTION:".format(me))
        raise

if __name__ == '__main__':
    me = sys.argv[0]
    in_bitsize = 256
    in_msg = "kick it, CC"
    main(me, title, in_bitsize, in_msg)
    sys.exit(0)


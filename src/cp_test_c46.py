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

"""Cryptopals Challenges: Test Challenge 46: RSA parity oracle."""

import sys
import utils.cp_aux_utils as utils
import time

title = "Challenge 46: RSA parity oracle"

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

def int_from_bytes(m_b):
    """Transforms a byte array message to an integer."""
    m = int(m_b.hex(), 16)
    return m

def bytes_from_int(m):
    """Transforms an integer message to a byte array message."""
    m_b = m.to_bytes((m.bit_length() + 7) // 8, 'big')
    return m_b

def decryption_oracle(c, bitsize):
    """The decryption oracle as described in the challenge."""

    global prv
    global pub

    # Generate the RSA keys.
    if prv is None:
        print("-" * 60)
        print("Generate RSA keys (decrypt):")
        (prv, pub) = utils.rsa_genkeys(bitsize)
        (d, n) = prv
        (e, n) = pub
        debug_msg("  d           = [{0}]".format(d))
        debug_msg("  e           = [{0}]".format(e))
        debug_msg("  n           = [{0}]".format(n))

    # Decrypt.
    m = utils.rsa_num_decrypt(prv, c)

    # Just return if the plaintext is even.
    return (m & 0x1) == 0

def execute_capture_data(msg_b64_str, bitsize):
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
        print("Generate RSA keys (execute):")
        (prv, pub) = utils.rsa_genkeys(bitsize)
        (d, n) = prv
        (e, n) = pub
        debug_msg("  d           = [{0}]".format(d))
        debug_msg("  e           = [{0}]".format(e))
        debug_msg("  n           = [{0}]".format(n))

    # Encrypt the message.
    msg_b64_b = utils.rawstr2bytes(msg_b64_str)
    m_b = utils.base64bytes2bytes(msg_b64_b)
    m = int_from_bytes(m_b)
    c = utils.rsa_num_encrypt(pub, m)
    debug_msg("-" * 60)
    debug_msg("Encrypt:")
    debug_msg("  msg_b64_str = [{0}]".format(msg_b64_str))
    debug_msg("  msg_b64_b   = [{0}]".format(msg_b64_b))
    debug_msg("  m_b         = [{0}]".format(m_b.hex()))
    debug_msg("  m           = [{0}]".format(m))
    debug_msg("  c           = [{0}]".format(c))

    data_captured = (pub, c)
    return data_captured

def execute_break_rsa(data_captured, bitsize):
    """Execute the ciphertext breaking as described by the challenge."""

    global prv
    global pub

    out_msg = None
    duration = 0

    # Get the data captured by the attacker.
    (pub, c) = data_captured
    (e, n) = pub

    print("-" * 60)
    print("Breaking the message...")
    print("-" * 60)

    # Break the message.
    # Implementing the breaking attack as described in the
    # challenge's statement.
    #
    # The range for message 'm' is initially '0 < m <= n'.
    # Each iteration will reduce the range in half:
    #  + If parity is even it's the higher limit that decreases.
    #  + If parity is odd it's the lower limit that increases.
    # The message 'm' will be discovered when 'low < m <= high'
    # with 'high - low' = 1, which will happen after 'n.bit_length()'
    # (or 'log2(n)') iterations at most.
    # The message will then be 'm = high'.
    #
    # To avoid rounding errors, we'll maintain both the current
    # 'low' and 'high' limits as fractions of 'n', storing the
    # numerator for each and the common denominator.
    # So, the lower limit is 'n * low / den' and the higher limit
    # is 'n * high / den', starting with 'low = 0', 'high = 1' and
    # 'den = 1', so that '0 < m <= n'.
    #
    # Now, what's the rationale behind this?
    #
    # Besides the explanations given in the challenge's statement,
    # there's some useful informal info in:
    #  + http://crypto.stackexchange.com/questions/11053/rsa-least-significant-bit-oracle-attack
    #
    # There's a full and detailed mathematical explanation in an
    # article named "Stronger Security Proofs for RSA and Rabin bits"
    # by Fischlin and Schnorr. A PDF version is available by googling:
    #  + https://www.google.pt/#q=stronger+security+proofs+for+rsa+and+rabin+bits+pdf&*
    #
    # Let's show some iterations to understand what happens.
    # We start with plaintext 'm' which is known to be '0 < m <= n'.
    # Our current 'm' is the quantity we know to be less than 'n'.
    # We can double it and check the resulting parity, which gives
    # us the information if '2*m <= n' (even parity) or if '2*m > n'
    # (odd parity). From that info, we can derive the new limits for
    # 'm' in each iteration.
    #
    # 1st Iteration (try 2*m):
    #  even: 2m <= n <=> m <= n/2, so we have:
    #  0n/2 < m <= 1n/2 <=>
    #  --------------------
    #  0 < m <= n/2
    #  --------------------
    #
    # 2nd Iteration (try 2*2*m = 4m):
    #  even: 4m <= n <=> m <= n/4, so we have:
    #  0n/4 < m <= 1n/4 <=>
    #  --------------------
    #  0 < m <= n/4
    #  --------------------
    #
    # 3rd Iteration (try 2*2*2*m = 8m):
    #  odd: 8m > n <=> m > n/8, so we have:
    #  1n/8 < m <= 2n/8 <=>
    #  --------------------
    #  n/8 < m <= n/4
    #  --------------------
    #  This is the 1st time we get an odd parity, which means
    #  the '8m' product wrapped the modulo 'n'. We will continue
    #  doubling, but on the next calculations, the current quantity
    #  that is less than 'n' is now no longer the original 'm', but
    #  instead '8m-n', because '8m' just wrapped over 'n'.
    #  This is actually a "carry" between operations, so our current
    #  "carry" (which initially was 'm') just became 'cy = 8m-n'.
    #  The next doubling will be on this quantity.
    #  A new "carry" needs to be recalculated whenever the parity is
    #  odd.
    #
    # 4th Iteration (try 2*cy = 2(8m-n)):
    #  even: 2(8m-n) <= n <=> 16m-2n <= n <=> m <= 3n/16, so we have:
    #  2n/16 < m <= 3n/16 <=>
    #  --------------------
    #  n/8 < m <= 3n/16
    #  --------------------
    #
    # 5th Iteration (try 2*2*cy = 4(8m-n)):
    #  even: 4(8m-n) <= n <=> 32m-4n <= n <=> m <= 5n/32, so we have:
    #  4n/32 < m <= 5n/32 <=>
    #  --------------------
    #  n/8 < m <= 5n/32
    #  --------------------
    #
    # 6th Iteration (try 2*2*2*cy = 8(8m-n)):
    #  odd: 8(8m-n) <= n <=> 64m-8n > n <=> m > 9n/64, so we have:
    #  9n/64 < m <= 10n/64 <=>
    #  --------------------
    #  9n/64 < m <= 5n/32
    #  --------------------
    #  And a new 'cy = 64m-8n-n = 64m -9n'
    #
    # 7th Iteration (try 2*cy = 2(64m-9n)):
    #  even: 2(64m-9n) <= n <=> 128m-18n <= n <=> m <= 19n/128, so we have:
    #  18n/128 < m <= 19n/128 <=>
    #  --------------------
    #  9n/64 < m <= 19n/128
    #  --------------------
    #
    # Continuing with the iterations, after at most 'n.bit_length()'
    # (same as 'log2(n)') iterations, we'll reach a case where
    # '(x-1) < m <= x', which means 'm = x'.
    # By the example above, it's also noticeable how the current
    # range delimiting 'm' is reduced to half in every iteration, as
    # a result of doubling the current "carry".
    #
    # In the example above, by looking at the lower and higher limits
    # as 'n*low/den' and 'n*high/den', i.e., fractions of 'n' with the
    # same denominator, and how they evolve in each iteration, becomes
    # easier to understand the implementation below. Both the numerators
    # and the common denominator are duplicated in each iteration, placing
    # the current range limits in the denominator required for representing
    # the new halved range. Then, depending on the parity, either the
    # higher limit numerator is decreased to the middle point of the
    # current range (even parity) or the lower limit numerator is increased
    # to the same middle point (odd parity), again, confirming the range
    # being decreased to half the previous range.

    # Current lower limit numerator.
    low = 0
    # Current higher limit numerator.
    high = 1
    # Current common denominator.
    den = 1
    # Current ciphertext.
    cd = c
    # Factor to apply to the current ciphertext to get a doubled
    # plaintext message.
    double = pow(2, e, n)
    # Iterations counter.
    cnt = 0
    # Current absolute values of lower and higher message limits.
    m_low = (n * low // den)
    m_high = (n * high // den)
    # We find 'm' when the limits difference is 1.
    # This must happen within at most 'n.bit_length()' (same as
    # 'log2(n)') iterations, because each iteration reduces the range
    # to half. Depending on the value of 'n', the number of iterations
    # will be either 'n.bit_length()' or 'n.bit_length() - 1'.
    tstart = int(time.time())
    while (m_high - m_low) > 1:
        # Force the doubling of the previous plaintext message.
        cd = (cd * double) % n
        # Check the parity of the doubled plaintext message.
        even = decryption_oracle(cd, bitsize)

        # Adjust the message range according to the parity results:
        #  + Even: Decrease higher limit so that range is halved, i.e,
        #    'high_new = high - (high - low) / 2 = (low + high) / 2'.
        #  + Odd: Reduce higher limit so that range is halved, i.e.
        #    'low_new = low + (high - low) / 2 = (low + high) / 2'.
        # As mentioned, to avoid rounding errors, we keep the 'low' and
        # 'high' limits as fractions of 'n' for which we store the
        # numerator and denominator.

        # Range is halved => Denominator is doubled.
        den *= 2
        # Adjust current 'low' and 'high' to the new 'den'.
        low *= 2
        high *= 2
        # Either the new lower limit or new higher limit is
        # moved to the middle point between their current values,
        # so that the range is halved.
        new_half = (low + high) // 2
        # Adjust either 'high' or 'low' depending on parity (even or odd).
        if even:
            high = new_half
        else:
            low = new_half
        m_low = (n * low // den)
        m_high = (n * high // den)

        # Did another iteration.
        cnt += 1
        debug_msg("-" * 60)
        debug_msg("Iteration {0}:".format(cnt))
        debug_msg("  cd          = [{0}]".format(cd))
        debug_msg("  even        = [{0}]".format(even))
        debug_msg("  range_min   = [{0}]".format(m_low))
        debug_msg("  range_max   = [{0}]".format(m_high))
        debug_msg("  distance    = [{0}]".format(m_high - m_low))
        debug_msg("  range_low   = [{0}]".format(low))
        debug_msg("  range_high  = [{0}]".format(high))
        debug_msg("  range_den   = [{0}]".format(den))
        tmp_msg_b = bytes_from_int(m_high)
        print("{0}".format(tmp_msg_b))

    tend = int(time.time())
    duration = tend - tstart
    print("-" * 60)
    print("Breaking the message...done ({0} seconds)".format(duration))

    # Sanity checks.
    if (m_high - m_low) != 1:
        print("-" * 60)
        print("ERROR: (m_high - m_low) != 1")
        print("-" * 60)
        return (out_msg, duration)
    if cnt > n.bit_length():
        print("-" * 60)
        print("ERROR: cnt = {0} != n.bit_length = {1}".format(cnt, n.bit_length()))
        print("-" * 60)
        return (out_msg, duration)

    # Decode the message.
    m = m_high
    out_msg_b = bytes_from_int(m)
    out_msg = utils.bytes2rawstr(out_msg_b)
    debug_msg("-" * 60)
    debug_msg("m             = [{0}]".format(m))
    debug_msg("out_msg       = [{0}]".format(out_msg))

    print("-" * 60)
    return (out_msg, duration)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_bitsize = 1024
        in_msg_b64 = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
        out_msg_ok = "That's why I found you don't play around with the Funky Cold Medina"
        data_captured = execute_capture_data(in_msg_b64, in_bitsize)
        (out_msg, duration) = execute_break_rsa(data_captured, in_bitsize)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_bitsize  = [{1}]".format(me, in_bitsize))
        print("{0}: in_msg_b64  = [{1}]".format(me, in_msg_b64))
        print("{0}: out_msg     = [{1}]".format(me, out_msg))
        print("{0}: duration    = [{1} seconds]".format(me, duration))
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

    sys.exit(0)


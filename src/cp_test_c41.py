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

"""Cryptopals Challenges: Test Challenge 41: Implement unpadded message recovery oracle."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 41: Implement unpadded message recovery oracle"

# Ciphertext hashes already seen by the oracle.
c_hashes = set()
# RSA keys used by the decryption oracle.
bitsize = 512
(prv, pub) = (None, None)

# Debug flag.
debug = 0

# Debug messages.
def debug_msg(*args, **kwargs):
    """Extra debug messages."""
    if not debug:
        return
    print(*args, **kwargs)

def decryption_oracle(c):
    """The decryption oracle as described in the challenge."""

    global prv
    global pub

    # Generate the RSA keys.
    if prv is None:
        (prv, pub) = utils.rsa_genkeys(bitsize)
        debug_msg("decryption_oracle: prv:", prv)
        debug_msg("decryption_oracle: pub:", pub)

    # Only decrypts the ciphertext if not done already.
    debug_msg("decryption_oracle: c:", c)
    c_b = c.to_bytes((c.bit_length() + 7) // 8, 'big')
    c_hash = utils.sha256_mac(b'', c_b)
    debug_msg("decryption_oracle: c_hash:", len(c_hash), c_hash.hex())
    if c_hash in c_hashes:
        debug_msg("decryption_oracle: ciphertext already processed")
        return None

    # Decrypt.
    m = utils.rsa_num_decrypt(prv, c)
    debug_msg("decryption_oracle: m:", m)

    # Remember this ciphertext was already decrypted by storing its hash.
    c_hashes.add(c_hash)

    return m

def execute_capture_data(msg):
    """Simulates the data capturing required for breaking the message."""

    global prv
    global pub

    # The attacker has captured the ciphertext for the message which he wants to break.
    # It also has the RSA public key.

    # Generate the RSA keys.
    if prv is None:
        (prv, pub) = utils.rsa_genkeys(bitsize)
        debug_msg("execute_capture_data: prv:", prv)
        debug_msg("execute_capture_data: pub:", pub)

    # Encrypt.
    debug_msg("execute_capture_data: msg:", msg)
    m = int(utils.rawstr2bytes(msg).hex(), 16)
    debug_msg("execute_capture_data: m:", m)
    c = utils.rsa_num_encrypt(pub, m)
    debug_msg("execute_capture_data: c:", c)

    # Request decryption to oracle so that 'c' cannot be decrypted again by
    # the attacker.
    m2 = decryption_oracle(c)
    debug_msg("execute_capture_data: m2:", m2)
    if m2 != m:
        raise Exception("capture_data: Decryption oracle returned invalid plaintext")

    return (pub, c)

def execute_break_rsa(data_captured):
    """Execute the RSA attack described in the challenge."""

    # The data captured is the RSA public key and the ciphertext we want to break
    # by using the decryption oracle.

    # "Capture the ciphertext C".
    (pub, c) = data_captured
    debug_msg("execute_break_rsa: c:", c)

    # Confirm that we cannot simply request the oracle to decrypt the captured
    # ciphertext, because it remembers that it has already done it and will
    # refuse to decrypt it again.
    m = decryption_oracle(c)
    debug_msg("execute_break_rsa: m:", m)
    if m != None:
        raise Exception("break_rsa: Decryption oracle decrypted captured ciphertext")

    # "Let N and E be the public modulus and exponent respectively".
    (e, n) = pub
    debug_msg("execute_break_rsa: e:", e)
    debug_msg("execute_break_rsa: n:", n)
    # "Let S be a random number > 1 mod N. Doesn't matter what.".
    s = utils.rand_int(2, n - 1)
    debug_msg("execute_break_rsa: s:", s)
    # "Now: C' = ((S**E mod N) C) mod N". C' is c2.
    c2 = (pow(s, e, n) * c) % n
    debug_msg("execute_break_rsa: c2:", c2)
    # "Submit C' (c2), which appears totally different from C, to the server,
    # recovering P' (m2), which appears totally different from P (m)".
    m2 = decryption_oracle(c2)
    debug_msg("execute_break_rsa: m2:", m2)
    # "Now: P(m) = (P'(m2) / S) mod N".
    # "Remember: you don't simply divide mod N; you multiply by the
    # multiplicative inverse mod N. So you'll need a modinv() function.".
    # Explanation why P can be recovered from P':
    #  + It's all about math.
    #  + http://crypto.stackexchange.com/questions/18631/chosen-plaintext-attack-on-textbook-rsa-decryption.
    #  + Quick summary:
    #     pub: (e, n)
    #     prv: (d, n)
    #     c = m^e % n
    #     m = c^d % n
    #     c2 = (c * s^e) % n                            =>
    #      m2 = c2^d % n                                <=>
    #      m2 = ((c * s^e) % n)^d % n                   <=>
    #      m2 = ((c^d % n) * ((s^e % n)^d % n)) % n
    #       Note that '((s^e % n)^d % n))' is 's' encrypted, then decrypted again,
    #       resulting in 's'                            <=>
    #      m2 = (m * s) % n                             <=>
    #      m = (m2 * s^-1) % n
    m = (m2 * utils.invmod(s, n)) % n
    debug_msg("execute_break_rsa: m:", m)
    msg = utils.bytes2rawstr(m.to_bytes((m.bit_length() + 7) // 8, 'big'))
    debug_msg("execute_break_rsa: msg:", msg)

    return msg

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_msg = "Sample test message to be cracked"
        data_captured = execute_capture_data(in_msg)
        out_msg = execute_break_rsa(data_captured)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_msg   = [{1}]".format(me, in_msg))
        print("{0}: bitsize  = [{1}]".format(me, bitsize))
        print("{0}: out_msg  = [{1}]".format(me, out_msg))
        ok = (out_msg == in_msg)
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


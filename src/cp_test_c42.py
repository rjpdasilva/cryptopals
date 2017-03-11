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

"""Cryptopals Challenges: Test Challenge 42: Bleichenbacher's e=3 RSA Attack."""

import sys
import utils.cp_aux_utils as utils
import re

title = "Challenge 42: Bleichenbacher's e=3 RSA Attack"

# Debug flag.
debug = 0

# Debug messages.
def debug_msg(*args, **kwargs):
    """Extra debug messages."""
    if not debug:
        return
    print(*args, **kwargs)

def gen_keys(bitsize):
    """Generate a RSA key pair."""

    debug_msg("-" * 60)
    debug_msg("gen_keys: Generating...")
    # Create a RSA public/private key pair.
    (prv, pub) = utils.rsa_genkeys(bitsize)
    debug_msg("gen_keys: Generating...done")
    (e, n) = pub
    debug_msg("gen_keys: n              :", n)
    return (prv, pub)

def sign_real(prv, msg, bitsize):
    """Perform real message signing."""

    debug_msg("-" * 60)

    # Get message hash.
    m_b = utils.rawstr2bytes(msg)
    h_b = utils.sha1_mac(b'', m_b)
    debug_msg("sign_real: msg           :", len(msg), msg)
    debug_msg("sign_real: m_b           :", len(m_b), m_b)
    debug_msg("sign_real: h_b           :", len(h_b), h_b.hex())

    # Do the PKCS#1 v1.5 padding.
    # Note: The ASN.1 part of the padding is ignored for this
    # challenge purpose. The idea behind it and results are
    # the same with or without ASN.1.
    pad_h_b = b'\x00\x01' + (b'\xff' * ((bitsize // 8) - len(h_b) - 3)) + b'\x00' + h_b
    debug_msg("sign_real: pad_h_b       :", len(pad_h_b), pad_h_b.hex())
    assert len(pad_h_b) == (bitsize // 8)

    # Sign.
    pad_h = int(pad_h_b.hex(), 16)
    debug_msg("sign_real: pad_h         :", pad_h)
    # Calling decrypt function because signing is done
    # by crypting with private key.
    sig = utils.rsa_num_decrypt(prv, pad_h)
    sig_b = sig.to_bytes((sig.bit_length() + 7) // 8, 'big')
    debug_msg("sign_real: sig           :", sig)
    debug_msg("sign_real: sig_b         :", len(sig_b), sig_b.hex())

    return sig_b

def sign_forge(msg, bitsize):
    """Implement the signature forging algorithm described by the challenge."""

    # "How to find such a block? Find a number that when cubed (a) doesn't
    # wrap the modulus (thus bypassing the key entirely) and (b) produces a
    # block that starts "00h 01h ffh ... 00h ASN.1 HASH"."
    #
    # "You can implement an integer cube root in your language, format the
    # message block you want to forge, leaving sufficient trailing zeros at
    # the end to fill with garbage, then take the cube-root of that block."

    # Besides the attack's explanation done by the challenge's statement,
    # more detailed information can be found in:
    #  + https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html.
    #  + https://blog.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/.

    debug_msg("-" * 60)

    # Get message hash.
    m_b = utils.rawstr2bytes(msg)
    h_b = utils.sha1_mac(b'', m_b)
    debug_msg("sign_forge: msg          :", len(msg), msg)
    debug_msg("sign_forge: m_b          :", len(m_b), m_b)
    debug_msg("sign_forge: h_b          :", len(h_b), h_b.hex())

    # Do the invalid PKCS#1 v1.5-like padding.
    # The padding is invalid because there's no enough
    # '0xff' padding bytes on it, but the signature
    # verifying function doesn't detect that and considers
    # it as valid.
    pad_h_b = b'\x00\x01\xff\x00' + h_b + (b'\x00' * ((bitsize // 8) - len(h_b) - 4))
    assert len(pad_h_b) == (bitsize // 8)
    pad_h = int(pad_h_b.hex(), 16)
    debug_msg("sign_forge: pad_h_b      :", len(pad_h_b), pad_h_b.hex())
    debug_msg("sign_forge: pad_h        :", pad_h)

    # Get the cubic root of the padded hash.
    # Since 'e = 3' by definition on the challenge and 'pad_h'
    # is small enough so that it's cube is lower than 'n', then
    # the signature decryption done by the verifying function
    # will be simply doing 'sig ^ 3', so if we want to forge
    # a valid signature we need to use as 'sig' the cubic root
    # of 'pad_h'.
    sig = utils.nth_root(pad_h, 3)

    # The 'nth_root' function calculates the integer 'nth' root
    # of a number (here 'n = 3') and returns the highest integer
    # that, when powered to 'n' doesn't exceed the number. This
    # way, we need to add '1' to the result, otherwise, when this
    # signature gets decrypted (cubed), the result won't match
    # the 'pad_h' calculated here. Note that 'pad_h' was padded
    # with trailing zeros, so if the cube root returns the
    # highest integer that powered to 3 doesn't exceed the number,
    # then for sure the 'h_b' of part of the decrypted signature
    # will be decreased, so that's why we add 1 here. By adding
    # 1, the decrypted signature 'pad_h' result will be greater
    # than the 'pad_h' calculated here, but that's not a problem
    # as long as the difference is less "fits" in the number of
    # trailing zeros we used for 'pad_h' (the "garbage" part
    # described in the challenge's statement), in which case it
    # won't affect the 'h_b' part, which is what we want to forge.
    # Alternatively, we could have used '0xff' bytes for padding
    # and take the cubic root as is, without adding 1.
    sig += 1

    sig_b = sig.to_bytes((sig.bit_length() + 7) // 8, 'big')
    debug_msg("sign_real: sig           :", sig)
    debug_msg("sign_real: sig_b         :", len(sig_b), sig_b.hex())

    return sig_b

def sign_verify(pub, msg, sig_b):
    """verify signature."""

    # This is the function that has the implementation fault
    # allowing the attack: It doesn't properly check the
    # PKCS#1 v1.5 padding by not verifying that all the padding
    # is present, but simply by parsing the decrypted signature
    # for getting the hash.

    debug_msg("-" * 60)
    debug_msg("sign_verify: sig_b       :", len(sig_b), sig_b.hex())

    # Decrypt the signature and extract the hash.
    sig = int(sig_b.hex(), 16)
    debug_msg("sign_verify: sig         :", sig)
    # Calling encrypt function because decrypting the signature
    # is done by crypting with public key.
    pad_h = utils.rsa_num_encrypt(pub, sig)
    debug_msg("sign_verify: pad_h       :", pad_h)
    # Need to prefix with '0x00' because the real signing padded
    # hash always starts with '0x00', and that '0x00' is gone
    # when it's converted to an integer before applying the crypt
    # on it.
    pad_h_b = b'\x00' + pad_h.to_bytes((pad_h.bit_length() + 7) // 8, 'big')
    debug_msg("sign_verify: pad_h_b     :", len(pad_h_b), pad_h_b.hex())
    # Use a regex to extract the hash out.
    regex = re.compile(b'\x00\x01\xff+?\x00(.{20})', re.DOTALL)
    match = regex.match(pad_h_b)
    if not match:
        return False
    h_b = match.group(1)
    debug_msg("sign_verify: h_b         :", len(h_b), h_b.hex())

    # Now, do our own hash calculation on the message.
    m_b = utils.rawstr2bytes(msg)
    calc_h_b = utils.sha1_mac(b'', m_b)
    debug_msg("sign_verify: m_b         :", len(m_b), m_b.hex())
    debug_msg("sign_verify: calc_h_b    :", len(calc_h_b), calc_h_b.hex())

    ok = (calc_h_b == h_b)
    debug_msg("sign_verify: ok          :", ok)
    return ok

def execute_forge_signature(msg, bitsize):
    """Control the signature forging test."""

    # Generate the RSA key pair being used.
    (prv, pub) = gen_keys(bitsize)

    # Do the real signing.
    sig_real_b = sign_real(prv, msg, bitsize)
    # Verify the real signature.
    sig_real_ok = sign_verify(pub, msg, sig_real_b)

    # Do the forged signing.
    sig_forged_b = sign_forge(msg, bitsize)
    sig_forged_ok = sign_verify(pub, msg, sig_forged_b)

    debug_msg("-" * 60)
    debug_msg("execute: sig_real_b      :", len(sig_real_b), sig_real_b.hex())
    debug_msg("execute: sig_real_ok     :", sig_real_ok)
    debug_msg("execute: sig_forged_b    :", len(sig_forged_b), sig_forged_b.hex())
    debug_msg("execute: sig_forged_ok   :", sig_forged_ok)
    debug_msg("-" * 60)

    return (sig_real_b, sig_real_ok, sig_forged_b, sig_forged_ok)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_msg = "hi mom"
        in_bitsize = 1024
        (sig_r, sig_r_ok, sig_f, sig_f_ok) = execute_forge_signature(in_msg, in_bitsize)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_msg      = [{1}]".format(me, in_msg))
        print("{0}: in_bitsize  = [{1}]".format(me, in_bitsize))
        print("{0}: sig_real    = [{1}] {2}".format(me, "OK" if sig_r_ok else "FAIL", sig_r.hex()))
        print("{0}: sig_forged  = [{1}] {2}".format(me, "OK" if sig_f_ok else "FAIL", sig_f.hex()))
        ok = (sig_r_ok and sig_f_ok)
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


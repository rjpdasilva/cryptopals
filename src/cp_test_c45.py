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

"""Cryptopals Challenges: Test Challenge 45: DSA parameter tampering."""

import sys
import utils.cp_aux_utils as utils
import cp_test_c43 as c43

title = "Challenge 45: DSA parameter tampering"

def execute_test_tampered_g(p, q, g, msg1, msg2):
    """Make challenge required tests with tampered 'g' parameter."""

    # This function is being tested with 2 different tampered 'g' values:
    #  (1) 'g = 0'
    #  (2) 'g = p + 1'
    # Let's see what happens for both cases.
    #
    # ---------------
    # (1) 'g = 0'
    # ---------------
    # The key generation will cause:
    #  'y = g^x % p' <=> 'y = 0^x % p' <=>
    #  'y = 0'
    # As for signing, we'll have:
    #  'r = (g^k % p) % q' <=> 'r = (0^k % p) % q' <=>
    #  'r = 0'
    # Finally, for signature verification, we get:
    #  'v = ((g^u1 * y^u2) % p) % q' <=> 'v = ((0^u1 * 0^u2) % p) % q' <=>
    #  'v = 0'
    # So, 'g = 0' unconditionally forces 'y', 'r' and 'v' to also be '0',
    # independently of all other variables.
    # Since the signature is considered valid when 'v == r' and both are
    # being forced to '0', then *ANY* signature '(r, s)' having 'r = 0'
    # will be considered valid!
    # To note that the standard DSA sign and verify functions will
    # reject signing/verifying when 'r = 0' and/or 's = 0. The initial
    # implementation of our 'dsa_sign()' and 'dsa_verify()' functions
    # did it as well. They were extended with a bool 'strict' parameter
    # (defaulting to 'True') to allow bypassing those tests for this
    # challenge's purpose.
    #
    # ---------------
    # (2) 'g = p + 1'
    # ---------------
    # Same kind of exploit as in (1), but in this case, it forces the
    # parameters to '1' instead of '0'.
    # Key generation:
    #  'y = g^x % p' <=> 'y = (p + 1)^x % p' <=>
    #  'y = 1'
    # Note that '(p + 1)^x' will always a sum of 'p' products plus '1',
    # no matter what the 'x' is. The 'p' modulo of 'p' products is always
    # '0', so only the '1' remains, which modulo 'p' gives 1.
    # Signing:
    #  'r = (g^k % p) % q' <=> 'r = ((p + 1)^k % p) % q' <=>
    #  'r = 1'
    # Signature verification:
    #  'v = ((g^u1 * y^u2) % p) % q' <=> 'v = (((p + 1)^u1 * 1^u2) % p) % q' <=>
    #  'v = 1'
    # So, in this case, we always have 'v = r = 1', which means that
    # *ANY* signature '(r, s)' having 'r = 1' is valid!
    # To note that for 'g = p + 1', the challenge statement throws some
    # formulas to generate a magic signature, for any arbitrary 'z':
    #  'r = ((y**z) % p) % q'
    #  's = (r / z) % q'
    # Not sure the purpose, but again we can see that 'r' will always be
    # '1' because 'y' is always '1', so this gives 's = (1 / z) % q', for
    # any 'z', which is basically the same as saying that 's' can be
    # anything, as it was already concluded above.

    ok = False
    forced_val = g % p
    print("-" * 60)
    print("Params:")
    print("  p          = [{0}]".format(p))
    print("  q          = [{0}]".format(q))
    print("  g          = [{0}]".format(g))
    print("  forced_val = [{0}]".format(forced_val))
    print("  msg1       = [{0}]".format(msg1))
    print("  msg2       = [{0}]".format(msg2))

    # Generate the DSA key pair.
    (prv, pub) = utils.dsa_genkeys(1024, 160, p, q, g)
    x = prv
    (_, _, _, y) = pub
    print("-" * 60)
    print("DSA Keys:")
    print("  x          = [{0}]".format(x))
    print("  y          = [{0}]".format(y))
    if y != forced_val:
        print("-" * 60)
        print("ERROR: y = [{0}] and should be [{1}]".format(y, forced_val))
        print("-" * 60)
        return ok

    # Sign the messages.
    m1 = c43.hash_msg_as_int(msg1)
    m2 = c43.hash_msg_as_int(msg2)
    # Do no use strict signing when we're forcing 'r' value to zero.
    (r1, s1) = utils.dsa_sign(m1, prv, pub, forced_val != 0)
    if r1 != forced_val:
        print("-" * 60)
        print("ERROR: r1 = [{0}] and should be [{1}]".format(r1, forced_val))
        print("-" * 60)
        return ok
    (r2, s2) = utils.dsa_sign(m2, prv, pub, forced_val != 0)
    if r2 != forced_val:
        print("-" * 60)
        print("ERROR: r2 = [{0}] and should be [{1}]".format(r2, forced_val))
        print("-" * 60)
        return ok
    print("-" * 60)
    print("DSA Signing:")
    print("  msg1       = [{0}]".format(msg1))
    print("    m1       = [{0}]".format(m1))
    print("    r1       = [{0}]".format(r1))
    print("    s1       = [{0}]".format(s1))
    print("  msg2       = [{0}]".format(msg2))
    print("    m2       = [{0}]".format(m2))
    print("    r2       = [{0}]".format(r2))
    print("    s2       = [{0}]".format(s2))

    # Verify the messages using the original signatures.
    # Do no use strict verifying when we're forcing 'r' value to zero.
    ok1 = utils.dsa_verify(m1, (r1, s1), pub, forced_val != 0)
    if not ok1:
        print("-" * 60)
        print("ERROR: Signature (original) verifying on msg1 failed")
        print("-" * 60)
        return ok
    ok2 = utils.dsa_verify(m2, (r2, s2), pub, forced_val != 0)
    if not ok2:
        print("-" * 60)
        print("ERROR: Signature (original) verifying on msg2 failed")
        print("-" * 60)
        return ok
    print("-" * 60)
    print("DSA Verifying (original signatures):")
    print("  msg1       = [{0}]".format(ok1))
    print("  msg2       = [{0}]".format(ok2))

    # Verify the messages using switched signatures.
    ok1 = utils.dsa_verify(m1, (r2, s2), pub, forced_val != 0)
    if not ok1:
        print("-" * 60)
        print("ERROR: Signature (switched) verifying on msg1 failed")
        print("-" * 60)
        return ok
    ok2 = utils.dsa_verify(m2, (r1, s1), pub, forced_val != 0)
    if not ok2:
        print("-" * 60)
        print("ERROR: Signature (switched) verifying on msg2 failed")
        print("-" * 60)
        return ok
    print("-" * 60)
    print("DSA Verifying (switched signatures):")
    print("  msg1       = [{0}]".format(ok1))
    print("  msg2       = [{0}]".format(ok2))

    # Verify the messages using using random values for 's'.
    cycles = 10000
    print("-" * 60)
    print("DSA Verifying (random 's' {0} signatures):".format(cycles))
    for i in range(cycles):
        s_rand = utils.rand_int(1, q - 1)
        ok1 = utils.dsa_verify(m1, (forced_val, s_rand), pub, forced_val != 0)
        if not ok1:
            print("-" * 60)
            print("ERROR: Signature (random) verifying on msg1 failed")
            print("-" * 60)
            return ok
        ok2 = utils.dsa_verify(m2, (forced_val, s_rand), pub, forced_val != 0)
        if not ok2:
            print("-" * 60)
            print("ERROR: Signature (switched) verifying on msg2 failed")
            print("-" * 60)
            return ok
    print("  msg1       = [{0}]".format(ok1))
    print("  msg2       = [{0}]".format(ok2))
    print("  cycles     = [{0}]".format(cycles))

    ok = True
    print("-" * 60)
    return ok

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_msg1 = "Hello, world"
        in_msg2 = "Goodbye, world"
        in_p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
        in_q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
        in_g1 = 0
        in_g2 = in_p + 1
        ok1 = execute_test_tampered_g(in_p, in_q, in_g1, in_msg1, in_msg2)
        ok2 = execute_test_tampered_g(in_p, in_q, in_g2, in_msg1, in_msg2)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_p     = [{1}]".format(me, hex(in_p)))
        print("{0}: in_q     = [{1}]".format(me, hex(in_q)))
        print("{0}: in_g1    = [{1}]".format(me, hex(in_g1)))
        print("{0}: in_g2    = [{1}]".format(me, hex(in_g2)))
        print("{0}: ok1      = [{1}]".format(me, ok1))
        print("{0}: ok2      = [{1}]".format(me, ok2))
        ok = (ok1 and ok2)
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


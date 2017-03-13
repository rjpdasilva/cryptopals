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

"""Cryptopals Challenges: Test Challenge 43: DSA key recovery from nonce."""

import sys
import utils.cp_aux_utils as utils
import time

title = "Challenge 43: DSA key recovery from nonce"

# Debug flag.
debug = 0

# Debug messages.
def debug_msg(*args, **kwargs):
    """Extra debug messages."""
    if not debug:
        return
    print(*args, **kwargs)

def hash_msg_as_int(msg):
    """SHA-1 hashes the message and returns hash as integer."""
    msg_b = utils.rawstr2bytes(msg)
    h_b = utils.sha1_mac(b'', msg_b)
    h = int(h_b.hex(), 16)
    return h

def key_get_x_from_k(h, pub, sig, k):
    """Derives 'x' (prv key) for a given 'k'."""
    (_, q, _, y) = pub
    (r, s) = sig
    x = (((s * k) - h) * utils.invmod(r, q)) % q
    return x

def check_keys(prv, pub):
    """Checks if the 'prv'/'pub' key pair is DSA valid."""
    x = prv
    (p, _, g, y) = pub
    return y == pow(g, x, p)

def break_dsa_prv_key(h, pub, sig, min_k, max_k):
    """Breaks the DSA private key using the strategy described by the challenge."""

    # According to DSA, when we're signing a message using
    # a 'k' sub-key, we have (refer to 'dsa_sign_k()' in utils):
    #  's = (invmod(k, q) * (h + x * r)) % q'.
    # The above is equivalent to:
    #  'x = (((s * k) - h) * invmod(r, q)) % q'
    # which is the formula described by the challenge to break
    # the private key 'x'.
    # From the formula, the only element which is not exactly
    # known is 'k'. However, according to the challenge's statement,
    # 'k' is limited to some range, which allows us to perform
    # a brute force attack on 'k' to determine the private key 'x'.
    # We know we have the correct value for 'k' and 'x' when 'x'
    # proves to be the correct value for 'y' (pub key), because
    # in that case only will we have 'y == pow(g, x, p)'.

    print("-" * 60)
    print("Breaking prv key...")
    tstart = int(time.time())
    for k in range(min_k, max_k + 1):
        x = key_get_x_from_k(h, pub, sig, k)
        prv = x
        if check_keys(prv, pub):
            tend = int(time.time())
            tdur = tend - tstart
            print("Breaking prv key...OK:")
            print("  prv =", hex(prv))
            print("  k   =", hex(k))
            print("-" * 60)
            return (True, prv, k, tdur)

    tend = int(time.time())
    tdur = tend - tstart
    print("Breaking prv key...FAILED")
    print("-" * 60)
    return (False, None, None, tdur)

def execute_break_dsa_prv_key(msg, h, pub, sig, x_h):
    """Control and execute the DSA private key break test."""

    debug_msg("-" * 60)
    ok_h = False
    ok_h_sig = False
    ok_prv = False
    prv = None
    k = None
    dur = 0
    ok_x_h = False
    ok_sig = False

    def show_exit():
        debug_msg("exit         :")
        debug_msg(" ok_h     =", ok_h)
        debug_msg(" ok_h_sig =", ok_h_sig)
        debug_msg(" ok_prv   =", ok_prv)
        if ok_prv:
            debug_msg(" prv      =", hex(prv))
            debug_msg(" k        =", hex(k))
        debug_msg(" ok_x_h   =", ok_x_h)
        debug_msg(" ok_sig   =", ok_sig)
        debug_msg("-" * 60)

    # Confirm we reach the same message hash.
    calc_h = hash_msg_as_int(msg)
    ok_h = (calc_h == h)
    debug_msg("h            :", hex(h))
    debug_msg("calc_h       :", hex(calc_h))
    debug_msg("ok_h         :", ok_h)
    if not ok_h:
        show_exit()
        return (ok_h, ok_h_sig, ok_prv, prv, k, ok_x_h, ok_sig)
    ok_h = True

    # Confirm the hash signature is correct.
    ok_h_sig = utils.dsa_verify(h, sig, pub)
    debug_msg("ok_h_sig     :", ok_h_sig)
    if not ok_h_sig:
        show_exit()
        return (ok_h, ok_h_sig, ok_prv, prv, k, ok_x_h, ok_sig)

    # Do the brute force attack on 'k' to get the 'prv' key.
    # This is the function that actual applies the breaking
    # algorithm as described in the challenge's statement.
    min_k = 0
    max_k = 2**16 - 1
    (ok_prv, prv, k, dur) = break_dsa_prv_key(h, pub, sig, min_k, max_k)
    debug_msg("prv          :", hex(prv))
    debug_msg("k            :", hex(k))
    debug_msg("ok_prv       :", ok_prv)
    debug_msg("dur          : {0} seconds".format(dur))
    if not ok_prv:
        show_exit()
        return (ok_h, ok_h_sig, ok_prv, prv, k, ok_x_h, ok_sig)

    # Confirm the private key fingerprint (SHA-1) matches the
    # one given in the challenge ('x_h').
    prv_msg = hex(prv)[2:]
    calc_x_h = hash_msg_as_int(prv_msg)
    ok_x_h = (calc_x_h == x_h)
    debug_msg("x_h          :", hex(x_h))
    debug_msg("calc_x_h     :", hex(calc_x_h))
    debug_msg("ok_x_h       :", ok_x_h)
    if not ok_x_h:
        show_exit()
        return (ok_h, ok_h_sig, ok_prv, prv, k, ok_x_h, ok_sig)

    # Now that we have the private key, confirm that we
    # get the same signature as described in the challenge.
    # Note that the main 'dsa_sign()' function cannot be
    # used here because we need to fixate the 'k' used.
    # Using the 'dsa_sign_k()' for that purpose.
    calc_sig = utils.dsa_sign_k(h, prv, pub, k)
    ok_sig = (calc_sig == sig)
    (r, s) = sig
    (calc_r, calc_s) = calc_sig
    debug_msg("r            :", hex(r))
    debug_msg("s            :", hex(s))
    debug_msg("calc_r       :", hex(calc_r))
    debug_msg("calc_s       :", hex(calc_s))
    debug_msg("ok_sig       :", ok_sig)

    show_exit()
    return (ok_h, ok_h_sig, ok_prv, prv, k, dur, ok_x_h, ok_sig)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_msg = """For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
"""
        in_h = 0xd2d0714f014a9784047eaeccf956520045c45265
        in_p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
        in_q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
        in_g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
        in_y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
        in_r = 548099063082341131477253921760299949438196259240
        in_s = 857042759984254168557880549501802188789837994940
        in_x_h = 0x0954edd5e0afe5542a4adf012611a91912a3ec16
        in_pub = (in_p, in_q, in_g, in_y)
        in_sig = (in_r, in_s)
        (ok_h, ok_h_sig, ok_prv, prv, k, dur, ok_x_h, ok_sig) = \
                execute_break_dsa_prv_key(in_msg, in_h, in_pub, in_sig, in_x_h)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_msg      = [{1}]".format(me, in_msg))
        print("{0}: in_h        = [{1}]".format(me, hex(in_h)))
        print("{0}: in_p        = [{1}]".format(me, hex(in_p)))
        print("{0}: in_q        = [{1}]".format(me, hex(in_q)))
        print("{0}: in_g        = [{1}]".format(me, hex(in_g)))
        print("{0}: in_y        = [{1}]".format(me, hex(in_y)))
        print("{0}: in_r        = [{1}]".format(me, in_r))
        print("{0}: in_s        = [{1}]".format(me, in_s))
        print("{0}: in_x_h      = [{1}]".format(me, hex(in_x_h)))
        print("{0}: ok_h        = [{1}]".format(me, ok_h))
        print("{0}: ok_h_sig    = [{1}]".format(me, ok_h_sig))
        print("{0}: ok_prv      = [{1}]".format(me, ok_prv))
        if ok_prv:
            print("{0}: prv         = [{1}]".format(me, hex(prv)))
            print("{0}: k           = [{1}]".format(me, hex(k)))
            print("{0}: duration    = [{1} seconds]".format(me, dur))
        print("{0}: ok_x_h      = [{1}]".format(me, ok_x_h))
        print("{0}: ok_sig      = [{1}]".format(me, ok_sig))
        ok = (ok_h and ok_h_sig and ok_prv and ok_x_h and ok_sig)
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


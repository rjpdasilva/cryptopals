"""Cryptopals Challenges: Test Challenge 28: Implement a SHA-1 keyed MAC."""

import sys
import cp_aux_utils as utils

title = "Challenge 28: Implement a SHA-1 keyed MAC"

# Random constant key used in challenge.
key_b = None
key_sz = None

def execute_test_sha1(msg):
    """Produces the SHA-1 authentication code as requested by the challenge."""

    global key_b
    global key_sz

    msg_b = utils.rawstr2bytes(msg)

    # Create the random key.
    if key_b is None:
        key_sz = utils.rand_int(1, 32)
        key_b = utils.rand_bytes(key_sz)

    # Get the SHA-1 without the key.
    sha1_b_nokey = utils.sha1_mac(b'', msg_b)
    # Get the SHA-1 with the key.
    sha1_b_key = utils.sha1_mac(key_b, msg_b)

    sha1_nokey = utils.bytes2hexstr(sha1_b_nokey)
    sha1_key = utils.bytes2hexstr(sha1_b_key)
    key = utils.bytes2hexstr(key_b)

    return (sha1_nokey, sha1_key, key_sz, key)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_msg = "This is a text message to be used for testing SHA-1 authentication!"
        # Get the SHA-1 according to challenge requirements.
        (sha1_nokey, sha1_key, key_sz, key) = execute_test_sha1(in_msg)
        # echo -n 'This is a text message to be used for testing SHA-1 authentication!' | sha1sum
        sha1_nokey_ok = "4510008298b75e5113c2d4b99964c6bc43c1f635"
        # "Verify that you cannot tamper with the message without breaking the MAC you've produced".
        # "and that you can't produce a new MAC without knowing the secret key".
        in_msg_t = "This is a tampered msg to be used for testing SHA-1 authentication!"
        (sha1_fake, sha1_tamper, key_sz, key) = execute_test_sha1(in_msg_t)
        # Elements:
        #  + 'in_msg': The original message to authenticate.
        #  + 'key_sz': The size of the key used in authentication.
        #  + 'key': The contents of the key used in authentication.
        #  + 'sha1': The resulting SHA-1 hash when using the key.
        #  + 'sha1_nk': The resulting SHA-1 hash when not using the key (message only). Useful for
        #    confirming if the SHA-1 algorithm is correct.
        #  + 'sha1_nk_ok': The SHA-1 hash obtained from 'in_msg'  using external tool ('sha1sum').
        #  + 'in_msg_tamper': A tampered message.
        #  + 'sha1_tamper': The keyed SHA-1 hash from 'in_msg_tamper'. Must be different than
        #    'sha1'.
        #  + 'sha1_orig': The keyed SHA-1 from the original message (i.e., it's the same as 'sha1').
        #  + 'sha1_fake': The attempt to generate a simple, non-keyed SHA-1 on the tampered message
        #    in order to fake its authenticity. Must be different than 'sha1_tamper'.
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_msg        = [{1}]".format(me, in_msg))
        print("{0}: key_sz        = [{1}]".format(me, key_sz))
        print("{0}: key           = [{1}]".format(me, key))
        print("{0}: sha1          = [{1}]".format(me, sha1_key))
        print("{0}: sha1_nk       = [{1}]".format(me, sha1_nokey))
        print("{0}: sha1_nk_ok    = [{1}]".format(me, sha1_nokey_ok))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_msg_tamper = [{1}]".format(me, in_msg_t))
        print("{0}: sha1_tamper   = [{1}]".format(me, sha1_tamper))
        print("{0}: sha1_orig     = [{1}]".format(me, sha1_key))
        print("{0}: sha1_fake     = [{1}]".format(me, sha1_fake))
        def result_ok():
            """Checks test success conditions."""
            if sha1_nokey != sha1_nokey_ok:
                return False
            if sha1_tamper == sha1_key:
                return False
            if sha1_fake == sha1_tamper:
                return False
            return True
        if not result_ok():
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


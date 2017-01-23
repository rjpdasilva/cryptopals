"""Cryptopals Challenges: Test Challenge 13: ECB cut-and-paste."""

import sys
import cp_aux_utils as utils

title = "Challenge 13: ECB cut-and-paste"

# Random constant key used in 'profile_encrypt()'.
key = None

# Real email for attack.
email_real = "john@acme.com"
# Email to use to get "admin" encrypted.
# Note the PKCS#7 padding to 16 bytes. It is required!
email_admin = "john@acme.admin" + "\x0b" * 11
# The encoded profile attacked so to use an "admin"
# role instead of a user role.
profile_attacked_expected = "email=john@acme.com&uid=10&role=admin"

def parse_kv(s):
    """'k1=v1&k2=v2&...' parsing into list of [k, v] lists."""
    kv_pairs = s.split('&')
    parsed = []
    for kv in kv_pairs:
        kv_items = kv.split('=')
        if len(kv_items) != 2:
            raise Exception("Invalid key/value item")
        k = kv_items[0]
        v = kv_items[1]
        parsed.extend([[k, v]])

    return parsed

def clean_metachars(s):
    """Clean metachars from string byte array."""
    s = s.replace('&', '')
    s = s.replace('=', '')
    return s

def profile_encode(profile):
    """Encode profile."""
    s = ""
    for items in profile:
        if len(s):
            s += "&"
        s += "{k}={v}".format(k = items[0], v = items[1])

    return s

def profile_for(email):
    """The challenge's 'profile_for()' function."""
    email = clean_metachars(email)
    profile = [
        ['email', email],
        ['uid', '10'],
        ['role', 'user']
        ]

    return profile_encode(profile)

def profile_encrypt(email):
    """Encrypt a profile."""

    global key
    blk_sz = 16

    # Generate a random key.
    key_sz = blk_sz
    if key is None:
        key = utils.rand_bytes(key_sz)

    # Create the profile string.
    pt = profile_for(email)
    pt_b = utils.rawstr2bytes(pt)

    # Pad and encrypt.
    pt_b = utils.pkcs7_pad(pt_b, blk_sz)
    ct_b = utils.aes_encrypt(pt_b, key, mode = "ECB")

    return ct_b

def profile_decrypt(ct_b):
    """Decrypt a profile."""

    global key
    blk_sz = 16

    # Key must have been created already.
    if key is None:
        raise Exception("No key for decrypting profile")

    # Decrypt and unpad.
    pt_b = utils.aes_decrypt(ct_b, key, mode = "ECB")
    pt_b = utils.pkcs7_unpad(pt_b, blk_sz)

    # Parse.
    pt = utils.bytes2rawstr(pt_b)
    profile = parse_kv(pt)

    return profile

def execute_role_fake():
    """Perform the 'role=admin' faking."""

    # Relies on knowing:
    #  + That encryption uses ECB with 16 bytes block size
    #    and PKCS#7 padding.
    #  + The key/value structure for the profile encoding.
    #  + That the attacker can control the email address data.
    #
    # The trick is to exercise the profile encrypting routine
    # in a way to produce the ciphertext blocks we need and
    # then to perform a "cut & paste" like operation on those
    # cipher blocks in order to build the cyphertext with the
    # fake/attacked profile.

    # Make sure everything up to and including the 'role='
    # has a length matching a block size multiple, so that
    # it can be "cut" to build the 1st part of the fake
    # ciphertext, i.e., everything except the actual role,
    # which we want to change from "user" to "admin".
    #
    # Example, feeding:
    #  "email=john@acme.com&uid=10&role=user",
    # which means using "john@acme.com" as the email, will
    # allow us to get the ciphertext for:
    #  "email=john@acme.com&uid=10&role=",
    # which is exactly 32 bytes long, so we can use it as
    # the prefix for our fake encrypted profile encoding.
    email1 = email_real
    profile_real_encoded = profile_for(email1)
    ct1 = profile_encrypt(email1)

    # Use the email part to fit the "admin" word in its
    # own block, so that its cipher block can also be "cut"
    # out and "pasted" after the ciphertext obtained before.
    # Pad the "admin" word in email part to match the block
    # size using PKCS#7 padding, so that the unpadding
    # function removes it, bringing back the "admin" word
    # intact (not the "admin" word will be the last real
    # text in the attacked ciphertext, thus the requirement
    # for the PKCS#7 padding).
    #
    # Example, feeding:
    #  "email=john@acme.adminXXXXXXXXXXX&uid=10&role=user",
    # where X is '\x0b' (11 PKCS#7 pad bytes), will put the
    # "admin" and its padding in one exact block, which will
    # allow us to "cut" the resulting ciphertext block and
    # then append it to the previous one, thus completing
    # the "role=admin" part.
    email2 = email_admin
    ct2 = profile_encrypt(email2)

    # Do the "cut & paste" of ECB blocks as described, thus
    # creating the attacked ciphertext.
    ct_fake = ct1[0:32] + ct2[16:32]

    # Decrypt and re-encode for confirming.
    profile_attacked = profile_decrypt(ct_fake)
    profile_attacked_encoded = profile_encode(profile_attacked)

    return (profile_real_encoded, profile_attacked_encoded)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        (profile_real, profile_attacked) = execute_role_fake()
        profile_attacked_ok = profile_attacked_expected
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: real     = [{1}]".format(me, profile_real))
        print("{0}: attacked = [{1}]".format(me, profile_attacked))
        print("{0}: expected = [{1}]".format(me, profile_attacked_expected))
        if profile_attacked != profile_attacked_expected:
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


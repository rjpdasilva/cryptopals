"""Cryptopals Challenges: Test Challenge 25: Break "random access read/write" AES CTR."""

import sys
import cp_aux_utils as utils

title = "Challenge 25: Break \"random access read/write\" AES CTR"

# Random constant key used in challenge.
# Known only to the 'ctr_encrypt()' and 'ctr_edit()' functions.
key_b = None

# Fixed constant block size used in challenge.
# Known only to the 'ctr_encrypt()' and 'ctr_edit()' functions.
blk_sz = 16

# Fixed constant nonce used in challenge.
# Known only to the 'ctr_encrypt()' and 'ctr_edit()' functions.
nonce = None

def get_plaintext(file_name, key):
    """Gets the plaintext to work with."""

    # Get the ciphertext.
    ct_b = utils.file_get_ciphertext_base64(file_name)

    # Convert the key to byte array.
    key_b = utils.rawstr2bytes(key)

    # Decrypt.
    pt_b = utils.aes_decrypt(ct_b, key_b, mode = "ECB")

    return pt_b

def ctr_encrypt(pt_b):
    """Start a new CTR encryption for the give plaintext byte arrays."""

    global key_b
    global nonce

    # Generate a random key and nonce.
    aes_key_sz = blk_sz
    if key_b is None:
        key_b = utils.rand_bytes(aes_key_sz)
    if nonce is None:
        nonce = utils.rand_bytes(8)[0]

    # Encrypt.
    aes_ctr = utils.AesCtr(key_b, nonce)
    ct_b = aes_ctr.encrypt(pt_b)

    return ct_b

def ctr_edit(ct_b, offset, new_pt_b):
    """Edit a CTR encryption with new plaintext at given offset, returning the new ciphertext."""

    global key_b
    global nonce

    # Confirm the key and nonce are available.
    if key_b is None or nonce is None:
        raise Exception("No key/nonce available yet. Must encrypt something first.")

    # Create a new 'AesCtr' object to work with, using the same key/nonce as used
    # by 'ctr_encrypt()'.
    aes_ctr = utils.AesCtr(key_b, nonce)

    # Due to CTR properties, the best way to edit the ciphertext is to
    # keep the current ciphertext up until the offset given and then
    # request for new ciphertext for the part being edited. To get the
    # correct keystream state for encrypting the new plaintext, we must
    # first push an amount of data equal to 'offset' into the encrypt
    # function, discarding the resulting ciphertext (which we already have).

    dummy_pt_b = b'0' * offset
    aes_ctr.encrypt(dummy_pt_b)
    new_ct_b = aes_ctr.encrypt(new_pt_b)
    edited_ct_b = ct_b[:offset] + new_ct_b

    return edited_ct_b

def execute_break_rnd_access_aes_ctr(file_name, aes_ecb_key):
    """Breaks a "random access read/write" AES CTR ciphertext using a AES-CTR "edit" function."""

    # Get the plaintext that is to be encrypted with CTR.
    # The plaintext is in 'file_name', base64 encoded and
    # AES-ECB encrypted using 'aes_ecb_key'.
    pt_b = get_plaintext(file_name, aes_ecb_key)
    pt = utils.bytes2rawstr(pt_b)

    # Request the CTR encryption.
    ct_b = ctr_encrypt(pt_b)

    # Now, for the breaking: The "edit" function is basically a way
    # the attacker has to ask for re-encrypting a new plaintext with
    # the same parameters (key/nonce). This takes us back to C19 and
    # C20, where, with enough different ciphertexts for the same
    # key/nonce pair, one could break the ciphertexts using
    # substitution (C19) or statistically (C20).
    #
    # However, looking more carefully to what the "edit" function
    # does, one can conclude that it's a real and complete AES-CTR
    # encryption function. Just use a zero offset and call it for any
    # ciphertext you want and you'll get back the encrypted result.
    # Even more incredibly, because encryption and decryption is the
    # same thing in CTR, the "edit" function is actually also a full
    # and complete decryption function! Just call it with any
    # ciphertext (e.g., the one we want to break!) and you'll get back
    # the respective plaintext!
    #
    # This happens because, for any byte 'i', 'CT[i] = PT[i] ^ KS[i]',
    # where CT is ciphertext, PT is plaintext and KS is the keystream.
    # Also means that 'PT[i] = CT[i] ^ KS[i]'.
    # Since we know that, by definition, the "edit" function must keep
    # the same keystream, it's easy to see that since feeding the
    # encrypt function with PT gives us CT and vice-versa.
    #
    # Using the same rationale, yet another possibility is to call the
    # "edit" function for offset zero, with a new plaintext consisting
    # of all zeros with the same length as the ciphertext. This would
    # give us 'NEW_CT = 0x00 ^ KS = KS'. Se we would, in fact, get the
    # actual keystream for any length we want, thus being able to crack
    # any ciphertext we want simply by XORing it with the keystream.
    #
    # Bottom line: To break the ciphertext feed the "edit" function
    # with new plaintext being the actual ciphertext and using a zero
    # offset.

    broken_pt_b = ctr_edit(ct_b, 0, ct_b)
    broken_pt = utils.bytes2rawstr(broken_pt_b)

    return (pt, broken_pt)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        # The file with the AES-ECB encrypted data is the same as used for C7.
        in_file = "data_c07.txt"
        # The AES-ECB key is also the same as used for C7.
        in_key = "YELLOW SUBMARINE"
        (pt, broken_pt) = execute_break_rnd_access_aes_ctr(in_file, in_key)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_file  = [{1}]".format(me, in_file))
        print("{0}: in_key   = [{1}]".format(me, in_key))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: result   = [<see below>)]".format(me))
        print("{0}: ".format(me) + "-" * 60)
        print(broken_pt)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: expected = [<see below>)]".format(me))
        print("{0}: ".format(me) + "-" * 60)
        print(pt)
        if broken_pt != pt:
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


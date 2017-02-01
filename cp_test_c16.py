"""Cryptopals Challenges: Test Challenge 16: CBC bitflipping attacks."""

import sys
import cp_aux_utils as utils

title = "Challenge 16: CBC bitflipping attacks"

# Random constant key and IV used in encryption oracle.
key_b = None
iv_b = None

def escape_userdata(s):
    """Escapes ';' (0x3b) and '=' (0x3d) chars from user data."""
    s = s.replace(b';', b'%3B')
    s = s.replace(b'=', b'%3D')

    return s

# An encryption function we can exercise (call), but of
# which we are not supposed to know the implementation
# details.
def encryption_oracle(pt_b):
    """Encryption Oracle: Challenge 16."""

    # Uses a key and block size of 16 bytes.
    # Prepends a constant and know data block.
    # Appends a constant and know data block.
    # Uses AES-CBC for encrypting.

    prefix_b = b'comment1=cooking%20MCs;userdata='
    suffix_b = b';comment2=%20like%20a%20pound%20of%20bacon'

    global key_b
    global iv_b
    blk_sz = 16

    # Generate random key and IV.
    if key_b is None:
        key_sz = blk_sz
        iv_sz = blk_sz
        key_b = utils.rand_bytes(key_sz)
        iv_b = utils.rand_bytes(iv_sz)

    # Build the plaintext (pt).
    pt_b = escape_userdata(pt_b)
    pt_b = prefix_b + pt_b + suffix_b
    pt_b = utils.pkcs7_pad(pt_b, blk_sz)

    # Encrypt.
    ct_b = utils.aes_encrypt(pt_b, key_b, mode = "CBC", iv = iv_b)

    return ct_b

def decryption_oracle(ct_b):
    """Decrypts and unpads a message encrypted by the oracle."""

    global key_b
    global iv_b
    blk_sz = 16

    if key_b is None:
        raise Exception("No key available for decrypting")

    # Decrypt and unpad.
    pt_b = utils.aes_decrypt(ct_b, key_b, mode = "CBC", iv = iv_b)
    pt_b = utils.pkcs7_unpad(pt_b, blk_sz)

    return pt_b

def execute_cbc_bitflip_attack(s):
    """Perform a CBC bitflip attack, so that a string appears in the plaintext."""

    # Attack relies on the fact that a 1 bit error in a ciphertext
    # block (N) will produce the exact same 1 bit error in the
    # plaintext block (N + 1). This happens because the way CBC
    # is implemented, in which ciphertext block (N) is XORed with
    # the decrypted ciphertext block (N + 1) to produce the
    # plaintext block (N + 1). To note that "corrupting" the
    # ciphertext block (N) will completely scramble the decrypted
    # plaintext block (N), but the purpose of the challenge is to
    # be able to "create" a specific string in the resulting
    # plaintext, even if the cost is corrupting another part of the
    # plaintext.
    #
    # The idea is to have at least 2 blocks of data that the attacker
    # can control and use bit flipping on the 1st block of the
    # associated ciphertext in a way that the resulting bit flipping
    # on the 2nd block of the resulting plaintext produces the
    # required "attack" string.
    #
    # For knowing exactly which bits to flip on the 1st ciphertext block
    # we first need to know which bits are changed on the 2nd block from
    # the original plaintext to the one we want to force on the end. A
    # XOR will tells us this info, i.e., the bits that need to change in
    # the 2nd block of plaintext are:
    #   BITS_TO_FLIP = PT_orig(2) ^ PT_attacked(2),
    # where "PT" means plaintext, "orig" is the original plaintext,
    # "attacked" is the attacked plaintext and the number in brackets is
    # the 2nd block controlled by the attacker.
    # As mentioned, in CBC, for flipping the bits in plaintext block 2,
    # all what is required is to flip the same bits in the ciphertext
    # block 1. This can be determined again via XOR:
    #   CT_attacked(1) = CT_orig(1) ^ BITS_TO_FLIP,
    # where "CT" means ciphertext, "orig" is the original ciphertext,
    # "attacked" is the attacked ciphertext and the number in brackets is
    # the 1st block controlled by the attacker.
    #
    # In summary, the strategy will be to get the ciphertext of an attacker
    # controlled string occupying exactly 2 blocks, calculate the bits that
    # need to be changed in the 1st ciphertext block in order to get the
    # desired string in the 2nd plaintext block, apply the bit flipping to
    # the ciphertext and confirm the resulting plaintext does contain the
    # string we want to force.
    #
    # In this particular challenge, the attack relies on knowing the block
    # size and the size of the prefix prepended by the oracle, which is
    # exactly 32 bytes (2 blocks).

    blk_sz = 16
    prefix_sz = 32

    # This is the 2 block data the attacker can control.
    # The contents is not important.
    pt_orig1_b = b'X' * blk_sz
    pt_orig2_b = b'Y' * blk_sz
    pt_orig_b = pt_orig1_b + pt_orig2_b

    # Get the ciphertext.
    ct_orig_b = encryption_oracle(pt_orig_b)

    # Get the attacker data 1st ciphertext block (oracle prepends 32 prefix
    # bytes to data).
    # This is the ciphertext block to which we will apply bit flipping in
    # order to create the desired string on the 2nd plaintext block.
    ct_orig1_b = ct_orig_b[prefix_sz:(prefix_sz + blk_sz)]

    # The desired 2nd block of plaintext.
    # Pad it with 'Z' till filling a block. Content is not important but will
    # show up in the attacked 2nd block of plaintext).
    if len(s) > blk_sz:
        raise Exception("Attack string must no exceed block size")
    pt_required_b = utils.rawstr2bytes(s)
    pt_attacked2_b = pt_required_b + b'Z' * (blk_sz - len(s))

    # Do the required bit flipping calculations.
    bits_to_flip_b = utils.xor(pt_orig2_b, pt_attacked2_b)
    ct_attacked1_b = utils.xor(ct_orig1_b, bits_to_flip_b)

    # Replace the 1st block of the original ciphertext with the attacked one.
    ct_attacked_b = ct_orig_b[0:prefix_sz] + ct_attacked1_b + ct_orig_b[(prefix_sz + blk_sz):]

    # Decrypt the attacked ciphertext to confirm attack success.
    pt_attacked_b = decryption_oracle(ct_attacked_b)
    found = pt_attacked_b.find(pt_required_b) != -1

    return (pt_attacked_b, found)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_str = ";admin=true;"
        (pt_attacked, found) = execute_cbc_bitflip_attack(in_str)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: attacked = [{1}]".format(me, pt_attacked))
        print("{0}: found    = [{1}]".format(me, found))
        if not found:
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


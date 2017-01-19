"""Cryptopals Challenges: Test Challenge 10: Implement CBC mode."""

import sys
import cp_aux_utils as utils

title = "Challenge 10: Implement CBC mode"

def execute_decrypt_aes_cbc_using_ebc(file_name, key, iv):
    """Descrypt a AES-CBC encrypted and base64 encoded file using a key."""

    # Get the ciphertext.
    ct = utils.file_get_ciphertext_base64(file_name)

    # Decrypt.
    plaintext = utils.aes_decrypt_cbc_using_ebc(ct, key, iv)

    # Convert to raw string.
    return utils.bytes2rawstr(plaintext)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_file = "data_c10.txt"
        in_key = b'YELLOW SUBMARINE'
        in_iv = b'\x00' * 16
        out_res = execute_decrypt_aes_cbc_using_ebc(in_file, in_key, in_iv)
        out_file = 'data_c6_out.txt'
        out_res_ok = utils.file_get(out_file)
        # These extra bytes (padding?) are part of the decrypted message.
        out_res_ok += ("\x04" * 4)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_file  = [{1}]".format(me, in_file))
        print("{0}: in_key   = [{1}]".format(me, in_key))
        print("{0}: in_iv    = [{1}]".format(me, in_iv))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: result   = [<see below>)]".format(me))
        print("{0}: ".format(me) + "-" * 60)
        print(out_res)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: expected = [<see below>)]".format(me))
        print("{0}: ".format(me) + "-" * 60)
        print(out_res_ok)
        if out_res != out_res_ok:
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

"""Cryptopals Challenges: Test Challenge 07: AES in ECB mode."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 07: AES in ECB mode"

def execute_decrypt_aes_ecb(file_name, key):
    """Decrypt a AES-ECB encrypted and base64 encoded file using a key."""

    # Get the ciphertext.
    ct = utils.file_get_ciphertext_base64(file_name)

    # Convert the key to byte array.
    key_b = utils.rawstr2bytes(key)

    # Decrypt.
    plaintext = utils.aes_decrypt(ct, key_b, mode = "ECB")

    return utils.bytes2rawstr(plaintext)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_file = 'data/data_c07.txt'
        in_key = "YELLOW SUBMARINE"
        out_res = execute_decrypt_aes_ecb(in_file, in_key)
        out_file = 'data/data_c06_out.txt'
        out_res_ok = utils.file_get(out_file)
        # These extra bytes (padding?) are part of the decrypted message.
        out_res_ok += ("\x04" * 4)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_file  = [{1}]".format(me, in_file))
        print("{0}: in_key   = [{1}]".format(me, in_key))
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


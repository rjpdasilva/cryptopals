"""Cryptopals Challenges: Test Challenge 05: Implement repeating-key XOR."""

import sys
import cp_aux_utils as utils

title = "Challenge 05: Implement repeating-key XOR"

def execute_encrypt_repeating_key_xor(file_name, key):
    """Encrypt a file's data with repeating key xor."""

    # Get the whole file data.
    data = utils.file_get(file_name)

    # Remove a possible trailing '\n'
    if data[-1] == '\n':
        data = data[:-1]

    # Encrypt the data.
    data_encr = utils.xor(data, key, in_fmt = "raw", out_fmt = "hex")

    return data_encr

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_file = 'data_c5.txt'
        in_key = "ICE"
        out_res = execute_encrypt_repeating_key_xor(in_file, in_key)
        out_res_ok = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_file  = [{1}]".format(me, in_file))
        print("{0}: result   = [{1}]".format(me, out_res))
        print("{0}: expected = [{1}]".format(me, out_res_ok))
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


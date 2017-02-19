"""Cryptopals Challenges: Test Challenge 31: Implement and break HMAC-SHA1 with an artificial
timing leak."""

import sys
import utils.cp_aux_utils as utils
import time
import urllib.request

title = "Challenge 31: Implement and break HMAC-SHA1 with an artificial timing leak"

# Web server address and port.
server_addr = ""
server_port = 9000
# Delay used for each HMAC byte that is correct (ms).
server_delay = 50
# Signature size (HMAC-SHA1).
sig_size = 20

def http_check_file_signature(file_name, sig, addr, port):
    """Does the HTTP request to check a file signature."""

    # Besides issuing the request to check the current
    # signature being guessed, this function also
    # measures the request processing duration.
    # This info is needed for deciding when we have
    # guessed the next unknown byte from the signature,
    # because the server has an implicit fixed delay
    # for each byte that is correct, when checking the
    # signature byte-by-byte (and bails out when the 1st
    # wrong byte is found).

    # Build the HTTP URL for the HTTP request.
    url = "http://{0}:{1}/test?file={2}&signature={3}".format(
            "localhost" if addr is "" else addr, port, file_name, sig.hex())

    # Issue the request.
    start = time.perf_counter()
    # Errors are triggered as exceptions, so use a
    # try/except block.
    try:
        resp = urllib.request.urlopen(url)
        end = time.perf_counter()
        # We're interested in catching the 200 (OK) status.
        # Any other status here is unexpected.
        if resp.status != 200:
            raise Exception("Unexpected OK status {0}".format(resp.status))
        # Valid signature.
        # Perf counter is fractional seconds => convert to ms.
        return (True, (end - start) * 1000.0)
    except urllib.error.HTTPError as e:
        # We're interested in catching the 500 (Error) status.
        # Any other status here is unexpected.
        end = time.perf_counter()
        if e.code != 500:
            raise Exception("Unexpected Error status {0}".format(e.code))
        # Invalid signature.
        # Perf counter is fractional seconds => convert to ms.
        return (False, (end - start) * 1000.0)

def execute_break_hmac_sha1(file_name, addr, port, delay):
    """Execute the timing leak attack for breaking the HMAC-SHA1 for any 'file_name'."""

    # The attack is based on:
    #  + Having a way of knowing if a signature is correct or not,
    #    by issuing an HTTP request to the server.
    #  + Knowing that the server does a byte-by-byte check on the
    #    signature, returning error as soon as a byte is wrong and
    #    having internally a fixed delay for each correct byte.
    #
    # The above allows a brute force attack (all values tested for
    # each byte till getting it right). The 1st byte will be correct
    # when the HTTP request takes the byte delay discussed above and
    # wrong if the request takes less time. Then, we prepare a new
    # request with the 1st byte already correct and then testing all
    # values again for the second byte, which we'll to to have
    # guessed when the request takes more than twice the delay. This
    # process is repeated till all bytes have been guessed. In the
    # end, if we guessed all bytes right, we should get an OK
    # response from the server.

    sig_broken = b''
    for i in range(sig_size):
        missing = sig_size - i
        delta_min = (i * delay) + delay
        found = False
        print("Guessing byte {0:02d} (dmin={1:6.1f})...".format(i, delta_min),
                end = '', flush = True)
        for v in range(256):
            v_b = bytes([v])
            sig = sig_broken + v_b + b'\x00' * (missing - 1)
            (ok, delta) = http_check_file_signature(file_name, sig, addr, port)
            if delta > delta_min:
                sig_broken += v_b
                print("done: v={0}, d={1:6.1f}\n({2}) {3}"
                        .format(v_b.hex(), delta, "sig-OK" if ok else "sig-KO", sig_broken.hex()))
                found = True
                break
        if not found:
            print("failed")
            return (False, sig_broken, "Could not guess byte {0}".format(i))

    # Confirm the guessed signature is correct.
    if not ok:
        return (False, sig_broken, "Guessed signature is invalid")

    return (True, sig_broken, "Signature was verified")

def main(me, title, delay, break_fn):
    # This script needs one argument: The file name.
    if len(sys.argv) != 2:
        print("{0}: Error: Missing <file_name> arg".format(me))
        print("{0}: usage: {0} <file_name>".format(me))
        sys.exit(1)
    try:
        file_name = sys.argv[1]
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: file_name     = [{1}]".format(me, file_name))
        print("{0}: server_addr   = [{1}]"
                .format(me, server_addr if server_addr != "" else "localhost"))
        print("{0}: server_port   = [{1}]".format(me, server_port))
        print("{0}: server_delay  = [{1} ms]".format(me, delay))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Breaking...".format(me))
        print("{0}: ".format(me) + "-" * 60)
        (ok, sig_broken, msg) = break_fn(file_name, server_addr, server_port, delay)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Breaking...done".format(me))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: success       = [{1}]".format(me, ok))
        print("{0}: message       = [{1}]".format(me, msg))
        print("{0}: signature     = [{1}]".format(me, sig_broken.hex()))
        if not ok:
            err_str = "\n{0}: ".format(me) + "-" * 60
            err_str += "\n{0}: TEST          = [FAILED] Result doesn't match expected.".format(me)
            err_str += "\n{0}: ".format(me) + "-" * 60
            raise Exception(err_str)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: TEST          = [OK]".format(me))
        print("{0}: ".format(me) + "-" * 60)
    except Exception:
        print("\n{0}: ".format(me) + "-" * 60)
        print("{0}: Caught ERROR EXCEPTION:".format(me))
        raise
    except:
        print("\n{0}: ".format(me) + "-" * 60)
        print("{0}: Caught UNEXPECTED EXCEPTION:".format(me))
        raise

if __name__ == '__main__':
    me = sys.argv[0]
    main(me, title, server_delay, execute_break_hmac_sha1)
    sys.exit(0)


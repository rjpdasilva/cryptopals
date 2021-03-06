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

"""Cryptopals Challenges: Test Challenge 31: Implement and break HMAC-SHA1 with an artificial
timing leak: Server."""

import sys
import utils.cp_aux_utils as utils
import time

title = "Challenge 31: Implement and break HMAC-SHA1 with an artificial timing leak: Server"

# Random constant key used in challenge.
key_b = None

# Maximum secret key size to use in the challenge.
max_key_sz = 1024
key_sz_real = None

# Web server address and port.
server_addr = ""
server_port = 9000
# Delay used for each HMAC byte that is correct (ms).
server_delay = 50

# To keep track of last file being requested.
last_file = None

# Debug flag.
debug = 0

# Debug messages.
def debug_msg(*args, **kwargs):
    """Extra debug messages."""
    if not debug:
        return
    print(*args, **kwargs)

def sha1_hmac(msg_b):
    """Produces the HMAC-SHA1 authentication code as requested by the challenge."""

    global key_b
    global key_sz_real

    # Create the random key.
    if key_b is None:
        key_sz_real = utils.rand_int(1, max_key_sz)
        key_b = utils.rand_bytes(key_sz_real)

    # Get the HMAC-SHA1 with the key.
    sha1_hmac_b = utils.sha1_hmac(key_b, msg_b)

    return sha1_hmac_b

def insecure_compare(hmac1, hmac2, delay):
    """The 'insecure_compare' function as described in the challenge's statement."""

    # Must have the same length.
    if len(hmac1) != len(hmac2):
        return False

    # Byte-by-byte comparison, exiting as soon as a byte is different and waiting
    # 'delay' ms for each equal byte.
    for i in range(len(hmac1)):
        if hmac1[i] != hmac2[i]:
            return False
        time.sleep(delay / 1000)

    return True

def http_req_get_handler(r):
    """The handler called by 'CpHTTPServer' for GET requests."""

    global last_file

    debug_msg()
    debug_msg("http_req_get_handler: New req for path [{0}]".format(r.path))

    # The request must be for '/test' path.
    if r.req_path != "/test":
        debug_msg("http_req_get_handler:   error: 500 (unknown path)")
        debug_msg()
        return (500, "Invalid path: {0}".format(r.req_path))

    # Get the 'file' and 'signature' items from the request's
    # query string.
    q = r.req_qs
    if 'file' not in q:
        debug_msg("http_req_get_handler:   error: 500 ('file' not in query string)")
        debug_msg()
        return (500, "Invalid query string: 'file' is missing")
    if 'signature' not in q:
        debug_msg("http_req_get_handler:   error: 500 ('signature' not in query string)")
        debug_msg()
        return (500, "Invalid query string: 'signature' is missing")

    file_name = q['file'][0]
    try:
        signature = utils.hexstr2bytes(q['signature'][0])
    except Exception:
        debug_msg("http_req_get_handler:   error: 500 (signature syntax invalid)")
        debug_msg()
        return (500, "Invalid signature syntax: {0}".format(q['signature'][0]))

    debug_msg("http_req_get_handler:   file      = [{0}]".format(file_name))
    debug_msg("http_req_get_handler:   signature = [{0}]".format(signature.hex()))

    # Instead of actually hashing a file check it against the
    # 'signature' item from the query string, for simplification,
    # we're hashing the file name itself. Serves the same purpose
    # regarding the challenge's idea.
    hmac_real = sha1_hmac(utils.rawstr2bytes(file_name))
    debug_msg("http_req_get_handler:   hmac_real = [{0}]".format(hmac_real.hex()))

    if len(signature) != len(hmac_real):
        debug_msg("http_req_get_handler:   error: 500 (signature length invalid)")
        debug_msg()
        return (500, "Invalid signature length: len {0} is {1}. Must be {2}"
                .format(signature.hex(), len(signature), len(hmac_real)))

    if file_name != last_file:
        print("http_req_get_handler: new file = [{0}], sig = [{1}]"
                .format(file_name, hmac_real.hex()))
        last_file = file_name
    # Do the 'insecure compare'.
    match = insecure_compare(hmac_real, signature, server_delay)
    debug_msg("http_req_get_handler:   match     = [{0}]".format(match))
    if not match:
        debug_msg("http_req_get_handler:   error: 500 (signature invalid)")
        debug_msg()
        return (500, "Invalid signature")

    debug_msg("http_req_get_handler: success: 200 (signature valid)")
    debug_msg()
    return (200, "OK - Valid signature")

def execute_server(addr, port):
    """Run the web server as required by the challenge."""

    # Create and run the HTTP server.
    httpd = utils.CpHTTPServer(addr, port, http_req_get_handler)
    httpd.serve_forever()

def main(me, title, delay):
    global server_delay
    server_delay = delay
    try:
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: server_addr   = [{1}]"
                .format(me, server_addr if server_addr != "" else "localhost"))
        print("{0}: server_port   = [{1}]".format(me, server_port))
        print("{0}: server_delay  = [{1} ms]".format(me, server_delay))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Running server...".format(me))
        print("{0}: (Ctrl+C to abort)".format(me))
        print("{0}: ".format(me) + "-" * 60)
        execute_server(server_addr, server_port)
        # Not supposed to reach this point.
        err_str = "\n{0}: ".format(me) + "-" * 60
        err_str += "\n{0}: SERVER RUN    = [FAILED] Exited unexpectedly.".format(me)
        err_str += "\n{0}: ".format(me) + "-" * 60
        raise Exception(err_str)
    except KeyboardInterrupt:
        # Correct exit point by Ctrl+C.
        print()
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: SERVER RUN    = [OK] Aborted by user.".format(me))
        print("{0}: ".format(me) + "-" * 60)
    except Exception:
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Caught ERROR EXCEPTION:".format(me))
        raise
    except:
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Caught UNEXPECTED EXCEPTION:".format(me))
        raise

if __name__ == '__main__':
    me = sys.argv[0]
    main(me, title, server_delay)
    sys.exit(0)


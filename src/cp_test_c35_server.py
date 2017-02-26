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

"""Cryptopals Challenges: Test Challenge 35: Implement DH with negotiated groups, and break with
malicious 'g' parameters: Server."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 35: Implement DH with negotiated groups, and break with malicious 'g' parameters: Server"

# Server address and port.
server_addr = None
server_port = None

# Debug flag.
debug = 0

# Debug messages.
def debug_msg(*args, **kwargs):
    """Extra debug messages."""
    if not debug:
        return
    print(*args, **kwargs)

def usage(me, err_msg = None):
    """Show script usage."""
    if err_msg != None:
        print(err_msg)
    print("{0}: usage: {0} <server_addr> <server_port>".format(me))

def get_args(me):
    """Script argument parsing."""

    global server_addr
    global server_port

    if len(sys.argv) != 3:
        usage(me, "{0}: Error: Missing arguments".format(me))
        return False

    server_addr = sys.argv[1]
    server_port = sys.argv[2]
    try:
        server_port = int(server_port)
    except:
        usage(me, "{0}: Error: Invalid <server_port> value: {1}. Must be integer > 0"
                .format(me, server_port))
        return False
    if server_port <= 0:
        usage(me, "{0}: Error: Invalid <server_port> value: {1}. Must be integer > 0"
                .format(me, server_port))
        return False

    return True

def request_handler(rh):
    """Execute the challenge's server protocol."""

    # Get a Socket IO utility object.
    sock_io = utils.CpSocketIO(rh)

    try:
        print("")
        print("=" * 60)
        print("server: New request")
        print("=" * 60)

        # A->B: Send "p", "g".
        debug_msg("server: Receiving 'p'...", end = '', flush = True)
        p = sock_io.readnum()
        debug_msg("done:\n  p = [{0}]".format(p))
        debug_msg("server: Receiving 'g'...", end = '', flush = True)
        g = sock_io.readnum()
        debug_msg("done:\n  g = [{0}]".format(g))

        # B->A: Send ACK (negotiated "p", "g").
        debug_msg("-" * 60)
        debug_msg("server: Sending negotiated 'p'...", end = '', flush = True)
        sock_io.writenum(p)
        debug_msg("done:\n  p = [{0}]".format(p))
        debug_msg("server: Sending negotiated 'g'...", end = '', flush = True)
        sock_io.writenum(g)
        debug_msg("done:\n  g = [{0}]".format(g))

        # Create the server's DH key pair.
        debug_msg("-" * 60)
        debug_msg("server: Generating DH keys...", end = '', flush = True)
        (b, B) = utils.dh_keys(p, g)
        debug_msg("done:\n  b = [{0}]\n  B = [{1}]".format(b, B))

        # A->B: Send "A".
        debug_msg("-" * 60)
        debug_msg("server: Receiving 'A'...", end = '', flush = True)
        A = sock_io.readnum()
        debug_msg("done:\n  A = [{0}]".format(A))

        # B->A: Send "B".
        debug_msg("-" * 60)
        debug_msg("server: Sending 'B'...", end = '', flush = True)
        sock_io.writenum(B)
        debug_msg("done:\n  B = [{0}]".format(B))

        # A->B: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv.
        debug_msg("-" * 60)
        debug_msg("server: Receiving ciphertext...", end = '', flush = True)
        ct_b = sock_io.readbytes()
        debug_msg("done:\n  ct_b = [{0}]".format(ct_b.hex()))
        debug_msg("server: Receiving 'iv'...", end = '', flush = True)
        iv_b = sock_io.readbytes()
        debug_msg("done:\n  iv_b = [{0}]".format(iv_b.hex()))

        # Generate the session key ('s'), derive the AES-CBC key
        # ('k') from it and decrypt.
        debug_msg("-" * 60)
        debug_msg("server: Generating keys and decrypting...", end = '', flush = True)
        s = utils.dh_session_key(A, b, p)
        s_b = s.to_bytes((s.bit_length() + 7) // 8, 'big')
        k = utils.sha1_mac(b'', s_b)[:16]
        pt_b = utils.aes_decrypt(ct_b, k, mode = "CBC", iv = iv_b)
        msg_b = utils.pkcs7_unpad(pt_b, 16)
        msg = utils.bytes2rawstr(msg_b)
        debug_msg("done:")
        debug_msg("  s     = [{0}]".format(s))
        debug_msg("  k     = [{0}]".format(k.hex()))
        debug_msg("  pt_b  = [{0}]".format(pt_b))
        debug_msg("  msg_b = [{0}]".format(msg_b))
        print("  msg   = [{0}]".format(msg))

        # Re-encrypt the message.
        debug_msg("-" * 60)
        debug_msg("server: Re-encrypting...", end = '', flush = True)
        server_iv_b = utils.rand_bytes(16)
        server_msg = msg
        server_msg_b = utils.rawstr2bytes(server_msg)
        server_pt_b = utils.pkcs7_pad(server_msg_b, 16)
        server_ct_b = utils.aes_encrypt(server_pt_b, k, mode = "CBC", iv = server_iv_b)
        debug_msg("done:")
        debug_msg("  server_msg   = [{0}]".format(server_msg))
        debug_msg("  server_msg_b = [{0}]".format(server_msg_b))
        debug_msg("  server_pt_b  = [{0}]".format(server_pt_b))
        debug_msg("  server_iv_b  = [{0}]".format(server_iv_b.hex()))
        debug_msg("  server_ct_b  = [{0}]".format(server_ct_b.hex()))

        # B->A: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv.
        debug_msg("-" * 60)
        debug_msg("server: Sending ciphertext...", end = '', flush = True)
        sock_io.writebytes(server_ct_b)
        debug_msg("done:\n  server_ct_b = [{0}]".format(server_ct_b.hex()))
        debug_msg("server: Sending 'iv'...", end = '', flush = True)
        sock_io.writebytes(server_iv_b)
        debug_msg("done:\n  server_iv_b = [{0}]".format(server_iv_b.hex()))
        print("=" * 60)
    except OSError as os_err:
        print("\nserver: OSError: ({0}, {1})".format(os_err.errno, os_err.strerror))
    except Exception:
        print("\nserver: Exception")

def execute_server(addr, port):
    """Run the server as required by the challenge."""

    # Create and run the TCP server.
    try:
        tcpd = utils.CpTCPServer(addr, port, request_handler)
        tcpd.serve_forever()
    except OSError as os_err:
        print("\nserver: OSError: ({0}, {1})".format(os_err.errno, os_err.strerror))
    except Exception:
        print("\nserver: Exception")

def main(me, title):
    """Challenge's main executing function."""

    # This script needs arguments, so get them.
    if not get_args(me):
        sys.exit(1)
    try:
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: server_addr = [{1}]".format(me, server_addr))
        print("{0}: server_port = [{1}]".format(me, server_port))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Running server...".format(me))
        print("{0}: (Ctrl+C to abort)".format(me))
        print("{0}: ".format(me) + "-" * 60)
        execute_server(server_addr, server_port)
        # Not supposed to reach this point.
        err_str = "\n{0}: ".format(me) + "-" * 60
        err_str += "\n{0}: SERVER RUN  = [FAILED] Exited unexpectedly.".format(me)
        err_str += "\n{0}: ".format(me) + "-" * 60
        raise Exception(err_str)
    except KeyboardInterrupt:
        # Correct exit point by Ctrl+C.
        print("")
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: SERVER RUN  = [OK] Aborted by user.".format(me))
        print("{0}: ".format(me) + "-" * 60)
    except Exception:
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Caught ERROR EXCEPTION:".format(me))
        raise
    except:
        print("\n{0}: ".format(me) + "-" * 60)
        print("{0}: Caught UNEXPECTED EXCEPTION:".format(me))
        raise

if __name__ == '__main__':
    me = sys.argv[0]
    main(me, title)
    sys.exit(0)


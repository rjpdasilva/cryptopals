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
malicious 'g' parameters: MITM."""

import sys
import utils.cp_aux_utils as utils
import socket

title = "Challenge 35: Implement DH with negotiated groups, and break with malicious 'g' parameters: MITM"

# MITM Server address and port.
mitm_addr = None
mitm_port = None

# Real Server address and port.
server_addr = None
server_port = None

# The 'g' hacking method:
#  + 1: Force 'g = 1'.
#  + 2: Force 'g = p'.
#  + 2: Force 'g = p - 1'.
hack_choice = None

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
    print("{0}: usage: {0} <mitm_addr> <mitm_port> <server_addr> <server_port> <hack_choice>"
            .format(me))

def get_args(me):
    """Script argument parsing."""

    global mitm_addr
    global mitm_port
    global server_addr
    global server_port
    global hack_choice

    if len(sys.argv) != 6:
        usage(me, "{0}: Error: Missing arguments".format(me))
        return False

    mitm_addr = sys.argv[1]
    mitm_port = sys.argv[2]
    try:
        mitm_port = int(mitm_port)
    except:
        usage(me, "{0}: Error: Invalid <mitm_port> value: {1}. Must be integer > 0"
                .format(me, mitm_port))
        return False
    if mitm_port <= 0:
        usage(me, "{0}: Error: Invalid <mitm_port> value: {1}. Must be integer > 0"
                .format(me, mitm_port))
        return False

    server_addr = sys.argv[3]
    server_port = sys.argv[4]
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

    hack_choice = sys.argv[5]
    try:
        hack_choice = int(hack_choice)
    except:
        usage(me, "{0}: Error: Invalid <hack_choice> value: {1}. Must be 1 (g = 1), 2 (g = p) or 3 (g = p - 1)"
                .format(me, hack_choice))
        return False
    if hack_choice not in [1, 2, 3]:
        usage(me, "{0}: Error: Invalid <hack_choice> value: {1}. Must be 1 (g = 1), 2 (g = p) or 3 (g = p - 1)"
                .format(me, hack_choice))
        return False
    return True

def get_session_key(p, hacked_g, ct_b, iv_b):
    """Do the session key hacking based on the selected hacked_g value."""

    # There are 3 'g' hacking strategies explored in this challenge, which
    # can be selected when running the MITM attacker via its last
    # '<hack_choice>' argument. The possible values and attack explanation
    # follow:
    #
    # '<hack_choice> = 1' => Force 'g = 1' =>
    #       A = 1^a % p = 1
    #       B = 1^b % p = 1
    #       sA = 1^a % p = 1
    #       sB = 1^b % p = 1
    # So, in this case, we're forcing the shared session key 's' to always
    # be 1.
    #
    # '<hack_choice> = 2' => Force 'g = p' =>
    #       A = p^a % p = 0
    #       B = p^b % p = 0
    #       sA = p^a % p = 0
    #       sB = p^b % p = 0
    # In this case, we're forcing the shared session key 's' to always
    # be 0.
    #
    # '<hack_choice> = 3' => Force 'g = p - 1' =>
    #   By doing some math analysis on '(p - 1)^n' it can be verified that
    #   the result is always a sum of 'p' factors plus +1 when 'n' is is
    #   odd or plus -1 when 'n' is even, which makes the result of
    #   '(p - 1)^n % p' be always either '1' (odd 'n') or 'p - 1' (even 'n').
    #   This way, we will have:
    #       A = (p - 1)^a % p =
    #           1,      when 'a' is odd or;
    #           (p - 1) when 'a' is even.
    #       B = (p - 1)^b % p =
    #           1,      when 'b' is odd or;
    #           (p - 1) when 'b' is even.
    #       sA = B^a % p =
    #           1,      when B is 1 or;
    #           1,      when B is (p - 1) and 'a' is odd or;
    #           (p - 1) otherwise.
    #       sB = A^b % p =
    #           1,      when A is 1 or;
    #           1,      when A is (p - 1) and 'b' is odd or;
    #           (p - 1) otherwise.
    # So, in this case, we're forcing the shared session key 's' to be
    # always either '1' or 'p - 1'. To know exactly which one is the
    # right one, we can explore the fact that the PKCS#7 un-padding
    # will tell us that there's an un-padding error, meaning that the
    # key was wrong, so we can tell which of the 2 possibilities is
    # the correct one.

    if hacked_g == 1:
        return 1

    if hacked_g == p:
        return 0

    # The case where 'hacked_g = p - 1'.
    assert hacked_g == (p - 1)

    # Try both possible key values.
    # Decrypt and check if there's a PKCS#7 unpad error.
    # The right value is the one not causing the error.
    s_possibilities = [1, p - 1]
    for s in s_possibilities:
        s_b = s.to_bytes((s.bit_length() + 7) // 8, 'big')
        k = utils.sha1_mac(b'', s_b)[:16]
        pt_b = utils.aes_decrypt(ct_b, k, mode = "CBC", iv = iv_b)
        try:
            msg_b = utils.pkcs7_unpad(pt_b, 16)
        except Exception:
            # Unpadding incorrect, so this is not the key!
            pass
        else:
            # No unpad error, so this is the key!
            return s

    # Reaching here would mean neither key possibilities
    # were correct!
    raise Exception("mitm: get_session_key: Could not find key when hacked_g = p - 1")

def request_handler(rh):
    """Execute the challenge's MITM protocol."""

    # Get a Socket IO utility object for the MITM server.
    mitm_sock_io = utils.CpSocketIO(rh)

    # Create the socket to connect to server.
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server = (server_addr, server_port)

    try:
        print("")
        print("=" * 60)
        print("mitm: New request")
        print("=" * 60)

        # A->M: Send "p", "g".
        debug_msg("mitm: Receiving 'p' from client...", end = '', flush = True)
        p = mitm_sock_io.readnum()
        debug_msg("done:\n  p = [{0}]".format(p))
        debug_msg("mitm: Receiving 'g' from client...", end = '', flush = True)
        g = mitm_sock_io.readnum()
        debug_msg("done:\n  g = [{0}]".format(g))

        # Connect to real server.
        debug_msg("-" * 60)
        debug_msg("mitm: Connecting to real server {0}:{1}...".format(server_addr, server_port),
                end = '', flush = True)
        server_sock.connect(server)
        # Get a Socket IO utility object for the MITM server.
        server_sock_io = utils.CpSocketIO(server_sock)
        debug_msg("done")

        # Set the hacked 'g' value that we will be forcing.
        if hack_choice == 1:
            hacked_g = 1
        elif hack_choice == 2:
            hacked_g = p
        elif hack_choice == 3:
            hacked_g = p - 1
        else:
            raise Exception("mitm: Invalid hack choice: {0}".format(hack_choice))

        # M->B: Relay "p", hacked "g" to server.
        debug_msg("-" * 60)
        debug_msg("mitm: Relaying 'p' to server...", end = '', flush = True)
        server_sock_io.writenum(p)
        debug_msg("done:\n  p = [{0}]".format(p))
        debug_msg("mitm: Relaying HACKED 'g' to server...", end = '', flush = True)
        server_sock_io.writenum(hacked_g)
        debug_msg("done:\n  hacked_g = [{0}]".format(hacked_g))

        # B->M: Send ACK (negotiated "p", "g").
        debug_msg("-" * 60)
        debug_msg("mitm: Receiving negotiated 'p' from server...", end = '', flush = True)
        server_p = server_sock_io.readnum()
        debug_msg("done:\n  server_p = [{0}]".format(server_p))
        debug_msg("mitm: Receiving negotiated 'g' from server...", end = '', flush = True)
        server_g = server_sock_io.readnum()
        debug_msg("done:\n  server_g = [{0}]".format(server_g))

        # M->A: Relay negotiated "p", hacked "g" to client.
        debug_msg("-" * 60)
        debug_msg("mitm: Relaying negotiated 'p' to client...", end = '', flush = True)
        mitm_sock_io.writenum(server_p)
        debug_msg("done:\n  server_p = [{0}]".format(server_p))
        debug_msg("mitm: Relaying HACKED 'g' to client...", end = '', flush = True)
        mitm_sock_io.writenum(hacked_g)
        debug_msg("done:\n  hacked_g = [{0}]".format(hacked_g))

        # A->M: Send "A".
        debug_msg("-" * 60)
        debug_msg("mitm: Receiving 'A' from client...", end = '', flush = True)
        A = mitm_sock_io.readnum()
        debug_msg("done:\n  A = [{0}]".format(A))

        # M->B: Relay "A" to server.
        debug_msg("-" * 60)
        debug_msg("mitm: Relaying 'A' to server...", end = '', flush = True)
        server_sock_io.writenum(A)
        debug_msg("done:\n  A = [{0}]".format(A))

        # B->M: Send "B".
        debug_msg("-" * 60)
        debug_msg("mitm: Receiving 'B' from server...", end = '', flush = True)
        B = server_sock_io.readnum()
        debug_msg("done:\n  B = [{0}]".format(B))

        # M->B: Relay "A" to server.
        debug_msg("-" * 60)
        debug_msg("mitm: Relaying 'B' to client...", end = '', flush = True)
        mitm_sock_io.writenum(B)
        debug_msg("done:\n  B = [{0}]".format(B))

        # A->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv.
        debug_msg("-" * 60)
        debug_msg("mitm: Receiving ciphertext from client...", end = '', flush = True)
        ct_b = mitm_sock_io.readbytes()
        debug_msg("done:\n  ct_b = [{0}]".format(ct_b.hex()))
        debug_msg("mitm: Receiving 'iv' from client...", end = '', flush = True)
        iv_b = mitm_sock_io.readbytes()
        debug_msg("done:\n  iv_b = [{0}]".format(iv_b.hex()))

        # M->B: Relay that to B.
        debug_msg("-" * 60)
        debug_msg("mitm: Relaying ciphertext to server...", end = '', flush = True)
        server_sock_io.writebytes(ct_b)
        debug_msg("done:\n  ct_b = [{0}]".format(ct_b.hex()))
        debug_msg("mitm: Relaying 'iv' to server...", end = '', flush = True)
        server_sock_io.writebytes(iv_b)
        debug_msg("done:\n  iv_b = [{0}]".format(iv_b.hex()))

        # B->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv.
        debug_msg("-" * 60)
        debug_msg("mitm: Receiving echo ciphertext from server...", end = '', flush = True)
        server_ct_b = server_sock_io.readbytes()
        debug_msg("done:\n  server_ct_b = [{0}]".format(server_ct_b.hex()))
        debug_msg("mitm: Receiving echo 'iv' from server...", end = '', flush = True)
        server_iv_b = server_sock_io.readbytes()
        debug_msg("done:\n  server_iv_b = [{0}]".format(server_iv_b.hex()))

        # M->A: Relay that to A.
        debug_msg("-" * 60)
        debug_msg("mitm: Relaying echo ciphertext to client...", end = '', flush = True)
        mitm_sock_io.writebytes(server_ct_b)
        debug_msg("done:\n  server_ct_b = [{0}]".format(server_ct_b.hex()))
        debug_msg("mitm: Relaying echo 'iv' to client...", end = '', flush = True)
        mitm_sock_io.writebytes(server_iv_b)
        debug_msg("done:\n  server_iv_b = [{0}]".format(server_iv_b.hex()))

        # Decrypt the messages exchanged.
        #
        # The MITM attacker has the possibility to manipulate the 'g' value
        # agreed between client and server. With this power, it can use 'g'
        # values such that can cause the shared session key to be predictable,
        # thus having the power to derive the key used for the message
        # encryption/decryption and getting full access to the messages
        # exchanged.

        # Get the shared session key that we forced by hacking 'g'.
        debug_msg("-" * 60)
        debug_msg("mitm: Determining session key...", end = '', flush = True)
        s = get_session_key(p, hacked_g, ct_b, iv_b)
        debug_msg("done:\n  s = [{0}]".format(s))

        debug_msg("-" * 60)
        debug_msg("mitm: Decrypting messages...", end = '', flush = True)
        s_b = s.to_bytes((s.bit_length() + 7) // 8, 'big')
        k = utils.sha1_mac(b'', s_b)[:16]
        pt_b = utils.aes_decrypt(ct_b, k, mode = "CBC", iv = iv_b)
        msg_b = utils.pkcs7_unpad(pt_b, 16)
        msg = utils.bytes2rawstr(msg_b)
        server_pt_b = utils.aes_decrypt(server_ct_b, k, mode = "CBC", iv = server_iv_b)
        server_msg_b = utils.pkcs7_unpad(server_pt_b, 16)
        server_msg = utils.bytes2rawstr(server_msg_b)
        debug_msg("done:")
        debug_msg("  s            = [{0}]".format(s))
        debug_msg("  k            = [{0}]".format(k.hex()))
        debug_msg("  pt_b         = [{0}]".format(pt_b))
        debug_msg("  msg_b        = [{0}]".format(msg_b))
        print("  msg          = [{0}]".format(msg))
        debug_msg("  server_pt_b  = [{0}]".format(server_pt_b))
        debug_msg("  server_msg_b = [{0}]".format(server_msg_b))
        print("  server_msg   = [{0}]".format(server_msg))

        print("=" * 60)
    except OSError as os_err:
        print("\nserver: OSError: ({0}, {1})".format(os_err.errno, os_err.strerror))
    except Exception:
        print("\nserver: Exception")
    finally:
        # Make sure the socket used to connect to the real server is closed.
        server_sock.close()

def execute_server(addr, port):
    """Run the MITM server/client as required by the challenge."""

    # Create and run the TCP MITM server.
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
        print("{0}: mitm_addr   = [{1}]".format(me, mitm_addr))
        print("{0}: mitm_port   = [{1}]".format(me, mitm_port))
        print("{0}: server_addr = [{1}]".format(me, server_addr))
        print("{0}: server_port = [{1}]".format(me, server_port))
        print("{0}: hack_choice = [{1}]".format(me, hack_choice))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Running MITM server...".format(me))
        print("{0}: (Ctrl+C to abort)".format(me))
        print("{0}: ".format(me) + "-" * 60)
        execute_server(mitm_addr, mitm_port)
        # Not supposed to reach this point.
        err_str = "\n{0}: ".format(me) + "-" * 60
        err_str += "\n{0}: MITM RUN    = [FAILED] Exited unexpectedly.".format(me)
        err_str += "\n{0}: ".format(me) + "-" * 60
        raise Exception(err_str)
    except KeyboardInterrupt:
        # Correct exit point by Ctrl+C.
        print("")
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: MITM RUN    = [OK] Aborted by user.".format(me))
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


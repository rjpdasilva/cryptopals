"""Cryptopals Challenges: Test Challenge 34: Implement a MITM key-fixing attack on Diffie-Hellman
with parameter injection: MITM."""

import sys
import utils.cp_aux_utils as utils
import socket

title = "Challenge 34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection: MITM"

# MITM Server address and port.
mitm_addr = None
mitm_port = None

# Real Server address and port.
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
    print("{0}: usage: {0} <mitm_addr> <mitm_port> <server_addr> <server_port>".format(me))

def get_args(me):
    """Script argument parsing."""

    global mitm_addr
    global mitm_port
    global server_addr
    global server_port

    if len(sys.argv) != 5:
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

    return True

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

        # A->M: Send "p", "g", "A".
        debug_msg("mitm: Receiving 'p' from client...", end = '', flush = True)
        p = mitm_sock_io.readnum()
        debug_msg("done:\n  p = [{0}]".format(p))
        debug_msg("mitm: Receiving 'g' from client...", end = '', flush = True)
        g = mitm_sock_io.readnum()
        debug_msg("done:\n  g = [{0}]".format(g))
        debug_msg("mitm: Receiving 'A' from client...", end = '', flush = True)
        A = mitm_sock_io.readnum()
        debug_msg("done:\n  A = [{0}]".format(A))

        # Connect to real server.
        debug_msg("-" * 60)
        debug_msg("mitm: Connecting to real server {0}:{1}...".format(server_addr, server_port),
                end = '', flush = True)
        server_sock.connect(server)
        # Get a Socket IO utility object for the MITM server.
        server_sock_io = utils.CpSocketIO(server_sock)
        debug_msg("done")

        # M->B: Send "p", "g", "p".
        debug_msg("-" * 60)
        debug_msg("mitm: Sending 'p' to server...", end = '', flush = True)
        server_sock_io.writenum(p)
        debug_msg("done:\n  p = [{0}]".format(p))
        debug_msg("mitm: Sending 'g' to server...", end = '', flush = True)
        server_sock_io.writenum(g)
        debug_msg("done:\n  g = [{0}]".format(g))
        debug_msg("mitm: Sending 'p' to server (as if it was 'A')...", end = '', flush = True)
        server_sock_io.writenum(p)
        debug_msg("done:\n  p = [{0}]".format(p))

        # B->M: Send "B".
        debug_msg("-" * 60)
        debug_msg("mitm: Receiving 'B' from server...", end = '', flush = True)
        B = server_sock_io.readnum()
        debug_msg("done:\n  B = [{0}]".format(B))

        # M->A: Send "p" as if it was B.
        debug_msg("-" * 60)
        debug_msg("mitm: Sending 'p' to client (as if it was 'B')...", end = '', flush = True)
        mitm_sock_io.writenum(p)
        debug_msg("done:\n  p = [{0}]".format(p))

        # A->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv.
        debug_msg("-" * 60)
        debug_msg("mitm: Receiving ciphertext from client...", end = '', flush = True)
        ct_b = mitm_sock_io.readbytes()
        debug_msg("done:\n  ct_b = [{0}]".format(ct_b.hex()))
        debug_msg("mitm: Receiving 'iv' from client...", end = '', flush = True)
        iv_b = mitm_sock_io.readbytes()
        debug_msg("done:\n  iv_b = [{0}]".format(iv_b.hex()))

        # M->B: Relay that to B.
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
        debug_msg("mitm: Relaying echo ciphertext to client...", end = '', flush = True)
        mitm_sock_io.writebytes(server_ct_b)
        debug_msg("done:\n  server_ct_b = [{0}]".format(server_ct_b.hex()))
        debug_msg("mitm: Relaying echo 'iv' to client...", end = '', flush = True)
        mitm_sock_io.writebytes(server_iv_b)
        debug_msg("done:\n  server_iv_b = [{0}]".format(server_iv_b.hex()))

        # Decrypt the messages exchanged.
        #
        # By sending 'p' as 'A' to the server and 'p' as 'B' to the client,
        # we, the MITM attacker, are causing both to reach a shared session
        # key ('s') with a value of zero, not matter what values were chosen
        # for 'p' and/or 'g':
        #
        # We have:
        #   A = g^a % p
        #   B = g^b % p
        # Then, both A and B calculate the same shared session key:
        #   A: s = B^a % p
        #   B: s = A^b % p
        # By forcing A = B = p (the attack done here), we get:
        #   A: s = p^a % p = 0
        #   B: s = p^b % p = 0
        # The result is zero because the 'p' modulus of any 'p' power (exp > 0)
        # is zero by definition, simply because a 'p' power (exp > 0) is a
        # multiple of 'p' and thus, its 'p' modulus is zero.
        #
        # So, with this attack we know the shared key 's' is zero. With that
        # info, we can derive the AES-CBC key used and decrypt the messages.
        debug_msg("mitm: Decrypting messages...", end = '', flush = True)
        s = 0
        s_b = s.to_bytes((s.bit_length() + 7) // 8, 'big')
        k = utils.sha1_mac(b'', s_b)[:16]
        pt_b = utils.aes_decrypt(ct_b, k, mode = "CBC", iv = iv_b)
        msg_b = utils.pkcs7_unpad(pt_b, 16)
        msg = utils.bytes2rawstr(msg_b)
        server_pt_b = utils.aes_decrypt(server_ct_b, k, mode = "CBC", iv = server_iv_b)
        server_msg_b = utils.pkcs7_unpad(server_pt_b, 16)
        server_msg = utils.bytes2rawstr(server_msg_b)
        debug_msg("done:")
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


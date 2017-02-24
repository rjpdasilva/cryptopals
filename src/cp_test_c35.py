"""Cryptopals Challenges: Test Challenge 35: Implement DH with negotiated groups, and break with
malicious 'g' parameters: Client."""

import sys
import utils.cp_aux_utils as utils
import socket

title = "Challenge 35: Implement DH with negotiated groups, and break with malicious 'g' parameters: Client"

# Server address, port and message to send.
server_addr = None
server_port = None
client_msg = None

# Diffie-Hellman (p, g) parameters being used initially.
p_init = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g_init = 2

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
    print("{0}: usage: {0} <server_addr> <server_port> '<msg_to_send>'".format(me))

def get_args(me):
    """Script argument parsing."""

    global server_addr
    global server_port
    global client_msg

    if len(sys.argv) != 4:
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
    client_msg = sys.argv[3]

    return True

def execute_client(addr, port, msg, p, g):
    """Execute the challenge's client protocol."""

    (a, A, B, s, k, server_msg) = (None, None, None, None, None, None)

    # Create the client socket, connect to server and execute
    # the protocol.
    server = (addr, port)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Get a Socket IO utility object.
        sock_io = utils.CpSocketIO(sock)

        try:
            # Connect to server.
            debug_msg("-" * 60)
            debug_msg("client: Connecting to server {0}:{1}...".format(addr, port), end = '', flush = True)
            sock.connect(server)
            debug_msg("done")

            # A->B: Send "p", "g".
            debug_msg("-" * 60)
            debug_msg("client: Sending 'p'...", end = '', flush = True)
            sock_io.writenum(p)
            debug_msg("done:\n  p = [{0}]".format(p))
            debug_msg("client: Sending 'g'...", end = '', flush = True)
            sock_io.writenum(g)
            debug_msg("done:\n  g = [{0}]".format(g))

            # B->A: Send ACK (negotiated "p", "g").
            debug_msg("-" * 60)
            debug_msg("client: Receiving negotiated 'p'...", end = '', flush = True)
            p = sock_io.readnum()
            debug_msg("done:\n  p = [{0}]".format(p))
            debug_msg("client: Receiving negotiated 'g'...", end = '', flush = True)
            g = sock_io.readnum()
            debug_msg("done:\n  g = [{0}]".format(g))

            # Create the client's DH key pair.
            debug_msg("-" * 60)
            debug_msg("client: Generating DH keys...", end = '', flush = True)
            (a, A) = utils.dh_keys(p, g)
            debug_msg("done:\n  a = [{0}]\n  A = [{1}]".format(a, A))

            # A->B: Send "A".
            debug_msg("-" * 60)
            debug_msg("client: Sending 'A'...", end = '', flush = True)
            sock_io.writenum(A)
            debug_msg("done:\n  A = [{0}]".format(A))

            # B->A: Send "B".
            debug_msg("-" * 60)
            debug_msg("client: Receiving 'B'...", end = '', flush = True)
            B = sock_io.readnum()
            debug_msg("done:\n  B = [{0}]".format(B))

            # Generate the session key ('s') and derive the
            # AES-CBC key ('k') from it.
            debug_msg("-" * 60)
            debug_msg("client: Generating keys and encrypting...", end = '', flush = True)
            s = utils.dh_session_key(B, a, p)
            s_b = s.to_bytes((s.bit_length() + 7) // 8, 'big')
            k = utils.sha1_mac(b'', s_b)[:16]
            # Generate a random IV and encrypt the message with the
            # AES-CBC key.
            iv_b = utils.rand_bytes(16)
            msg_b = utils.rawstr2bytes(msg)
            pt_b = utils.pkcs7_pad(msg_b, 16)
            ct_b = utils.aes_encrypt(pt_b, k, mode = "CBC", iv = iv_b)
            debug_msg("done:")
            debug_msg("  s     = [{0}]".format(s))
            debug_msg("  k     = [{0}]".format(k.hex()))
            debug_msg("  msg_b = [{0}]".format(msg_b))
            debug_msg("  pt_b  = [{0}]".format(pt_b))
            debug_msg("  iv_b  = [{0}]".format(iv_b.hex()))
            debug_msg("  ct_b  = [{0}]".format(ct_b.hex()))

            # A->B: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv.
            debug_msg("-" * 60)
            debug_msg("client: Sending ciphertext...", end = '', flush = True)
            sock_io.writebytes(ct_b)
            debug_msg("done:\n  ct_b = [{0}]".format(ct_b.hex()))
            debug_msg("client: Sending 'iv'...", end = '', flush = True)
            sock_io.writebytes(iv_b)
            debug_msg("done:\n  iv_b = [{0}]".format(iv_b.hex()))

            # B->A: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv.
            debug_msg("-" * 60)
            debug_msg("client: Receiving ciphertext...", end = '', flush = True)
            server_ct_b = sock_io.readbytes()
            debug_msg("done:\n  server_ct_b = [{0}]".format(server_ct_b.hex()))
            debug_msg("client: Receiving 'iv'...", end = '', flush = True)
            server_iv_b = sock_io.readbytes()
            debug_msg("done:\n  server_iv_b = [{0}]".format(server_iv_b.hex()))

            # Decrypt the server message.
            debug_msg("-" * 60)
            debug_msg("client: Decrypting...", end = '', flush = True)
            server_pt_b = utils.aes_decrypt(server_ct_b, k, mode = "CBC", iv = server_iv_b)
            server_msg_b = utils.pkcs7_unpad(server_pt_b, 16)
            server_msg = utils.bytes2rawstr(server_msg_b)
            debug_msg("done:")
            debug_msg("  server_pt_b  = [{0}]".format(server_pt_b))
            debug_msg("  server_msg_b = [{0}]".format(server_msg_b))
            debug_msg("  server_msg   = [{0}]".format(server_msg))
        except OSError as os_err:
            print("\nclient: OSError: ({0}, {1})".format(os_err.errno, os_err.strerror))
        except Exception:
            print("\nclient: Exception")

    return (p, g, a, A, B, s, k, server_msg)

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
        print("{0}: client_msg  = [{1}]".format(me, client_msg))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Executing...".format(me))
        print("{0}: ".format(me) + "-" * 60)
        debug_msg("")
        (p, g, a, A, B, s, k, server_msg) = \
                execute_client(server_addr, server_port, client_msg, p_init, g_init)
        ok = (server_msg == client_msg)
        debug_msg("")
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Executing...done".format(me))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: success     = [{1}]".format(me, ok))
        if ok:
            print("{0}: server_msg  = [{1}]".format(me, server_msg))
            print("{0}: p           = [{1}]".format(me, p))
            print("{0}: g           = [{1}]".format(me, g))
            print("{0}: a           = [{1}]".format(me, a))
            print("{0}: A           = [{1}]".format(me, A))
            print("{0}: B           = [{1}]".format(me, B))
            print("{0}: s           = [{1}]".format(me, s))
            print("{0}: k           = [{1}]".format(me, k.hex()))
        if not ok:
            err_str = "\n{0}: ".format(me) + "-" * 60
            err_str += "\n{0}: TEST        = [FAILED] Result doesn't match expected.".format(me)
            err_str += "\n{0}: ".format(me) + "-" * 60
            raise Exception(err_str)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: TEST        = [OK]".format(me))
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


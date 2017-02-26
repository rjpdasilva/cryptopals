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

"""Cryptopals Challenges: Test Challenge 36: Implement Secure Remote Password (SRP): Server."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 36: Implement Secure Remote Password (SRP): Server"

# Server address and port.
server_addr = None
server_port = None

# Client user and password.
user = None
password = None

# Static parameters agreed upon client and server.
N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3

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
    print("{0}: usage: {0} <server_addr> <server_port> '<user>' '<password>'".format(me))

def get_args(me):
    """Script argument parsing."""

    global server_addr
    global server_port
    global user
    global password

    if len(sys.argv) != 5:
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

    user = sys.argv[3]
    password = sys.argv[4]

    return True

def request_handler(rh):
    """Execute the challenge's server protocol."""

    # Get a Socket IO utility object.
    sock_io = utils.CpSocketIO(rh)

    print("")
    print("=" * 60)
    print("server: New request")
    print("=" * 60)

    # S:
    #   1. Generate salt as random integer.
    #   2. Generate string xH=SHA256(salt|password).
    #   3. Convert xH to integer x somehow (put 0x on hexdigest).
    #   4. Generate v=g**x % N.
    #   5. Save everything but x, xH.
    debug_msg("server: Generating server keys...", end = '', flush = True)
    salt = int(utils.rand_bytes(8).hex(), 16)
    xH = utils.sha256_mac(b'', utils.rawstr2bytes(str(salt) + password))
    x = int(xH.hex(), 16)
    v = pow(g, x, N)
    (b, B) = utils.dh_keys(N, g)
    B += (k * v)
    debug_msg("done:")
    debug_msg("  salt = [{0}]".format(salt))
    debug_msg("  v    = [{0}]".format(v))
    debug_msg("  b    = [{0}]".format(b))
    debug_msg("  B    = [{0}]".format(B))

    try:
        # C->S: Send I, A=g**a % N (a la Diffie-Hellman).
        debug_msg("-" * 60)
        debug_msg("server: Receiving 'I'...", end = '', flush = True)
        I = sock_io.readbytes()
        debug_msg("done:")
        print("  I = [{0}]".format(I))
        debug_msg("server: Receiving 'A'...", end = '', flush = True)
        A = sock_io.readnum()
        debug_msg("done:\n  A = [{0}]".format(A))

        # S->C: Send salt, B=kv + g**b % N.
        debug_msg("-" * 60)
        debug_msg("server: Sending 'salt'...", end = '', flush = True)
        sock_io.writenum(salt)
        debug_msg("done:\n  salt = [{0}]".format(salt))
        debug_msg("server: Sending 'B'...", end = '', flush = True)
        sock_io.writenum(B)
        debug_msg("done:\n  B = [{0}]".format(B))

        # S, C: Compute string uH = SHA256(A|B), u = integer of uH.
        debug_msg("-" * 60)
        debug_msg("server: Computing 'u'...", end = '', flush = True)
        AB_str = str(A) + str(B)
        uH = utils.sha256_mac(b'', utils.rawstr2bytes(AB_str))
        u = int(uH.hex(), 16)
        debug_msg("done:\n  u = [{0}]".format(u))

        # S: Generate K.
        #   1. Generate S = (A * v**u) ** b % N.
        #   2. Generate K = SHA256(S).
        debug_msg("-" * 60)
        debug_msg("server: Generating 'K'...", end = '', flush = True)
        Sb = (A * pow(v, u, N))
        S = pow(Sb, b, N)
        K = utils.sha256_mac(b'', utils.rawstr2bytes(str(S)))
        debug_msg("done:")
        debug_msg("  S = [{0}]".format(S))
        debug_msg("  K = [{0}]".format(K.hex()))

        # C->S: Send HMAC-SHA256(K, salt).
        debug_msg("-" * 60)
        debug_msg("server: Receiving 'auth'...", end = '', flush = True)
        auth = sock_io.readbytes()
        debug_msg("done:\n  auth = [{0}]".format(auth.hex()))

        # S->C: Send "OK" if HMAC-SHA256(K, salt) validates.
        debug_msg("-" * 60)
        debug_msg("server: Sending 'auth_msg'...", end = '', flush = True)
        auth_msg_b = b'NOT OK'
        server_auth = utils.sha256_hmac(K, utils.rawstr2bytes(str(salt)))
        server_I = utils.rawstr2bytes(user)
        if I == server_I and auth == server_auth:
            auth_msg_b = b'OK'
        sock_io.writebytes(auth_msg_b)
        debug_msg("done:")
        debug_msg("  auth        = [{0}]".format(auth.hex()))
        debug_msg("  server_auth = [{0}]".format(server_auth.hex()))
        print("  auth_msg    = [{0}]".format(auth_msg_b))

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
        print("{0}: user        = [{1}]".format(me, user))
        print("{0}: password    = [{1}]".format(me, password))
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


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

"""Cryptopals Challenges: Test Challenge 36: Implement Secure Remote Password (SRP): Client."""

import sys
import utils.cp_aux_utils as utils
import socket

title = "Challenge 36: Implement Secure Remote Password (SRP): Client"

# Server address and port.
server_addr = None
server_port = None

# Client user and password.
user = None
password = None

# Static parameters agreed upon client and server.
N_init = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g_init = 2
k_init = 3

# Forcing 'A' by argument.
# 'None' means not forcing 'A'.
# Any integer value 'n >= 0' means 'A = n * N', i.e., 'A' is a multiple of 'N'.
forced_A_m = None

# Debug flag.
debug = 0

# Debug messages.
def debug_msg(*args, **kwargs):
    """Extra debug messages."""
    if not debug:
        return
    print(*args, **kwargs)

def usage(me, allow_forced_A, err_msg = None):
    """Show script usage."""
    if err_msg != None:
        print(err_msg)
    print("{0}: usage: {0} <server_addr> <server_port> '<user>' '<password>'{1}"
            .format(me, " [<forced_A_m>]" if allow_forced_A else ""))

def get_args(me, allow_forced_A):
    """Script argument parsing."""

    global server_addr
    global server_port
    global user
    global password
    global forced_A_m

    if len(sys.argv) < 5:
        usage(me, allow_forced_A, "{0}: Error: Missing arguments".format(me))
        return False
    if allow_forced_A:
        max_args = 6
    else:
        max_args = 5
    if len(sys.argv) > max_args:
        usage(me, allow_forced_A, "{0}: Error: Too many arguments".format(me))
        return False

    server_addr = sys.argv[1]
    server_port = sys.argv[2]
    try:
        server_port = int(server_port)
    except:
        usage(me, allow_forced_A, "{0}: Error: Invalid <server_port> value: {1}. Must be integer > 0"
                .format(me, server_port))
        return False
    if server_port <= 0:
        usage(me, allow_forced_A, "{0}: Error: Invalid <server_port> value: {1}. Must be integer > 0"
                .format(me, server_port))
        return False

    user = sys.argv[3]
    password = sys.argv[4]

    if allow_forced_A and len(sys.argv) == 6:
        forced_A_m = sys.argv[5]
        try:
            forced_A_m = int(forced_A_m)
        except:
            usage(me, allow_forced_A, "{0}: Error: Invalid <forced_A_m> value: {1}. Must be integer >= 0"
                    .format(me, forced_A_m))
            return False
        if forced_A_m < 0:
            usage(me, allow_forced_A, "{0}: Error: Invalid <forced_A_m> value: {1}. Must be integer > 0"
                    .format(me, forced_A_m))
            return False

    return True

def execute_client(addr, port, user, password, N, g, k, fAm):
    """Execute the challenge's client protocol."""

    (a, A, salt, B, u, S, K, auth_msg) = \
            (None, None, None, None, None, None, None, "NOT OK")

    # Create the client's DH key pair.
    debug_msg("-" * 60)
    debug_msg("client: Generating DH keys...", end = '', flush = True)
    (a, A) = utils.dh_keys(N, g)
    if fAm is not None:
        A = fAm * N
    debug_msg("done:\n  a  = [{0}]\n  {1} = [{2}]"
            .format(a, "A " if fAm is None else "fAm", A))

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

            # C->S: Send I, A=g**a % N (a la Diffie-Hellman).
            I = utils.rawstr2bytes(user)
            debug_msg("-" * 60)
            debug_msg("client: Sending 'I'...", end = '', flush = True)
            sock_io.writebytes(I)
            debug_msg("done:\n  I = [{0}]".format(I))
            debug_msg("client: Sending 'A'...", end = '', flush = True)
            sock_io.writenum(A)
            debug_msg("done:\n  A = [{0}]".format(A))

            # S->C: Send salt, B=kv + g**b % N.
            debug_msg("-" * 60)
            debug_msg("client: Receiving 'salt'...", end = '', flush = True)
            salt = sock_io.readnum()
            debug_msg("done:\n  salt = [{0}]".format(salt))
            debug_msg("client: Receiving 'B'...", end = '', flush = True)
            B = sock_io.readnum()
            debug_msg("done:\n  B = [{0}]".format(B))

            # S, C: Compute string uH = SHA256(A|B), u = integer of uH.
            debug_msg("-" * 60)
            debug_msg("client: Computing 'u'...", end = '', flush = True)
            AB_str = str(A) + str(B)
            uH = utils.sha256_mac(b'', utils.rawstr2bytes(AB_str))
            u = int(uH.hex(), 16)
            debug_msg("done:\n  u = [{0}]".format(u))

            # C: Generate K.
            #   1. Generate string xH=SHA256(salt|password).
            #   2. Convert xH to integer x somehow (put 0x on hexdigest).
            #   3. Generate S = (B - k * g**x)**(a + u * x) % N.
            #   4. Generate K = SHA256(S).
            debug_msg("-" * 60)
            if fAm is None:
                debug_msg("client: Generating 'K'...", end = '', flush = True)
                xH = utils.sha256_mac(b'', utils.rawstr2bytes(str(salt) + password))
                x = int(xH.hex(), 16)
                Sb = (B - k * pow(g, x, N))
                Se = (a + u * x)
                S = pow(Sb, Se, N)
            else:
                debug_msg("client: Generating 'K' (with forced 'A')...", end = '', flush = True)
                # When we force 'A' to be a multiple of 'N', we're forcing
                # the server to always have 'S = 0', because it uses:
                #   'S = (A * v**u) ** b % N',
                # meaning that '(A * v**u) ** b' will always be a factor of 'N', so
                # its modulus 'N' will always be zero!
                S = 0
            K = utils.sha256_mac(b'', utils.rawstr2bytes(str(S)))
            debug_msg("done:")
            debug_msg("  S = [{0}]".format(S))
            debug_msg("  K = [{0}]".format(K.hex()))

            # C->S: Send HMAC-SHA256(K, salt).
            auth = utils.sha256_hmac(K, utils.rawstr2bytes(str(salt)))
            debug_msg("-" * 60)
            debug_msg("client: Sending 'auth'...", end = '', flush = True)
            sock_io.writebytes(auth)
            debug_msg("done:\n  auth = [{0}]".format(auth.hex()))

            # S->C: Send "OK" if HMAC-SHA256(K, salt) validates.
            debug_msg("-" * 60)
            debug_msg("client: Receiving 'auth_msg...", end = '', flush = True)
            auth_msg_b = sock_io.readbytes()
            auth_msg = utils.bytes2rawstr(auth_msg_b)
            debug_msg("done:\n  auth_msg = [{0}]".format(auth_msg))
            debug_msg("-" * 60)
        except OSError as os_err:
            print("\nclient: OSError: ({0}, {1})".format(os_err.errno, os_err.strerror))
        except Exception:
            print("\nclient: Exception")

    return (N, g, k, a, A, salt, B, u, S, K, auth_msg)

def main(me, title, allow_forced_A):
    """Challenge's main executing function."""

    # This script needs arguments, so get them.
    if not get_args(me, allow_forced_A):
        sys.exit(1)
    try:
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: server_addr = [{1}]".format(me, server_addr))
        print("{0}: server_port = [{1}]".format(me, server_port))
        print("{0}: user        = [{1}]".format(me, user))
        print("{0}: password    = [{1}]".format(me, password))
        if allow_forced_A:
            print("{0}: forced_A_m  = [{1}]".format(me, forced_A_m))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Executing...".format(me))
        print("{0}: ".format(me) + "-" * 60)
        debug_msg("")
        (N, g, k, a, A, salt, B, u, S, K, auth_msg) = \
                execute_client(server_addr, server_port, user, password, N_init, g_init, k_init,
                        forced_A_m)
        ok = (auth_msg == "OK")
        debug_msg("")
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Executing...done".format(me))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: auth_msg    = [{1}]".format(me, auth_msg))
        print("{0}: success     = [{1}]".format(me, ok))
        if ok:
            print("{0}: N           = [{1}]".format(me, N))
            print("{0}: g           = [{1}]".format(me, g))
            print("{0}: k           = [{1}]".format(me, k))
            print("{0}: a           = [{1}]".format(me, a))
            if forced_A_m is None:
                print("{0}: A           = [{1}]".format(me, A))
            else:
                print("{0}: forced_A    = [{1}]".format(me, A))
            print("{0}: salt        = [{1}]".format(me, salt))
            print("{0}: B           = [{1}]".format(me, B))
            print("{0}: u           = [{1}]".format(me, u))
            print("{0}: S           = [{1}]".format(me, S))
            print("{0}: K           = [{1}]".format(me, K.hex()))
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
    main(me, title, False)
    sys.exit(0)


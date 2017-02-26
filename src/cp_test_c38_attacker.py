"""Cryptopals Challenges: Test Challenge 38: Offline dictionary attack on simplified SRP: Attacker."""

# There's a good description about this attack on:
#  http://srp.stanford.edu/ndss.html#SECTION00032300000000000000

import sys
import utils.cp_aux_utils as utils
import time
import threading

title = "Challenge 38: Offline dictionary attack on simplified SRP: Attacker"

# Server address and port.
server_addr = None
server_port = None

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

class PasswordBreaker(threading.Thread):
    """The thread used for the password breaking."""

    def __init__(self, N, g, salt, A, b, u, hmac, identifier):
        """The constructor: gathers the elements required for breaking the password."""
        self._N = N
        self._g = g
        self._salt = salt
        self._A = A
        self._b = b
        self._u = u
        self._hmac = hmac
        self._id = identifier
        super().__init__()

    def get_password_hmac(self, password):
        """Compute the HMAC if the password would be 'password'."""

        xH = utils.sha256_mac(b'', utils.rawstr2bytes(str(self._salt) + password))
        x = int(xH.hex(), 16)
        v = pow(self._g, x, self._N)
        Sb = (self._A * pow(v, self._u, self._N))
        S = pow(Sb, self._b, self._N)
        K = utils.sha256_mac(b'', utils.rawstr2bytes(str(S)))
        hmac = utils.sha256_hmac(K, utils.rawstr2bytes(str(self._salt)))

        return hmac

    def run(self, *args, **kwargs):
        """The thread's main run function."""

        password = None

        # Using '/usr/share/dict/words' for trying passwords.
        words_file = "/usr/share/dict/words"

        # Build a words array.
        with open(words_file) as wf:
            words = [w.strip() for w in wf]

        # Try each word and check if the resulting hash matches the hash
        # given to us by the client.
        last_letter = ''
        tstart = int(time.time())
        for pw in words:
            if pw[0].lower() != last_letter:
                if last_letter != '':
                    print("mitm: {0}: Check passwords starting with '{1}'...done (not found)"
                            .format(self._id, last_letter))
                last_letter = pw[0].lower()
                print("mitm: {0}: Check passwords starting with '{1}'..."
                        .format(self._id, last_letter))
            mitm_hmac = self.get_password_hmac(pw)
            if mitm_hmac == self._hmac:
                password = pw
                print("mitm: {0}: Check passwords starting with '{1}'...done (found)"
                        .format(self._id, last_letter))
                break
        tend = int(time.time())
        tdur = tend - tstart
        if password == None:
            print("mitm: {0}: Check passwords starting with '{1}'...done (not found)"
                    .format(self._id, last_letter))

        print("mitm: {0}: Password break results:".format(self._id))
        print("  result   = [{0}]".format("FAIL" if password is None else "OK"))
        print("  duration = [{0:02d}:{1:02d}] (mm:ss)".format(tdur // 60, tdur % 60))
        if password != None:
            print("  password = [{0}]".format(password))

def request_handler(rh):
    """Execute the challenge's server protocol."""

    # Get a Socket IO utility object.
    sock_io = utils.CpSocketIO(rh)

    print("")
    print("=" * 60)
    print("mitm: New request")
    print("=" * 60)

    # S:
    #   1. Generate salt as random integer.
    #   2. Generate server's Diffie-Hellman key pair.
    debug_msg("mitm: Generating server keys...", end = '', flush = True)
    # Using small integers for 'salt' and '(b, B)' so that
    # the password cracking calculations are faster, thus
    # reducing the overall time needed to crack the password.
    salt = 0
    b = 5
    B = pow(g, b, N)
    debug_msg("done:")
    debug_msg("  salt = [{0}]".format(salt))
    debug_msg("  b    = [{0}]".format(b))
    debug_msg("  B    = [{0}]".format(B))

    try:
        # C->S: Send I, A=g**a % N (a la Diffie-Hellman).
        debug_msg("-" * 60)
        debug_msg("mitm: Receiving 'I'...", end = '', flush = True)
        I = sock_io.readbytes()
        debug_msg("done:")
        print("  I = [{0}]".format(I))
        debug_msg("mitm: Receiving 'A'...", end = '', flush = True)
        A = sock_io.readnum()
        debug_msg("done:\n  A = [{0}]".format(A))

        # S->C: salt, B = g**b % n, u = 128 bit random number.
        debug_msg("-" * 60)
        # Using small integers for 'u' so that the password cracking
        # calculations are faster, thus reducing the overall time
        # needed to crack the password.
        u = 1
        debug_msg("mitm: Sending 'salt'...", end = '', flush = True)
        sock_io.writenum(salt)
        debug_msg("done:\n  salt = [{0}]".format(salt))
        debug_msg("mitm: Sending 'B'...", end = '', flush = True)
        sock_io.writenum(B)
        debug_msg("done:\n  B = [{0}]".format(B))
        debug_msg("mitm: Sending 'u'...", end = '', flush = True)
        sock_io.writenum(u)
        debug_msg("done:\n  u = [{0}]".format(u))

        # C->S: Send HMAC-SHA256(K, salt).
        debug_msg("-" * 60)
        debug_msg("mitm: Receiving 'auth'...", end = '', flush = True)
        auth = sock_io.readbytes()
        debug_msg("done:\n  auth = [{0}]".format(auth.hex()))

        # S->C: Send a fake "OK".
        debug_msg("-" * 60)
        debug_msg("mitm: Sending fake 'OK'...", end = '', flush = True)
        auth_msg_b = b'OK'
        sock_io.writebytes(auth_msg_b)
        debug_msg("done:")
        debug_msg("  auth        = [{0}]".format(auth.hex()))
        print("  auth_msg    = [{0}]".format(auth_msg_b))

        # S: Try to crack the password in a separate thread.
        print("-" * 60)
        identifier = utils.rand_int(1, 9999)
        print("mitm: Launching thread (id={0})) to break password...".format(identifier),
                end = '', flush = True)
        breaker = PasswordBreaker(N, g, salt, A, b, u, auth, identifier)
        breaker.start()
        print("done")

        print("=" * 60)
    except OSError as os_err:
        print("\nmitm: OSError: ({0}, {1})".format(os_err.errno, os_err.strerror))
    #except Exception:
        #print("\nmitm: Exception")

def execute_server(addr, port):
    """Run the server as required by the challenge."""

    # Create and run the TCP server.
    try:
        tcpd = utils.CpTCPServer(addr, port, request_handler)
        tcpd.serve_forever()
    except OSError as os_err:
        print("\nmitm: OSError: ({0}, {1})".format(os_err.errno, os_err.strerror))
    except Exception:
        print("\nmitm: Exception")

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


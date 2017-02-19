"""Cryptopals Challenges: Test Challenge 32: Implement and break HMAC-SHA1 with a slightly less
artificial timing leak."""

import sys
import utils.cp_aux_utils as utils
import cp_test_c31 as c31

title = "Challenge 32: Implement and break HMAC-SHA1 with a slightly less artificial timing leak"

# Web server address and port.
server_addr = ""
server_port = 9000
# Delay used for each HMAC byte that is correct (ms).
server_delay = 3
# Signature size (HMAC-SHA1).
sig_size = 20

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
    #
    # The above was the exactly approach that was used in C31.
    # However, when using a lower server delay (the case of this
    # challenge), the process described above may incorrectly assume
    # a guessed by is correct. This way, the following will be done
    # for having a better informed guess about each byte:
    #  + Send an initial dummy request to server just to get it
    #    running, because it has been noticed that the 1st request
    #    has some extra delay associated with it.
    #  + Measure the delay for all the possible byte values, instead
    #    of assuming that a delay passing the threshold means the
    #    byte is correctly guessed. This is because the delay for
    #    some wrong byte may still be beyond the expected delay
    #    threshold, when the delay is smaller.
    #  + Do the delay measuring for all byte values more than once,
    #    so that a statistical average can be computed. Required
    #    because there may be some sporadic internal server delays
    #    for some measurements.
    #  + Once the delay for each possible byte value is averaged,
    #    finding the correct byte will be the one having the maximum
    #    averaged delay, provided that the delay itself is over the
    #    expected delay threshold for a correct byte.
    #
    # On top, also make some additional consistency checks on the
    # average delta for the current byte as compared to the one for
    # the previous byte and the absolute average delta value itself,
    # to detect cases where we've guessed the previous byte
    # incorrectly, causing the accumulated delay to get a suspicious
    # value. In these cases, the process aborts guessing the current
    # byte and goes back to retry guessing the previous byte.

    # Do the initial dummy request.
    c31.http_check_file_signature(file_name, b'\x00' * sig_size, addr, port)

    sig_broken = b''
    rounds = 10
    delta_diff = None
    deltas_avg = [0] * sig_size
    while len(sig_broken) < sig_size:
        l = len(sig_broken)
        missing = sig_size - l
        print("Guessing byte {0:02d}...".format(l + 1), end = '', flush = True)
        # Measure all byte values' delay. Do it 'rounds' times.
        deltas = [0] * 256
        for i in range(rounds):
            for v in range(256):
                v_b = bytes([v])
                sig = sig_broken + v_b + b'\x00' * (missing - 1)
                (ok, delta) = c31.http_check_file_signature(file_name, sig, addr, port)
                deltas[v] += delta
        # Average the deltas per round.
        deltas = [(deltas[i] / rounds) for i in range(256)]
        # Get the average delta.
        delta_avg = sum(deltas) / 256
        # Get the byte value which has the highest delay.
        delta_max_v = max(range(256), key = (lambda x: deltas[x]))
        delta_max = deltas[delta_max_v]
        v_b = bytes([delta_max_v])

        # Make some checks on the current byte's delta average:
        #  + Must be >= than the sum of deltas for each known byte.
        #  + Most not be > than the sum of deltas for each known byte
        #    plus the byte being guessed plus the next 2 bytes (a
        #    large safety margin).
        #  + The delay diff to the latest delta average must exceed
        #    the delay for one correct byte.
        if delta_avg < (l * delay):
                # Previous byte is not correct.
                print("fail: v={0}, davg={1:7.3f} < {2} (1)"
                        .format(v_b.hex(), delta_avg, l * delay))
                # Retry previous byte.
                sig_broken = sig_broken[:-1]
                continue
        if delta_avg > ((l + 4) * delay):
                # Previous byte is not correct.
                print("fail: v={0}, davg={1:7.3f} > {2} (2)"
                        .format(v_b.hex(), delta_avg, (l + 4) * delay))
                # Retry previous byte.
                sig_broken = sig_broken[:-1]
                continue
        if l > 0:
            delta_diff = abs(deltas_avg[l - 1] - delta_avg)
            if  delta_diff < (delay * 0.9):
                # Previous byte is not correct.
                print("fail: v={0}, davg={1:7.3f}, ldavg={2:7.3f}, diff={3:7.3f} < {4} (3)"
                        .format(v_b.hex(), delta_avg, deltas_avg[l - 1], delta_diff, (delay * 0.9)))
                # Retry previous byte.
                sig_broken = sig_broken[:-1]
                continue

        # Byte considered correct.
        sig_broken += v_b
        print("done: v={0}, d={1:7.3f}, davg={2:7.3f}, ldavg={3:7.3f}, diff={4:7.3f}\n({5}) {6}"
                .format(v_b.hex(), delta_max, delta_avg,
                    deltas_avg[l - 1] if l > 0 else 0,
                    delta_diff if delta_diff != None else 0,
                    "sig-OK" if ok else "sig-KO", sig_broken.hex()))
        deltas_avg[l] = delta_avg

        # Confirm the guessed signature is correct.
        if len(sig_broken) == sig_size:
            print("Confirming sig={0}...".format(sig_broken.hex()), end = '', flush = True)
            (ok, delta) = c31.http_check_file_signature(file_name, sig_broken, addr, port)
            print("done: {0}".format(ok))
            if not ok:
                # Retry last byte.
                sig_broken = sig_broken[:-1]
                continue
            break

    # Confirm the guessed signature is correct.
    if not ok:
        return (False, sig_broken, "Guessed signature is invalid")
    return (True, sig_broken, "Signature was verified")

if __name__ == '__main__':
    me = sys.argv[0]
    c31.main(me, title, server_delay, execute_break_hmac_sha1)
    sys.exit(0)


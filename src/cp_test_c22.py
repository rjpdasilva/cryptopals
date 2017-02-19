"""Cryptopals Challenges: Test Challenge 22: Crack an MT19937 seed."""

import sys
import utils.cp_aux_utils as utils
import time

title = "Challenge 22: Crack an MT19937 seed"

# For taking note of current time in order to simulate time passing.
time_now = None

def mt19937_timestamp_seed():
    """Creates a RNG seeded with a timestamp."""

    global time_now

    print("-" * 60)

    # Mark the 1st time.
    time_now = int(time.time())

    # "Wait a random number of seconds between, I don't know, 40 and 1000."
    # Time passing is by simulation.
    twait = utils.rand_int(40, 1000)
    print("Generate: Simulate waiting {0} seconds...".format(twait))
    time_now += twait
    print("Generate: Simulate waiting {0} seconds...done".format(twait))

    # "Seed the RNG with the current Unix timestamp."
    tnow = time_now
    seed = tnow
    rng = utils.MT19937(seed)
    print("Generate: Seed is {0}".format(seed))

    # "Waits a random number of seconds again."
    twait = utils.rand_int(40, 1000)
    print("Generate: Simulate waiting {0} seconds...".format(twait))
    time_now += twait
    print("Generate: Simulate waiting {0} seconds...done".format(twait))

    # "Returns the first 32 bit output of the RNG."
    num = rng.uint32()
    print("Generate: Number is {0}".format(num))

    return (seed, num)

def execute_break_mt19937_seed(num):
    """Breaks a MT19937 seed, which is known to have been based on a recent timestamp."""

    # The strategy is to "rewind" into the timestamp used when the RNG was
    # seeded, which we know it was recently. This way, we take the current
    # time, use it to create the RNG, get the 1st generated number and
    # compare it with the 'num' received. If not matching, we try again 1
    # second in the past, i.e., we subtract 1 second to the current timestamp
    # and try again. Eventually, with enough iterations, we will create the
    # RNG with the same timestamp, and that will give us the same 1st generated
    # number.

    print("-" * 60)
    print("Cracking: Number is {0}".format(num))
    print("Cracking: Calculating...")

    tnow = time_now
    # How far do we go into the past in seconds.
    twnd = 5000

    # Start searching for the timestamp in the past that will match the seed.
    found = False
    seed = 0
    for toffs in range(twnd):
        tpast = tnow - toffs
        rng = utils.MT19937(tpast)
        n = rng.uint32()
        if n == num:
            # The RNG gives 'n' equal to 'num', so the seed must have been 'tpast'.
            seed = tpast
            found = True
            break

    print("Cracking: Calculating...done")
    if found:
        print("Cracking: Found seed {0} at toffs {1}".format(seed, toffs))
    else:
        print("Cracking: Seed NOT FOUND in twnd {0}".format(twnd))
    print("-" * 60)

    return seed

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        (seed_ok, num) = mt19937_timestamp_seed()
        seed = execute_break_mt19937_seed(num)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: num      = [{1}]".format(me, num))
        print("{0}: seed_ok  = [{1}]".format(me, seed_ok))
        print("{0}: seed     = [{1}]".format(me, seed))
        if seed != seed_ok:
            err_str = "\n{0}: ".format(me) + "-" * 60
            err_str += "\n{0}: TEST     = [FAILED] Result doesn't match expected.".format(me)
            err_str += "\n{0}: ".format(me) + "-" * 60
            raise Exception(err_str)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: TEST     = [OK]".format(me))
        print("{0}: ".format(me) + "-" * 60)
    except Exception:
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Caught ERROR EXCEPTION:".format(me))
        raise
    except:
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Caught UNEXPECTED EXCEPTION:".format(me))
        raise

    sys.exit(0)


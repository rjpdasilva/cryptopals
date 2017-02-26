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

"""Cryptopals Challenges: Test Challenge 23: Clone an MT19937 RNG from its output."""

import sys
import utils.cp_aux_utils as utils

title = "Challenge 23: Clone an MT19937 RNG from its output"

def undo_rs_xor(value, shift):
    """Reverses MT19937 Right Shift + XOR operations."""

    # Each result bit is the XOR between the same bit in 'val'
    # with the same bit of the right shifted result so far.
    result = 0
    for bit_n in reversed(range(32)):
        bit_mask = 0x1 << bit_n
        bit_r = (value ^ (result >> shift)) & bit_mask
        result |= bit_r

    return result

def undo_ls_and_xor(value, shift, mask):
    """Reverses MT19937 Left Shift + AND + XOR operations."""

    # Each result bit is the XOR between the same bit in 'val'
    # with the same bit of the logical and between the left
    # shifted result so far and the mask.
    result = 0
    for bit_n in range(32):
        bit_mask = 0x1 << bit_n
        bit_r = (value ^ ((result << shift) & mask)) & bit_mask
        result |= bit_r

    return result

def mt19937_untemper(num):
    """Reverses a MT19937 output back into its corresponding element in the state array."""

    # Apply the inverse of the tempering operations in inverse order.
    num = undo_rs_xor(num, 18)
    num = undo_ls_and_xor(num, 15, 4022730752)
    num = undo_ls_and_xor(num, 7, 2636928640)
    num = undo_rs_xor(num, 11)

    return num

def mt19937_create():
    """Creates the MT19937 RNG to be cloned."""

    # Create a new RNG with a random seed.
    seed = utils.rand_int(0, 0xffffffff)
    rng = utils.MT19937(seed)

    # Pop a random amount of numbers out if it, to prove that it can be
    # clone in whatever state it is when caught by the cloning function.
    num_to_pop = utils.rand_int(10, 10000)
    for i in range(num_to_pop):
        rng.uint32()

    print("-" * 60)
    print("Create RNG: Seed is {0}, got {1} numbers out".format(seed, num_to_pop))

    return rng

def execute_mt19937_clone(rng_real, count):
    """Clones the given MT19937 RNG."""

    print("-" * 60)

    # Create the clone RNG.
    # The seed is not important, because we will later overwrite all its
    # internal state with that reversed from the real RNG.
    rng_clone = utils.MT19937(0)

    # Extract 624 numbers from the real RNG. Untemper (reverse) each
    # extracted value and place it on the cloned state array, in the
    # associated position, thus cloning the internal state of the real
    # RNG. Once done for all 624 positions, we have completed cloning
    # the real RNG internal state, so we can force the cloned state back
    # into the clone RNG created. We need to tap 624 numbers from the
    # real RNG because that's the period used by the RNG to permute its
    # internal state.
    #
    # We don't know the current state index in the real RNG, but it
    # doesn't matter anyway, because the states are periodic and circular,
    # so what matters is that the cloned RNG is "in phase" with the real
    # one, meaning the next state and output will be the same on both,
    # even if # their internal state indexes are not the same.

    # The RNG internal state array that will be cloned from the real RNG.
    mt_clone = [0] * 624

    # Extract all untempered numbers.
    print("Clone RNG: Cloning internal state...")
    for i in range(624):
        num = rng_real.uint32()
        num_untempered = mt19937_untemper(num)
        mt_clone[i] = num_untempered
    print("Clone RNG: Cloning internal state...done")

    # Force the cloned state into the clone RNG.
    rng_clone.set_state(mt_clone)

    # Get a number list for each.
    print("Clone RNG: Generating number lists...")
    num_list_real = [rng_real.uint32() for i in range(count)]
    num_list_clone = [rng_clone.uint32() for i in range(count)]
    print("Clone RNG: Generating number lists...done")
    print("-" * 60)

    return (num_list_real, num_list_clone)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_count = 5000
        in_rng_real = mt19937_create()
        (out_real, out_clone) = execute_mt19937_clone(in_rng_real, in_count)
        ok = True
        # Confirm generated numbers by real RNG and clone RNG are the same.
        # If not, identify the 1st number where they're different.
        for i in range(in_count):
            num_real = out_real[i]
            num_clone = out_clone[i]
            if num_clone != num_real:
                ok = False
                break
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: in_count = [{1}]".format(me, in_count))
        if ok:
            print("{0}: equal    = [True]".format(me))
        else:
            print("{0}: equal    = [False], Real={1} != Clone={2} at Num={3}"
                    .format(me, num_real, num_clone, i + 1))
        if not ok:
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


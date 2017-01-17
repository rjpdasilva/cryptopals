"""Cryptopals Challenges: Auxiliary/utility functions."""

import base64
from Crypto.Util.strxor import strxor
import string

def hexstr2bytes(s):
    """Convert an hex string to a byte array."""

    b = b''

    try:
        if not len(s):
            raise Exception("Invalid hex string: Empty")
        b = bytes.fromhex(s)
    except TypeError:
        raise Exception("Invalid hex string: Not a string")
    except ValueError:
        raise Exception("Invalid hex string: Not hex encoded")
    except Exception:
        raise
    except:
        raise

    return b

def rawstr2bytes(s):
    """Convert a raw string to a byte array."""

    b = b''

    try:
        if not len(s):
            raise Exception("Invalid raw string: Empty")
        b = s.encode("utf-8")
    except TypeError:
        raise Exception("Invalid raw string: Not a string")
    except ValueError:
        raise Exception("Invalid raw string: Not 'utf=8' encodable")
    except Exception:
        raise
    except:
        raise

    return b

def bytes2hexstr(b):
    """Convert a byte array to an hex encoded string."""

    s = ''

    try:
        if not len(b):
            raise Exception("Invalid byte array: Empty")
        s = b.hex()
    except TypeError:
        raise Exception("Invalid byte array: Not a byte array")
    except ValueError:
        raise Exception("Invalid byte array: Not a valid byte array")
    except Exception:
        raise
    except:
        raise

    return s

def bytes2rawstr(b):
    """Convert a byte array to a raw string."""

    s = ''

    try:
        if not len(b):
            raise Exception("Invalid byte array: Empty")
        s = b.decode("utf-8")
    except TypeError:
        raise Exception("Invalid byte array: Not a byte array")
    except ValueError:
        raise Exception("Invalid byte array: Not a valid byte array")
    except UnicodeDecodeError:
        raise Exception("Invalid byte array: Not 'utf-8' decodable")
    except Exception:
        raise
    except:
        raise

    return s

def bytes2base64bytes(b):
    """Convert a byte array to a base64 encoded byte array."""

    b64 = b''

    try:
        if not len(b):
            raise Exception("Invalid byte array: Empty")
        b64 = base64.b64encode(b)
    except TypeError:
        raise Exception("Invalid byte array: Not a byte array")
    except ValueError:
        raise Exception("Invalid byte array: Not a valid byte array")
    except Exception:
        raise
    except:
        raise

    return b64

def xor(src, key):
    """Create a byte array resulting from b XOR k."""

    len_src = len(src)
    len_key = len(key)

    try:
        if not len_src:
            raise Exception("Invalid src for xor: Empty")
        if not len_key:
            raise Exception("Invalid key for xor: Empty")

        # Make key size equal the src size:
        #  + Truncate key if larger than src.
        #  + Extend key, repeating its pattern till it reaches src size.
        if len_key >= len_src:
            new_key = key[:len_src]
        else:
            new_key = key * (len_src // len_key) + key[:((len_src % len_key))]

        xor_b = strxor(src, new_key)
    except TypeError:
        raise Exception("Invalid types for xor")
    except ValueError:
        raise Exception("Invalid values for xor")
    except Exception:
        raise
    except:
        raise

    return xor_b

# Python dictionary with an English letters statistical frequency.
# Data from: https://en.wikipedia.org/wiki/Letter_frequency.
# Space frequency added.
en_letter_freq = {
    'a':  8.167,
    'b':  1.492,
    'c':  2.782,
    'd':  4.253,
    'e': 12.702,
    'f':  2.228,
    'g':  2.015,
    'h':  6.094,
    'i':  6.966,
    'j':  0.153,
    'k':  0.772,
    'l':  4.025,
    'm':  2.406,
    'n':  6.749,
    'o':  7.507,
    'p':  1.929,
    'q':  0.095,
    'r':  5.987,
    's':  6.327,
    't':  9.056,
    'u':  2.758,
    'v':  0.978,
    'w':  2.360,
    'x':  0.150,
    'y':  1.974,
    'z':  0.074,
    ' ': 13.000
}

# Read in a file with a list of english words.
# Use a 'set' for improved lookup performance.
with open("english_words.txt") as word_file:
    english_words = set(word.strip().lower() for word in word_file)

def score_english_string_freq(s):
    """Score an English string using character frequency."""
    # Make verything lowercase.
    s_low_chars = [chr(c).lower() for c in s]
    # Score is the sum of the each letter score (frequency).
    # Chars not in the table are not accounted for in the score.
    score = sum([en_letter_freq[c] for c in s_low_chars if c in en_letter_freq])
    return score

def score_english_string_words(s):
    """Score an English string using correct words presence."""
    score = 0

    # Must have something in it.
    if not len(s):
        return 0

    # Must contain only printable chars.
    printable = set(string.printable)
    if len([chr(c) for c in s if chr(c) not in printable]):
        return 0

    # Check for english words against dictionary.
    words = bytes2rawstr(s).split()
    for w in words:
        if w.lower() in english_words:
            score += 15

    return score

def score_english_string(s):
    """Score an English string."""
    score = 0

    # Valid words component.
    score += score_english_string_words(s)
    # Character frequency component.
    score += score_english_string_freq(s)

    return score

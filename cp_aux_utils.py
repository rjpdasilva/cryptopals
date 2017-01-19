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
        s = b.decode("utf-8", "backslashreplace")
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

def base64bytes2bytes(b64):
    """Convert a base64 encoded byte array to a decoded byte array."""

    b = b''

    try:
        if not len(b64):
            raise Exception("Invalid base64 byte array: Empty")
        b = base64.b64decode(b64)
    except TypeError:
        raise Exception("Invalid base64 byte array: Not a byte array")
    except ValueError:
        raise Exception("Invalid base64 byte array: Not a valid byte array")
    except Exception:
        raise
    except:
        raise

    return b

def xor(src_str, key_str, in_fmt = "bytes", out_fmt = "bytes"):
    """Perform <src> XOR <key>. The <key> is processed to match <src> size"""

    # Convert to byte array.
    if in_fmt == "hex":
        src = hexstr2bytes(src_str)
        key = hexstr2bytes(key_str)
    elif in_fmt == "raw":
        src = rawstr2bytes(src_str)
        key = rawstr2bytes(key_str)
    else: # in_fmt == "bytes"
        src = src_str
        key = key_str

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

    # Convert to required format.
    if out_fmt == "hex":
        xor_r = bytes2hexstr(xor_b)
    elif out_fmt == "raw":
        xor_r = bytes2rawstr(xor_b)
    else: # out_fmt == "bytes"
        xor_r = xor_b

    return xor_r

def break_single_byte_xor(str, in_hex = True, out_raw = True):
    """Decrypt an hex encoded string ciphered with single-byte xor."""

    def score_decr(decr):
        """Score an English string provided as a byte array."""
        # 'decr' is a decrypted byte array to score.
        return score_english_string(decr)

    # Convert to byte array.
    if in_hex:
        src_b = hexstr2bytes(str)
    else:
        src_b = str

    # List all the keys and respective xor decrypted byte array.
    list_decr = [(k, xor(src_b, bytes([k]))) for k in range(256)]

    # Add the score to each decrypted byte array.
    list_decr_scored = [(i[0], i[1], score_decr(i[1])) for i in list_decr]

    # Get the high scoring decrypted byte array.
    sort_key = (lambda decr_scored: decr_scored[2])
    res = max(list_decr_scored, key = sort_key)

    # Convert decrypted message to required format.
    if out_raw:
        res = (res[0], bytes2rawstr(res[1]), res[2])

    return res

def count_bits_1_bin(val):
    """Count the number of bits present in one integer."""

    nbits = bin(val).count('1')

    return nbits

def count_bits_1(src):
    """Count the number of bits present in a byte array."""

    nbits = sum([count_bits_1_bin(byte) for byte in src])

    return nbits

def hamming_dist(src, key):
    """Calculate hamming distance between 2 byte arrays."""

    # It's the number of '1' bits after xor'ing both operands.
    xor_b = xor(src, key)
    dist = count_bits_1(xor_b)

    return dist

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
    # Make everything lowercase.
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

def file_get_lines(fn):
    """Generate normalized lines read from a file."""
    with open(fn) as f:
        # Remove one trailing '\n' from the line, if it's there.
        for line in f:
            if line[-1] == '\n':
                line = line[:-1]
            yield line

def file_get(fn):
    """Read a whole file in."""
    with open(fn) as f:
        return f.read()

def file_get_ciphertext_base64(file_name):
    """Get the ciphertext from a base64 encoded file."""

    # Get the file data.
    text = file_get(file_name)

    # Convert to byte array.
    text_b = rawstr2bytes(text)

    # Base64 decode it.
    ct_b = base64bytes2bytes(text_b)

    return ct_b


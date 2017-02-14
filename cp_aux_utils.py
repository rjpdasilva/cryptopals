"""Cryptopals Challenges: Auxiliary/utility functions."""

import base64
import string
from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES
from Crypto.Random import random

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

def find_repetitions(s, sz):
    """Find repetitions of 'sz'-sized blocks of 's' within 's' itself."""

    # Check how many full blocks of 'sz' fit in 's' and split 's'
    # into those blocks.
    len_s = len(s)
    nblks = len_s // sz
    len_s_align = nblks * sz
    s_align = s[:len_s_align]
    s_blks = [s_align[n:n + sz] for n in range(0, len_s_align, sz)]

    # Count how many times each block is repeated in the string.
    # Do this by comparing all non-repeating combinations of 2
    # blocks.
    score = len([1 for i in range(0, nblks - 1) for j in range(i + 1, nblks)
                    if s_blks[i] == s_blks[j]])

    return score

def aes_decrypt(cipher, key, mode = "ECB", iv = b''):
    """Decrypt cipher with key, using AES in specified mode."""
    if mode == "ECB":
        aes_mode = AES.MODE_ECB
    elif mode == "CBC":
        aes_mode = AES.MODE_CBC
    else:
        raise Exception("Invalid AES mode for decryption.")

    crypto = AES.new(key, aes_mode, iv)
    plain = crypto.decrypt(cipher)

    return plain

def aes_encrypt(plain, key, mode = "ECB", iv = b''):
    """Encrypt plain with key, using AES in specified mode."""
    if mode == "ECB":
        aes_mode = AES.MODE_ECB
    elif mode == "CBC":
        aes_mode = AES.MODE_CBC
    else:
        raise Exception("Invalid AES mode for decryption.")

    crypto = AES.new(key, aes_mode, iv)
    cipher = crypto.encrypt(plain)

    return cipher

def aes_decrypt_cbc_using_ecb(cipher, key, iv):
    """Decrypt AES-CBC cipher with key, using AES-ECB and XOR."""

    try:
        crypto = AES.new(key, AES.MODE_ECB)
        sz = len(key)
        if sz != len(iv):
            raise Exception("Invalid IV: Size not matching key size")
        # Split ciphertext in blocks.
        blks = [cipher[n:n + sz] for n in range(0, len(cipher), sz)]
        # For each cipher block, decrypt it with ECB and then XOR
        # it with the previous cipher block (or the IV in the for
        # the 1st cipher block). Put all decrypted blocks together
        # to have the plaintext.
        plain = b''
        cipher_last = iv
        for i in range(len(blks)):
            blk_plain = crypto.decrypt(blks[i])
            plain += xor(blk_plain, cipher_last)
            cipher_last = blks[i]
    except TypeError:
        raise Exception("Invalid types for AES decrypt")
    except ValueError:
        raise Exception("Invalid values for AES decrypt")
    except Exception:
        raise
    except:
        raise

    return plain

def aes_encrypt_cbc_using_ecb(plain, key, iv):
    """Encrypt AES-CBC plaintext with key, using AES-ECB and XOR."""

    try:
        crypto = AES.new(key, AES.MODE_ECB)
        sz = len(key)
        if sz != len(iv):
            raise Exception("Invalid IV: Size not matching key size")
        # Split plaintext in blocks.
        blks = [plain[n:n + sz] for n in range(0, len(plain), sz)]
        # For each plain block, XOR it with the previous cipher
        # block (or the IV in the for the 1st plain block) and
        # then encrypt it with ECB. Put all encrypted blocks
        # together to have the ciphertext.
        cipher = b''
        cipher_last = iv
        for i in range(len(blks)):
            blk_plain = xor(blks[i], cipher_last)
            cipher_last = crypto.encrypt(blk_plain)
            cipher += cipher_last
    except TypeError:
        raise Exception("Invalid types for AES decrypt")
    except ValueError:
        raise Exception("Invalid values for AES decrypt")
    except Exception:
        raise
    except:
        raise

    return cipher

# AES-CTR crypto requires maintaining state, so use a class for it.
class AesCtr:
    """AES-CTR crypto functionality."""

    def __init__(self, key, nonce, nonce_size = 8, ctr_size = 8, big_endian = False):
        self._key = key
        self._nonce = nonce
        self._nonce_size = nonce_size
        self._ctr_size = ctr_size
        self._endian = 'big' if big_endian else 'little'
        self._ks_bytes = b''
        self._ctr = 0
        self._block_size = self._nonce_size + self._ctr_size
        if self._block_size % 16:
            raise Exception("AesCtr: nonce + ctr size must be multiple of 16")
        self._crypto = AES.new(self._key, AES.MODE_ECB)

    def encrypt(self, plaintext):
        """AES-CTR encrypt function (decrypt is the same)."""
        pt = plaintext
        if len(pt) == 0:
            return b''

        # For the keystream 'ks', start with any remaining unused bytes
        # from last encrypt/decrypt operation.
        ks = self._ks_bytes
        # Generate new keystream blocks for covering the required
        # plaintext.
        while len(ks) < len(pt):
            # Prepare a new key block and append it to keystream.
            kb_pt = self._nonce.to_bytes(self._nonce_size, self._endian)
            kb_pt += self._ctr.to_bytes(self._ctr_size, self._endian)
            kb_ct = self._crypto.encrypt(kb_pt)
            ks += kb_ct
            self._ctr += 1

        # Adjust keystream to match plaintext size, while keeping any
        # exceeding bytes for next encrypt/decrypt operation.
        if len(ks) > len(pt):
            self._ks_bytes = ks[len(pt):]
            ks = ks[:len(pt)]

        # Finally, do the XOR between the plaintext and keystream.
        ct = strxor(pt, ks)

        return ct

    def decrypt(self, ciphertext):
        """AES-CTR decrypt function."""
        # Encrypt/Decrypt is the same process!
        return self.encrypt(ciphertext)

def pkcs7_pad(b, sz):
    """PKCS#7 pad a byte array to 'sz' bytes."""
    try:
        if sz < 2 or sz > 256:
            raise Exception("Invalid sz for pkcs7_pad")
        # Determine how many bytes required for padding.
        # In the case 'len_b' is a multiple of 'sz', PKCS#7 still
        # required padding of 'sz' bytes.
        len_b = len(b)
        if not len_b:
            raise Exception("Invalid byte array: Empty")
        pad_len = sz - (len_b % sz)
        # The byte value used for padding is the pad length.
        pad_byte = bytes([pad_len])
        padded_b = b + pad_byte * pad_len
    except TypeError:
        raise Exception("Invalid types for pkcs7_pad")
    except ValueError:
        raise Exception("Invalid values for pkcs7_pad")
    except Exception:
        raise
    except:
        raise

    return padded_b

def pkcs7_unpad(b, sz):
    """Unpad a PKCS#7 byte array padded to 'sz' bytes."""
    try:
        if sz < 2 or sz > 256:
            raise Exception("Invalid sz for pkcs7_unpad")
        len_b = len(b)
        if not len_b:
            raise Exception("Invalid byte array: Empty")
        if (len_b) % sz != 0:
            raise Exception("Invalid byte array: Not padded")
        num_pad = b[-1]
        if num_pad > sz or num_pad == 0:
            raise Exception("Invalid byte array: Incorrect number of pad bytes")
        pad_bytes = b[-num_pad:]
        if pad_bytes != bytes([num_pad] * num_pad):
            raise Exception("Invalid byte array: Incorrect pad bytes content")
        unpadded_b = b[0:-num_pad]
    except TypeError:
        raise Exception("Invalid types for pkcs7_pad")
    except ValueError:
        raise Exception("Invalid values for pkcs7_pad")
    except Exception:
        raise
    except:
        raise

    return unpadded_b

def rand_int(low, high):
    """Generate random integer 'rnd' where 'low' <= 'rnd' <= 'high'."""
    return random.randint(low, high)

def rand_bytes(nbytes):
    """Generate random byte array with maximum of 'nbytes'."""
    rnd = random.getrandbits(nbytes * 8)
    rnd_b = rnd.to_bytes(nbytes, byteorder = 'big')
    return rnd_b



def _uint32(x):
    # Get the 32 least significant bits.
    return int(0xFFFFFFFF & x)

# MT19937: Mersenne Twister Random Number Generator (RNG).
# https://en.wikipedia.org/wiki/Mersenne_Twister
class MT19937:
    """Wikipedia implementation of MT19937 RNG."""

    def __init__(self, seed):
        # Initialize the index to 0.
        self._index = 624
        self._mt = [0] * 624
        # Initialize the initial state to the seed.
        self._mt[0] = _uint32(seed)
        for i in range(1, 624):
            self._mt[i] = _uint32(1812433253 * (self._mt[i - 1] ^ self._mt[i - 1] >> 30) + i)

    def _twist(self):
        for i in range(624):
            # Get the most significant bit and add it to the less significant
            # bits of the next number.
            y = _uint32((self._mt[i] & 0x80000000) + (self._mt[(i + 1) % 624] & 0x7fffffff))
            self._mt[i] = self._mt[(i + 397) % 624] ^ y >> 1

            if y % 2 != 0:
                self._mt[i] = self._mt[i] ^ 0x9908b0df

        self._index = 0

    def uint32(self):
        if self._index >= 624:
            self._twist()

        y = self._mt[self._index]

        # Right shift by 11 bits
        y = y ^ y >> 11
        # Shift y left by 7 and take the bitwise and of 2636928640
        y = y ^ y << 7 & 2636928640
        # Shift y left by 15 and take the bitwise and of y and 4022730752
        y = y ^ y << 15 & 4022730752
        # Right shift by 18 bits
        y = y ^ y >> 18

        self._index = self._index + 1

        return _uint32(y)

    def set_state(self, mt):
        """Forces a new internal state."""
        self._mt = mt[:]

# Stream Cipher using MT19937 RNG.
class MT19937StreamCipher:
    """Stream Cipher using MT19937 RNG."""

    def __init__(self, key):
        self._key = key
        self._rng = MT19937(self._key)
        self._ks_bytes = b''

    def encrypt(self, plaintext):
        """Encrypt function (decrypt is the same)."""
        pt = plaintext
        if len(pt) == 0:
            return b''

        # For the keystream 'ks', start with any remaining unused bytes
        # from last encrypt/decrypt operation.
        ks = self._ks_bytes
        # Generate new keystream blocks for covering the required
        # plaintext.
        while len(ks) < len(pt):
            # Prepare a new key block and append it to keystream.
            kb = self._rng.uint32().to_bytes(4, 'little')
            ks += kb

        # Adjust keystream to match plaintext size, while keeping any
        # exceeding bytes for next encrypt/decrypt operation.
        if len(ks) > len(pt):
            self._ks_bytes = ks[len(pt):]
            ks = ks[:len(pt)]

        # Finally, do the XOR between the plaintext and keystream.
        ct = strxor(pt, ks)

        return ct

    def decrypt(self, ciphertext):
        """Decrypt function."""
        # Encrypt and Decrypt use the same process!
        return self.encrypt(ciphertext)


# https://github.com/sfstpala/SlowSHA

# Copyright (C) 2011 by Stefano Palazzo
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# A SHA-1 pure python implementation.
# Some modifications were made to fit the challenges' purposes.
class SHA1:
    _h0 = 0x67452301
    _h1 = 0xefcdab89
    _h2 = 0x98badcfe
    _h3 = 0x10325476
    _h4 = 0xc3d2e1f0

    def __init__(self, message, h = [_h0, _h1, _h2, _h3, _h4], length = None):
        # Check if an initial state was given (h and length)
        self._h0 = h[0]
        self._h1 = h[1]
        self._h2 = h[2]
        self._h3 = h[3]
        self._h4 = h[4]
        if length is None:
            length = len(message)

        # Get the bit length.
        length = bin(length * 8)[2:].rjust(64, "0")

        # Update the SHA.
        while len(message) > 64:
            self._handle(''.join(bin(i)[2:].rjust(8, "0") for i in message[:64]))
            message = message[64:]

        # Deal with padding.
        message = ''.join(bin(i)[2:].rjust(8, "0") for i in message) + "1"
        message += "0" * ((448 - len(message) % 512) % 512) + length

        # Update the SHA (final).
        for i in range(len(message) // 512):
            self._handle(message[i * 512:i * 512 + 512])

    def _handle(self, chunk):
        lrot = lambda x, n: (x << n) | (x >> (32 - n))
        w = []

        for j in range(len(chunk) // 32):
            w.append(int(chunk[j * 32:j * 32 + 32], 2))

        for i in range(16, 80):
            w.append(lrot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1) & 0xffffffff)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4

        for i in range(80):
            if i <= i <= 19:
                f, k = d ^ (b & (c ^ d)), 0x5a827999
            elif 20 <= i <= 39:
                f, k = b ^ c ^ d, 0x6ed9eba1
            elif 40 <= i <= 59:
                f, k = (b & c) | (d & (b | c)), 0x8f1bbcdc
            elif 60 <= i <= 79:
                f, k = b ^ c ^ d, 0xca62c1d6
            temp = lrot(a, 5) + f + e + k + w[i] & 0xffffffff
            a, b, c, d, e = temp, a, lrot(b, 30), c, d

        self._h0 = (self._h0 + a) & 0xffffffff
        self._h1 = (self._h1 + b) & 0xffffffff
        self._h2 = (self._h2 + c) & 0xffffffff
        self._h3 = (self._h3 + d) & 0xffffffff
        self._h4 = (self._h4 + e) & 0xffffffff

    def _digest(self):
        return (self._h0, self._h1, self._h2, self._h3, self._h4)

    def hexdigest(self):
        return ''.join(hex(i)[2:].rjust(8, "0")
                for i in self._digest())

    def digest(self):
        hexdigest = self.hexdigest()
        return bytes(int(hexdigest[i * 2:i * 2 + 2], 16) for i in range(len(hexdigest) // 2))

# Do a MAC using SHA-1 with the given key and message.
def sha1_mac(key, msg):
    """Provide an MAC of 'msg' using the given 'key'."""

    message = key + msg
    sha1 = SHA1(message)

    return sha1.digest()

# Perform SHA-1 message padding.
def sha1_pad(msg):
    l = len(msg) * 8
    msg += b'\x80'
    msg += b'\x00' * ((56 - (len(msg) % 64)) % 64)
    msg += l.to_bytes(8, 'big')
    return msg


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


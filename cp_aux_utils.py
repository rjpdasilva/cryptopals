"""Cryptopals Challenges: Auxiliary/utility functions."""

import base64

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


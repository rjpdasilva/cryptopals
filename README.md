# cryptopals

Implementation of the [Cryptopals Matasano Crypto Challenges](http://cryptopals.com/).

Coded in Python 3.

## Installation

Get the implementation's git repo from `git@github.com:rjpdasilva/cryptopals.git`.

A Python 3 installation is required for running the samples.

The following core modules are used by the implementation:
* `base64`
* `http.server`
* `string`
* `struct`
* `sys`
* `time`
* `urllib.parse`
* `urllib.request`

Besides the core modules that are part of the Python installation, the following
additional modules (and respective package install command) are required:
* `Crypto` (`pip install pycrypto`)

## Usage

Each challenge has a python script for running it, named `cp_test_c<nn>.py`,
where `<nn>` is the challenge number.

For example:
* `cp_test_c06.py` is for Challenge 6.
* `cp_test_c21.py` is for Challenge 21.

For running a challenge:
* Use a shell placed on the challenge scripts folder.
* Call python with the challenge script:<br>
`python cp_test_c<nn>.py`
* Example:<br>
`python cp_test_c12.py`

Notes:
* In general, the challenges' scripts require no arguments, but, in some cases, arguments may be
required (e.g. `cp_test_c31.py`), in which case the required arguments will be described when
running it without any arguments.
* Some scripts require user input and/or interaction. This will be noticeable when running these
scripts.
* Some challenges require a server to be run before executing the actual test script. This is the
case of `cp_test_c31.py`, where the server script is `cp_test_c31_server.py`. This naming scheme is
used for all challenges with a client and server.
* Challenge specific data is presented to the user.
* The final challenge test result is presented in the end.

## Examples

Below are some examples of running the challenges.

### No arguments required, no user interaction required

```
$ python cp_test_c03.py
cp_test_c03.py: ------------------------------------------------------------
cp_test_c03.py: Challenge 03: Single-byte XOR cipher
cp_test_c03.py: ------------------------------------------------------------
cp_test_c03.py: in_str   = [1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736]
cp_test_c03.py: result   = [(key=88/0x58, msg="Cooking MC's like a pound of bacon")], score = [306.073]
cp_test_c03.py: expected = [(key=88/0x58, msg="Cooking MC's like a pound of bacon")]
cp_test_c03.py: ------------------------------------------------------------
cp_test_c03.py: TEST     = [OK]
cp_test_c03.py: ------------------------------------------------------------
```

### No arguments required, user interaction required (entering number of loops)

```
$ python cp_test_c11.py
cp_test_c11.py: ------------------------------------------------------------
cp_test_c11.py: Challenge 11: An ECB/CBC detection oracle
cp_test_c11.py: ------------------------------------------------------------
Enter number of loops to execute (1 ~ 10000):
2000
cp_test_c11.py: in_file  = [data_c06_out.txt]
cp_test_c11.py: loops    = [ 2000]
cp_test_c11.py:   ECB    = [  982] ( 49.10%)
cp_test_c11.py:   CBC    = [ 1018] ( 50.90%)
cp_test_c11.py:   ok     = [ 2000] (100.00%)
cp_test_c11.py:   ko     = [    0] (  0.00%)
cp_test_c11.py: ------------------------------------------------------------
cp_test_c11.py: TEST     = [OK]
cp_test_c11.py: ------------------------------------------------------------
```

### With server and client scripts, argument required for client

This is required, e.g., for Challenge 31.

Starting the server:
```
$ python cp_test_c31_server.py
cp_test_c31_server.py: ------------------------------------------------------------
cp_test_c31_server.py: Challenge 31: Implement and break HMAC-SHA1 with an artificial timing leak: Server
cp_test_c31_server.py: ------------------------------------------------------------
cp_test_c31_server.py: server_addr   = [localhost]
cp_test_c31_server.py: server_port   = [9000]
cp_test_c31_server.py: server_delay  = [50 ms]
cp_test_c31_server.py: ------------------------------------------------------------
cp_test_c31_server.py: Running server...
cp_test_c31_server.py: (Ctrl+C to abort)
cp_test_c31_server.py: ------------------------------------------------------------
```

Running the client, which needs one argument specifying the file name:
```
$ python cp_test_c31.py
cp_test_c31.py: Error: Missing <file_name> arg
cp_test_c31.py: usage: cp_test_c31.py <file_name>

$ python cp_test_c31.py somefile.txt
cp_test_c31.py: ------------------------------------------------------------
cp_test_c31.py: Challenge 31: Implement and break HMAC-SHA1 with an artificial timing leak
cp_test_c31.py: ------------------------------------------------------------
cp_test_c31.py: file_name     = [somefile.txt]
cp_test_c31.py: server_addr   = [localhost]
cp_test_c31.py: server_port   = [9000]
cp_test_c31.py: server_delay  = [50 ms]
cp_test_c31.py: ------------------------------------------------------------
cp_test_c31.py: Breaking...
cp_test_c31.py: ------------------------------------------------------------
Guessing byte 00 (dmin=  50.0)...done: v=d7, d=  52.3
(sig-KO) d7
Guessing byte 01 (dmin= 100.0)...done: v=1c, d= 103.0
(sig-KO) d71c
Guessing byte 02 (dmin= 150.0)...
```


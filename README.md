# cryptopals

Implementation of the [Cryptopals Matasano Crypto Challenges](http://cryptopals.com/).

Coded in Python 3.

## Installation

Get the implementation's git repo from `git@github.com:rjpdasilva/cryptopals.git`.

A Python 3 installation is required for running the samples.

The following core modules are used by the implementation:
* `base64`
* `string`
* `sys`
* `time`

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
* Call python with the challenge script:
```
python cp_test_c<nn>.py
```
* Example: `python cp_test_c12.py`

Notes:
* The challenge scripts require no parameters.
* Challenge specific data is presented to the user.
* The final challenge test result is presented in the end.
* Some scripts require user input and/or interaction.

Below are some examples of running the challenges.

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


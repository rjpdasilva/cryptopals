# **cryptopals**

Implementation of the [Cryptopals Matasano Crypto Challenges](http://cryptopals.com/).<br>
Coded in Python 3.


## Table of Contents

* [Installation](#installation)
* [Usage](#usage)
* [Examples](#examples)
  * [No arguments required, no user interaction required](#examples1)
  * [No arguments required, user interaction required](#examples2)
  * [With server and client scripts, argument required for client](#examples3)
  * [With server, client and MITM scripts, arguments required for all](#examples4)


<a name="installation"></a>
## Installation

Get the implementation's git repo from `git@github.com:rjpdasilva/cryptopals.git`.<br>
The repo's directory structure is:
```
.               # Repo's root ('README.md').
└─ src          # Challenge scripts.
   ├─ data      # Data files (input data, expected results, etc.).
   └─ utils     # Utility modules.
```

A Python 3 installation is required for running the samples.

The following core modules are used by the implementation:
* `base64`
* `hashlib`
* `hmac`
* `http.server`
* `socket`
* `socketserver`
* `string`
* `struct`
* `sys`
* `time`
* `urllib.parse`
* `urllib.request`

Besides the core modules that are part of the Python installation, the following
additional modules (and respective package install command) are required:
* `Crypto` (`pip install pycrypto`)


<a name="usage"></a>
## Usage

Each challenge has a python script for running it, named `cp_test_c<nn>.py`,
where `<nn>` is the challenge number. All the challenges' scripts are inside the `src/` folder.

For example:
* `cp_test_c06.py` is for Challenge 6.
* `cp_test_c21.py` is for Challenge 21.

For running a challenge:
* Use a shell placed on the challenge scripts folder (`src/`).
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
* Some challenges (e.g. MITM - Man in The Middle attacks) require a real server and a MITM server to
be started before running the challenge's test script. For example, Challenge 34, tested by running
the `cp_test_c34.py` script, needs a real server `cp_test_c34_server.py` and the MITM server
`cp_test_c34_mitm.py` scripts to be started before testing. This naming scheme is kept the same in
all client/server with MITM attack challenges.
* Challenge specific data is presented to the user.
* The final challenge test result is presented in the end.


<a name="examples"></a>
## Examples

Below are some examples of running the challenges.


<a name="examples1"></a>
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


<a name="examples2"></a>
### No arguments required, user interaction required (entering number of loops)

```
$ python cp_test_c11.py
cp_test_c11.py: ------------------------------------------------------------
cp_test_c11.py: Challenge 11: An ECB/CBC detection oracle
cp_test_c11.py: ------------------------------------------------------------
Enter number of loops to execute (1 ~ 10000):
2000
cp_test_c11.py: in_file  = [data/data_c06_out.txt]
cp_test_c11.py: loops    = [ 2000]
cp_test_c11.py:   ECB    = [  982] ( 49.10%)
cp_test_c11.py:   CBC    = [ 1018] ( 50.90%)
cp_test_c11.py:   ok     = [ 2000] (100.00%)
cp_test_c11.py:   ko     = [    0] (  0.00%)
cp_test_c11.py: ------------------------------------------------------------
cp_test_c11.py: TEST     = [OK]
cp_test_c11.py: ------------------------------------------------------------
```


<a name="examples3"></a>
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


<a name="examples4"></a>
### With server, client and MITM scripts, arguments required for all

This is used, e.g., in Challenge 34.

Starting the server (1st incorrectly without arguments, then correctly):
```
$ python cp_test_c34_server.py
cp_test_c34_server.py: Error: Missing arguments
cp_test_c34_server.py: usage: cp_test_c34_server.py <server_addr> <server_port>


$ python cp_test_c34_server.py localhost 9001
cp_test_c34_server.py: ------------------------------------------------------------
cp_test_c34_server.py: Challenge 34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection: Server
cp_test_c34_server.py: ------------------------------------------------------------
cp_test_c34_server.py: server_addr = [localhost]
cp_test_c34_server.py: server_port = [9001]
cp_test_c34_server.py: ------------------------------------------------------------
cp_test_c34_server.py: Running server...
cp_test_c34_server.py: (Ctrl+C to abort)
cp_test_c34_server.py: ------------------------------------------------------------
```

Starting the MITM attacker (1st incorrectly without arguments, then correctly):
```
$ python cp_test_c34_mitm.py
cp_test_c34_mitm.py: Error: Missing arguments
cp_test_c34_mitm.py: usage: cp_test_c34_mitm.py <mitm_addr> <mitm_port> <server_addr> <server_port>

$ python cp_test_c34_mitm.py localhost 9000 localhost 9001
cp_test_c34_mitm.py: ------------------------------------------------------------
cp_test_c34_mitm.py: Challenge 34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection: MITM
cp_test_c34_mitm.py: ------------------------------------------------------------
cp_test_c34_mitm.py: mitm_addr   = [localhost]
cp_test_c34_mitm.py: mitm_port   = [9000]
cp_test_c34_mitm.py: server_addr = [localhost]
cp_test_c34_mitm.py: server_port = [9001]
cp_test_c34_mitm.py: ------------------------------------------------------------
cp_test_c34_mitm.py: Running MITM server...
cp_test_c34_mitm.py: (Ctrl+C to abort)
cp_test_c34_mitm.py: ------------------------------------------------------------
```

Starting the client to connect with real server on port 9001 (1st incorrectly without arguments,
then correctly):
```
$ python cp_test_c34.py
cp_test_c34.py: Error: Missing arguments
cp_test_c34.py: usage: cp_test_c34.py <server_addr> <server_port> '<msg_to_send>'


> python cp_test_c34.py localhost 9001 'This is a test message for Challenge 34!!!'
cp_test_c34.py: ------------------------------------------------------------
cp_test_c34.py: Challenge 34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection: Client
cp_test_c34.py: ------------------------------------------------------------
cp_test_c34.py: server_addr = [localhost]
cp_test_c34.py: server_port = [9001]
cp_test_c34.py: client_msg  = [This is a test message for Challenge 34!!!]
cp_test_c34.py: ------------------------------------------------------------
cp_test_c34.py: Executing...
cp_test_c34.py: ------------------------------------------------------------
cp_test_c34.py: ------------------------------------------------------------
cp_test_c34.py: Executing...done
cp_test_c34.py: ------------------------------------------------------------
cp_test_c34.py: success     = [True]
cp_test_c34.py: server_msg  = [This is a test message for Challenge 34!!!]
cp_test_c34.py: p           = [2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919]
cp_test_c34.py: g           = [2]
cp_test_c34.py: a           = [1799556359217574138302394686461232382539154993105913817210303481854944919685295423166624493081553358610444092412252629803030780026174625037454904589483729705897210231049138586839704431440724625989473945002326630265189356990031390277941183992375517248385501921337771870775286607755315969136136806839331474633312083258838858001305005607014439636506041864536395951225478852245452693966195921832350928936294339059363183991026222254867911668235606406506658776020632071]
cp_test_c34.py: A           = [2393756105909493757837726052892113692389492266056739806553434361232403489523676946361077538250681656684888594511409111742249003095783712333520651652309116280969765850279672156979700283674303931078592082289417423711922793607864749228857554745606767934462417916261883732385906882038725811782913490508081748064494923225995756234547098762000670618532854128900118217888460388208311787901170473881827863268333657893266539563928871560636184404300110153644719204338359710]
cp_test_c34.py: B           = [1904542986915325800766610364746505964555381739070232185660269103888338443400495168085467452468145881716375638972541606663639122898394808453159031203431808024404017066689227081702234676962161625800088109601935579029411210531665651622560364792954435356509835535420201879672690928507773545086626105849353765583863057400570202982861344801957588293439151654155335156581587158796191487599139181662981706829625180201144589476360491139688780436773547886883010553687716735]
cp_test_c34.py: s           = [1489565576219369970311610343717827023736216936045668853571411220280382445345219633220664788154863363807372743952470790774393190543655173574257319653511853857088096786554363799780180310839608819984225673711959447266062059941781986224972849680504260699151712157836008468751992023549270654383937117291168701720038258945915985440847850675072006784268271472711855623846115492191130268066668313176231291710966921958979373324733772006452414524322869763456297078231347119]
cp_test_c34.py: k           = [be9ed25142055425d5cdf938cf920530]
cp_test_c34.py: ------------------------------------------------------------
cp_test_c34.py: TEST        = [OK]
cp_test_c34.py: ------------------------------------------------------------
```


Starting the client to connect with MITM attacker on port 9000 (1st incorrectly without arguments,
then correctly):
```
$ python cp_test_c34.py
cp_test_c34.py: Error: Missing arguments
cp_test_c34.py: usage: cp_test_c34.py <server_addr> <server_port> '<msg_to_send>'


$ python cp_test_c34.py localhost 9000 'This is a test message for Challenge 34!!!'
cp_test_c34.py: ------------------------------------------------------------
cp_test_c34.py: Challenge 34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection: Client
cp_test_c34.py: ------------------------------------------------------------
cp_test_c34.py: server_addr = [localhost]
cp_test_c34.py: server_port = [9000]
cp_test_c34.py: client_msg  = [This is a test message for Challenge 34!!!]
cp_test_c34.py: ------------------------------------------------------------
cp_test_c34.py: Executing...
cp_test_c34.py: ------------------------------------------------------------
cp_test_c34.py: ------------------------------------------------------------
cp_test_c34.py: Executing...done
cp_test_c34.py: ------------------------------------------------------------
cp_test_c34.py: success     = [True]
cp_test_c34.py: server_msg  = [This is a test message for Challenge 34!!!]
cp_test_c34.py: p           = [2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919]
cp_test_c34.py: g           = [2]
cp_test_c34.py: a           = [2227764430602070007397969750035736901300405612223576229226881829287830942202329689706029754286382441716234829413122587914721616246791064266614124006476970521132428770097170499109628898166017354745176809004433068593701674412008148565319131821337607536223623065963120864621496990882974682385913892417806577603838488748994867888168968320686232579639074735105307979566759746023755908890524892869467670951119262432319656297247372216088071899206049657112695063639961576]
cp_test_c34.py: A           = [735765577145384398771388620910480668507508996980783667147731221843220338699776357822989759440422036457733508428967564278672144346897697616260205088196627709585458027618350769074690117534061817771407308864408168101887419309086220587925651514940847045375599772907353941439584546519727347919368026309336209957846904828368825452966774523660070830891702498369304404843948414743784346536015739362406422636336397731373465098458990332400401885431951455736574748388781482]
cp_test_c34.py: B           = [2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919]
cp_test_c34.py: s           = [0]
cp_test_c34.py: k           = [da39a3ee5e6b4b0d3255bfef95601890]
cp_test_c34.py: ------------------------------------------------------------
cp_test_c34.py: TEST        = [OK]
cp_test_c34.py: ------------------------------------------------------------
```


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

"""Cryptopals Challenges: Test Challenge 49: CBC-MAC Message Forgery."""

import sys
import utils.cp_aux_utils as utils
import re

title = "Challenge 49: CBC-MAC Message Forgery"

# Key used throughout the challenge for computing/verifying a CBC-MAC.
key = None
blk_sz = 16

# Debug flag.
debug = 0

# Debug messages.
def debug_msg(*args, **kwargs):
    """Extra debug messages."""
    if not debug:
        return
    print(*args, **kwargs)

# Calculate the CBC-MAC.
def cbc_mac(pt, iv):
    """Calculate the CBC-MAC on a given plaintext."""

    global key

    debug_msg("-" * 60)
    # Generate the key.
    if key == None:
        key = utils.rand_bytes(blk_sz)
        debug_msg("CBC-MAC  : Generate key:")
        debug_msg("CBC-MAC  :   key         = [{0}]".format(key.hex()))

    # CBC encrypt the message.
    pt_pad = utils.pkcs7_pad(pt, blk_sz)
    ct = utils.aes_encrypt(pt_pad, key, mode = 'CBC', iv = iv)

    # The CBC-MAC is the last block from the CBC encrypted message.
    mac = ct[-blk_sz:]

    debug_msg("CBC-MAC  : Calculate CBC-MAC:")
    debug_msg("CBC-MAC  :   blk_sz      = [{0}]".format(blk_sz))
    debug_msg("CBC-MAC  :   key         = [{0}]".format(key.hex()))
    debug_msg("CBC-MAC  :   pt          = [{0}]".format(pt))
    debug_msg("CBC-MAC  :   pt_pad      = [{0}]".format(pt_pad))
    debug_msg("CBC-MAC  :   iv          = [{0}]".format(iv.hex()))
    debug_msg("CBC-MAC  :   ct          = [{0}]".format(ct.hex()))
    debug_msg("CBC-MAC  :   mac         = [{0}]".format(mac.hex()))

    return mac

# Server: Process a request message (for the 1st challenge scenario).
def server_process_request_1(req):
    """Simulates the server request message processing for the 1st scenario."""

    # Message format: 'message || IV || MAC'.
    # Both 'IV' and 'MAC' have 'blk_sz' length.
    mac = req[-blk_sz:]
    iv = req[-(2 * blk_sz):-blk_sz]
    msg = req[:-(2 * blk_sz)]
    print("-" * 60)
    print("SERVER1  : New Request:")
    debug_msg("SERVER1  :   req         = [{0}]".format(req))
    debug_msg("SERVER1  :   iv          = [{0}]".format(iv.hex()))
    debug_msg("SERVER1  :   msg         = [{0}]".format(msg))

    # Verify the CBC-MAC.
    print("SERVER1  :   Calculating CBC-MAC...")
    mac_ok = cbc_mac(msg, iv)
    debug_msg("-" * 60)
    print("SERVER1  :   Calculating CBC-MAC...done")
    debug_msg("SERVER1  :   mac recv    = [{0}]".format(mac.hex()))
    debug_msg("SERVER1  :   mac ok      = [{0}]".format(mac_ok.hex()))
    if mac != mac_ok:
        print("SERVER1  : Request is INVALID: Incorrect CBC-MAC")
        return False

    # Parse the request message.
    trf_from = ""
    trf_to = ""
    trf_amount = 0
    items = msg.split(b'&')
    # Only items 'from', 'to' and 'amount' are allowed, and all
    # are required, no less, no more and in this order.
    allowed_items = [b'from', b'to', b'amount']
    if len(items) != len(allowed_items):
        print("SERVER1  : Request is INVALID: Incorrect items number: [{0}] (should be [{1}])"
                .format(len(items), len(allowed_items)))
        return False
    for i, item in enumerate(items):
        kv = item.split(b'=')
        # For each item, only one 'key=value' pair is allowed.
        if len(kv) != 2:
            print("SERVER1  : Request is INVALID: Incorrect item syntax: [{0}]"
                    .format(utils.bytes2rawstr(item)))
            print("-" * 60)
            return False
        k = kv[0]
        v = kv[1]
        if k != allowed_items[i]:
            print("SERVER1  : Request is INVALID: Unexpected item key: [{0}] (should be [{1}])"
                    .format(utils.bytes2rawstr(k), utils.bytes2rawstr(allowed_items[i])))
            print("-" * 60)
            return False
        if len(v) == 0:
            print("SERVER1  : Request is INVALID: Empty item value in key: [{0}]"
                    .format(utils.bytes2rawstr(k)))
            print("-" * 60)
            return False
        if k == b'from':
            match = re.match(b'^[A-Za-z]+$', v)
            if not match:
                print("SERVER1  : Request is INVALID: Invalid 'from': [{0}]"
                        .format(utils.bytes2rawstr(v)))
                print("-" * 60)
                return False
            trf_from = utils.bytes2rawstr(v)
        elif k == b'to':
            match = re.match(b'^[A-Za-z]+$', v)
            if not match:
                print("SERVER1  : Request is INVALID: Invalid 'to': [{0}]"
                        .format(utils.bytes2rawstr(v)))
                print("-" * 60)
                return False
            trf_to = utils.bytes2rawstr(v)
        else:
            match = re.match(b'^[0-9]+$', v)
            if not match:
                print("SERVER1  : Request is INVALID: Invalid 'amount': [{0}]"
                        .format(utils.bytes2rawstr(v)))
                print("-" * 60)
                return False
            trf_amount = int(match.group(0))

    # Request message accepted!
    print("SERVER1  : Request is VALID:")
    print("SERVER1  : Transfer [{0}] from [{1}] to [{2}]!".format(trf_amount, trf_from, trf_to))
    print("-" * 60)
    return True

# Server: Process a request message (for the 2nd challenge scenario).
def server_process_request_2(req):
    """Simulates the server request message processing for the 2nd scenario."""

    # Message format: 'message || MAC'.
    # 'MAC' has 'blk_sz' length.
    mac = req[-blk_sz:]
    msg = req[:-blk_sz]
    # The 'IV' is fixed to zero.
    iv = b'\x00' * blk_sz
    print("-" * 60)
    print("SERVER2  : New Request:")
    debug_msg("SERVER2  :   req         = [{0}]".format(req))
    debug_msg("SERVER2  :   iv(fixed)   = [{0}]".format(iv.hex()))
    debug_msg("SERVER2  :   msg         = [{0}]".format(msg))

    # Verify the CBC-MAC.
    print("SERVER2  :   Calculating CBC-MAC...")
    mac_ok = cbc_mac(msg, iv)
    debug_msg("-" * 60)
    print("SERVER2  :   Calculating CBC-MAC...done")
    debug_msg("SERVER2  :   mac recv    = [{0}]".format(mac.hex()))
    debug_msg("SERVER2  :   mac ok      = [{0}]".format(mac_ok.hex()))
    if mac != mac_ok:
        print("SERVER2  : Request is INVALID: Incorrect CBC-MAC")
        return False

    # Parse the request message.
    trf_from = ""
    items = msg.split(b'&')
    # Only items 'from' and 'tx_list' are allowed, and all
    # are required, no less, no more and in this order.
    allowed_items = [b'from', b'tx_list']
    if len(items) != len(allowed_items):
        print("SERVER2  : Request is INVALID: Incorrect items number: [{0}] (should be [{1}])"
                .format(len(items), len(allowed_items)))
        return False
    for i, item in enumerate(items):
        kv = item.split(b'=')
        # For each item, only one 'key=value' pair is allowed.
        if len(kv) != 2:
            print("SERVER2  : Request is INVALID: Incorrect item syntax: [{0}]"
                    .format(utils.bytes2rawstr(item)))
            print("-" * 60)
            return False
        k = kv[0]
        v = kv[1]
        if k != allowed_items[i]:
            print("SERVER2  : Request is INVALID: Unexpected item key: [{0}] (should be [{1}])"
                    .format(utils.bytes2rawstr(k), utils.bytes2rawstr(allowed_items[i])))
            print("-" * 60)
            return False
        if len(v) == 0:
            print("SERVER2  : Request is INVALID: Empty item value in key: [{0}]"
                    .format(utils.bytes2rawstr(k)))
            print("-" * 60)
            return False
        if k == b'from':
            match = re.match(b'^[A-Za-z]+$', v)
            if not match:
                print("SERVER2  : Request is INVALID: Invalid 'from': [{0}]"
                        .format(utils.bytes2rawstr(v)))
                print("-" * 60)
                return False
            trf_from = utils.bytes2rawstr(v)
        else:
            tx_list = v
    # Parse the 'tx_list'.
    tx_items = [tx_item.split(b':') for tx_item in tx_list.split(b';')]
    if len(tx_items) < 1:
        print("SERVER2  : Request is INVALID: No tx items")
        return False
    for tx_item in tx_items:
        # This check had to be relaxed for allowing the attack.
        # It was originally 'len(tx_item) != 2'.
        if len(tx_item) < 2:
            print("SERVER2  : Request is INVALID: Invalid 'tx_item': [{0}]"
                    .format(tx_item))
            print("-" * 60)
            return False
        (trf_to, trf_amount) = (tx_item[0], tx_item[1])
        match = re.match(b'^[A-Za-z]+$', trf_to)
        if not match:
            print("SERVER2  : Request is INVALID: Invalid 'to' in tx_item: [{0}]"
                    .format(utils.bytes2rawstr(trf_to)))
            print("-" * 60)
            return False
        # This check had to be relaxed for allowing the attack.
        # Regex was originally '^[0-9]+$'.
        match = re.match(b'^[0-9]+', trf_amount)
        if not match:
            print("SERVER2  : Request is INVALID: Invalid 'amount' in tx_item: [{0}]"
                    .format(utils.bytes2rawstr(trf_amount)))
            print("-" * 60)
            return False

    # Request message accepted!
    print("SERVER2  : Request is VALID:")
    for tx_item in tx_items:
        (trf_to, trf_amount) = (tx_item[0], tx_item[1])
        trf_amount = re.match(b'(^[0-9]+)', trf_amount).group(1)
        print("SERVER2  : Transfer [{0}] from [{1}] to [{2}]!"
                .format(int(trf_amount), trf_from, utils.bytes2rawstr(trf_to)))
    print("-" * 60)
    return True

# Client: Build and send a request message to server (for the 1st challenge scenario).
def client_send_request_1(trf_from, trf_to, trf_amount):
    """Simulates the client request message sending for the 1st scenario."""

    print("-" * 60)
    print("CLIENT1  : New Request:")
    print("CLIENT1  :   from        = [{0}]".format(trf_from))
    print("CLIENT1  :   to          = [{0}]".format(trf_to))
    print("CLIENT1  :   amount      = [{0}]".format(trf_amount))

    # Do some validations.
    if not re.match('^[A-Za-z]+$', trf_from):
        print("CLIENT1  : Request is INVALID: Incorrect 'from': [{0}]".format(trf_from))
        print("-" * 60)
        return (False, None)
    if not re.match('^[A-Za-z]+$', trf_to):
        print("CLIENT1  : Request is INVALID: Incorrect 'to': [{0}]".format(trf_to))
        print("-" * 60)
        return (False, None)
    if not re.match('^[0-9]+$', str(trf_amount)):
        print("CLIENT1  : Request is INVALID: Incorrect 'amount': [{0}]".format(trf_amount))
        print("-" * 60)
        return (False, None)

    # Build the request message.
    msg = "from={0}&to={1}&amount={2}".format(trf_from, trf_to, trf_amount)
    msg = utils.rawstr2bytes(msg)
    iv = utils.rand_bytes(blk_sz)
    print("CLIENT1  :   Calculating CBC-MAC...")
    mac = cbc_mac(msg, iv)
    debug_msg("-" * 60)
    print("CLIENT1  :   Calculating CBC-MAC...done")
    # Message format: 'message || IV || MAC'.
    req = msg + iv + mac
    debug_msg("CLIENT1  :   msg         = [{0}]".format(msg))
    debug_msg("CLIENT1  :   iv          = [{0}]".format(iv.hex()))
    debug_msg("CLIENT1  :   mac         = [{0}]".format(mac.hex()))
    debug_msg("CLIENT1  :   req         = [{0}]".format(req))

    # There's no actual web client/server implemented.
    # Just forward the message to the server processing function.
    print("CLIENT1  :   Sending to server...")
    ok = server_process_request_1(req)
    print("CLIENT1  :   Sending to server...done")
    print("CLIENT1  : Request {0}".format("OK" if ok else "FAILED"))
    print("-" * 60)
    return (ok, req)

# Client: Build and send a request message to server (for the 2nd challenge scenario).
def client_send_request_2(trf_from, trf_list):
    """Simulates the client request message sending for the 1st scenario."""

    print("-" * 60)
    print("CLIENT2  : New Request:")
    print("CLIENT2  :   from        = [{0}]".format(trf_from))
    print("CLIENT2  :   list        = [{0}]".format(trf_list))

    # Do some validations.
    if not re.match('^[A-Za-z]+$', trf_from):
        print("CLIENT2  : Request is INVALID: Incorrect 'from': [{0}]".format(trf_from))
        print("-" * 60)
        return (False, None)
    if len(trf_list) < 1:
        print("CLIENT2  : Request is INVALID: Empty list")
        print("-" * 60)
        return (False, None)
    for trf_item in trf_list:
        if len(trf_item) != 2:
            print("CLIENT2  : Request is INVALID: Incorrect trf_list item: [{0}]".format(trf_item))
            print("-" * 60)
            return (False, None)
        (trf_to, trf_amount) = trf_item
        if not re.match('^[A-Za-z]+$', trf_to):
            print("CLIENT2  : Request is INVALID: Incorrect 'to': [{0}] in [{1}]"
                    .format(trf_to, trf_item))
            print("-" * 60)
            return (False, None)
        if not re.match('^[0-9]+$', str(trf_amount)):
            print("CLIENT2  : Request is INVALID: Incorrect 'amount': [{0}] in [{1}]"
                    .format(trf_amount, trf_item))
            print("-" * 60)
            return (False, None)

    # Build the request message.
    tx_list_msg = ";".join(["{0}:{1}".format(to, amount) for (to, amount) in trf_list])
    msg = "from={0}&tx_list={1}".format(trf_from, tx_list_msg)
    msg = utils.rawstr2bytes(msg)
    # The 'IV' is fixed to zero in this scenario.
    iv = b'\x00' * blk_sz
    print("CLIENT2  :   Calculating CBC-MAC...")
    mac = cbc_mac(msg, iv)
    debug_msg("-" * 60)
    print("CLIENT2  :   Calculating CBC-MAC...done")
    # Message format: 'message || MAC'.
    req = msg + mac
    debug_msg("CLIENT2  :   msg         = [{0}]".format(msg))
    debug_msg("CLIENT2  :   iv(fixed)   = [{0}]".format(iv.hex()))
    debug_msg("CLIENT2  :   mac         = [{0}]".format(mac.hex()))
    debug_msg("CLIENT2  :   req         = [{0}]".format(req))

    # There's no actual web client/server implemented.
    # Just forward the message to the server processing function.
    print("CLIENT2  :   Sending to server...")
    ok = server_process_request_2(req)
    print("CLIENT2  :   Sending to server...done")
    print("CLIENT2  : Request {0}".format("OK" if ok else "FAILED"))
    print("-" * 60)
    return (ok, req)

# Execute the attack for the challenge's 1st scenario, for
# which the 'IV' is controlled by the attacker.
def execute_forge_cbc_mac_1(victim, attacker, amount):
    """Execute the attack for the challenge's 1st scenario."""

    # Besides the explanation about the attack in the challenge's statement
    # itself, there's also a more detailed explanation in Wikipedia under
    # https://en.wikipedia.org/wiki/CBC-MAC.
    #
    # The attack exploits the fact that the attacker has control over the
    # CBC initialization vector, giving him the power to flip any bits
    # of the message's 1st block by flipping the same bits of the 'IV' he
    # controls, while keeping a previously calculated and valid CBC-MAC intact
    # and reusable.
    #
    # The attacker cannot check messages from other clients, but he is able to
    # create a fake account, generate and peek at messages created from his
    # fake account and then finally change such a message so that he transfers
    # the money from a real victim account into the attackers real account.
    #
    # The following considerations assume a 16-byte block size, but are valid
    # for any other block size.
    #
    # The message structure is 'from=#{from_id}&to=#{to_id}&amount=#{amount}'.
    # The idea is to create a fake account (for the 'from' part) whose ID may
    # depend on the final victim ID (names in this implementation) to attack,
    # having in mind that this attack allows changing the first block (16 bytes)
    # as wished, but nothing else. With the fake ID, the attacker creates a
    # valid request, with a valid CBC-MAC and with the 'to' and 'amount' parts
    # already set to the final required result, i.e., 'to' set to the attacker's
    # real name and the amount set as wanted. The server would accept this
    # request in terms of CBC-MAC validation, but otherwise reject it or ignore
    # it because, e.g., the fake account wouldn't have such amount. Still this
    # leaves the attacker with a message having a valid CBC-MAC and a 1st block
    # he can change as pleased.
    #
    # Since the attacker can only control the 1st 16-byte block, the attack
    # focus on changing the 'from' part, from the fake account into the victim's
    # real account. The way this is done depends on the victim's name:
    #  + The 'from=' part already takes 5 bytes. This leaves 11 bytes left on
    #    the 1st block.
    #  + If the victim's name length is <= 11 chars, then the fake account name
    #    can be anything with the same length as the victim's name, because all
    #    of the victim's name chars stay on the 1st block, thus fully reachable
    #    by the attack.
    #  + If the victim's name exceeds 11 chars, then those exceeding chars are
    #    outside the 1st block, thus out of the attack's reach, so they must be
    #    used for the trailing part of the fake name. In this case, the fake name
    #    can start with any 11 chars, but the remaining chars must match the same
    #    chars of the victim's name.
    #
    # Once this prepared request message for the fake account is generated, sent
    # and captured, its 'from' part can be changed to contain the real victim's
    # name while keeping its CBC-MAC, simply by checking which bits were flipped
    # for changing the 'from' name and flip the same bits on the 'IV'. Since the
    # rest of the request message already contained the attacker's real account
    # in the 'to' part as well as the amount required, this effectively changes
    # the 'from' part from the attacker's fake account into the victim's real
    # account in a message request that will be accepted by the server, thus
    # achieving the desired attack goal.
    #
    # Regarding the bit flipping, it's explained by the CBC way of operation.
    # When the server will validate the CBC-MAC, it starts by encrypting the
    # message using the client/server shared key and the IV provided by the
    # client. The last block of the encrypted message is the MAC.
    # For the fake account message, the CBC-MAC process will get 'IV_1' and
    # 'Block0_1' (as the IV and the 1st message block), XOR them, feed that
    # to the cipher to get the 1st ciphertext block and continue with the same
    # process till the final ciphertext block, which is the MAC. Let's call
    # 'I_1 = IV_1 XOR Block0_1', which is what is fed to the cipher in the
    # 1st step. When the attacker hacks the 1st block to change the 'from' into
    # the real victim's name, it is changing block 0 to 'Block0_2'. What the
    # attacker wants is to have 'I_2' same as 'I_1', which will cause the
    # CBC-MAC calculation on the server to reach the same result as for the
    # message with the fake account.
    # So, we have:
    #  'I_1 = IV_1 XOR Block0_1'    (for the fake account message)
    #  'I_2 = IV_2 XOR Block0_2',   (for the real victim account message)
    #  'I_2 = I_1'                  (for reaching the same CBC-MAC in the end)
    # This gives:
    #  'IV_2 XOR Block0_2 = IV_1 XOR Block0_1'      <=>
    #  'IV_2 = IV_1 XOR (Block0_1 XOR Block0_2)'
    # Which is exactly what was described before, i.e., the same bit flipping
    # that was done for going from 'Block0_1' into 'Block0_2' must also be
    # applied to 'IV_1' in order to have an 'IV_2' that keeps the same final
    # CBC-MAC in both messages.

    print("-" * 60)
    print("ATTACKER1: New Request:")
    print("ATTACKER1:   victim      = [{0}]".format(victim))
    print("ATTACKER1:   attacker    = [{0}]".format(attacker))
    print("ATTACKER1:   amount      = [{0}]".format(amount))

    # Let's start by creating the fake name, depending on the victim's name.
    len_from = len("from=")
    len_remain = blk_sz - len_from
    fake_from = "X" * min(len(victim), len_remain) + victim[len_remain:]
    debug_msg("ATTACKER1:   fake_from   = [{0}]".format(fake_from))

    # It's assumed the attacker can create an account with the fake name,
    # so he can also create, issue and capture a valid request using this fake
    # name in the 'from' part.
    print("ATTACKER1:   Sending fake request...")
    (ok, fake_req) = client_send_request_1(fake_from, attacker, amount)
    print("ATTACKER1:   Sending fake request...done")
    if not ok:
        print("ATTACKER1: Send fake request FAILED")
        print("-" * 60)
        return (False, None)

    # Extract the required elements from the fake request.
    mac = fake_req[-blk_sz:]
    fake_iv = fake_req[-(2 * blk_sz):-blk_sz]
    fake_msg = fake_req[:-(2 * blk_sz)]
    debug_msg("ATTACKER1:   fake_req    = [{0}]".format(fake_req))
    debug_msg("ATTACKER1:   mac         = [{0}]".format(mac.hex()))
    debug_msg("ATTACKER1:   fake_iv     = [{0}]".format(fake_iv.hex()))
    debug_msg("ATTACKER1:   fake_msg    = [{0}]".format(fake_msg))

    # Hack the fake request to replace the fake name in the 'from' part by the
    # real victim's name, while keeping everything else afterwards.
    hacked_msg = b'from=' + utils.rawstr2bytes(victim) + fake_msg[len_from + len(victim):]

    # Compensate the changing of the 1st block by applying the same changes on
    # the IV, to keep the CBC-MAC valid on the hacked message.
    hacked_iv = utils.xor(fake_iv, utils.xor(fake_msg[:blk_sz], hacked_msg[:blk_sz]))

    # Create the hacked request and inject it on the server.
    hacked_req = hacked_msg + hacked_iv + mac
    debug_msg("ATTACKER1:   hacked_msg  = [{0}]".format(hacked_msg))
    debug_msg("ATTACKER1:   hacked_iv   = [{0}]".format(hacked_iv.hex()))
    debug_msg("ATTACKER1:   hacked_req  = [{0}]".format(hacked_req))
    print("ATTACKER1:   Injecting hacked request...")
    ok = server_process_request_1(hacked_req)
    print("ATTACKER1:   Injecting hacked request...done")
    print("ATTACKER1: Inject hacked request {0}".format("OK" if ok else "FAILED"))
    print("-" * 60)
    return (ok, hacked_req)

# Execute the attack for the challenge's 2n scenario, for
# which the 'IV' is fixed.
def execute_forge_cbc_mac_2(victim, victim_list, attacker, amount):
    """Execute the attack for the challenge's 2nd scenario."""

    # In this 2nd scenario, the attacker no longer controls the 'IV', so he
    # no longer is able to change a message's 1st block.
    #
    # In this scenario, the attacker is able to grab a valid signed request
    # from the victim issuing a transfer request to some arbitrary list of
    # recipients. The attacker, like in 1st scenario, is also able to create
    # some fake account and message request having the fake account name in
    # the 'from' part.
    # The message structure is now 'from=#{from_id}&tx_list=#{transactions}'
    # with the 'transactions' part being a list of 'to' / 'amount' pairs
    # represented by 'to:amount(;to:amount)*'.
    #
    # The attack works by exploiting the fact that the attacker can grab
    # a valid request from the victim, thus knowing what its CBC-MAC is, and
    # then concatenating it (length extending it) with a modified version of
    # a message of its own from his fake account. The final attacking message
    # starts with the captured victim's message and ends with a modified
    # version of an attacker fake request message, in a way that the final
    # attacking message extends the 'transactions' list of the victim's
    # original message to contain the attacker's real account and amount
    # required.
    #
    # This way, we have for the original captured victim's message request:
    #  R1 = M1 || MAC1
    # This message has the victim's name in the 'from' part and some random
    # names in the 'transactions' list.
    # The attacker fake message request is:
    #  R2 = M2 || MAC2
    # It contains a prepared 'from' part in the 1st message block which is
    # the attacker's fake account name and the attacker real name and desired
    # amount is placed in the 'transactions' part.
    # The final, attacking message will then be:
    #  R3 = M3 || MAC2
    # Note the final message CBC-MAC is 'MAC2', the one from 'R2'.
    # 'M3' must start with 'M1' so that the victim's name is in the 'from'
    # part. It must then be padded so that the server will compute the CBC-MAC
    # to match 'MAC1' up until the end of the padding of 'M1', just like it did
    # for 'R1'. So, up until now, we have 'M3 = Pad(M1)', which computes to a
    # CBC-MAC of 'MAC1'. We now want to extend this message with parts of 'M2',
    # with the final CBC-MAC computing to 'MAC2'. We know that 'MAC2' was
    # calculated for R2 with an 'IV = 0', but now we already have the previous
    # ciphertext calculated (on 'M3 = Pad(M1)'), which is 'MAC1'.
    # The original computation made by the server for M2's 1st block is:
    #  I2 = M2_0 XOR IV = M2_0 XOR 0 = M2_0
    # 'I2' is what's fed to the cipher for the 1st block.
    # With 'M3_ext', we want to keep this 'I2, so that the final CBC-MAC is
    # 'MAC2'.
    # In 'M3_ext', we have:
    #  I3 = MAC1 XOR M3_ext_0.
    # If we want 'I3 = I2', it gives:
    #  MAC1 XOR M3_ext_0 = M2_0
    #  M3_ext_0 = M2_0 XOR MAC1
    # This means we have to "sacrifice" the 1st block of 'M2' ('M2_0') in order
    # to keep 'MAC2' as the valid CBC-MAC of 'M3' ('Pad(M1) || M2_modified').
    # This is actually convenient, has it's important to remove the 'from' part
    # and the initial part of the 'tx_list' out of 'M2', because we only want to
    # extend the 'transactions' part of the original 'M1'.
    #
    # So, in summary, the forged message 'M3' will be a concatenation of:
    #  + 'M1', the original victim's captured message.
    #  + Padding of 'M1' to block size.
    #    Required so that at its end, the CBC-MAC is indeed 'MAC1' and also to
    #    align the following 'M2' part to block size (to keep its padding
    #    requirement needed to keep 'MAC2' as well).
    #  + The 1st block of 'M2' XORed with 'MAC1'.
    #    Mandatory to have the forged message CBC-MAC kept to 'MAC2'. In this
    #    case, we're actually replacing the 'IV = 0' of M2 by 'IV = MAC1', so
    #    we must also change the 1st block of 'M2' to keep the final 'MAC2'.
    #  + The remaining part of 'M2', starting from its 2nd block.
    # This also means that 'M3' will have some "garbage" between M1's original
    # 'transaction' list and M2's forged transaction list:
    #  + The padding of 'M1'.
    #  + The XORed 1st block of 'M2'.
    # This attack only works if the server ignores this "garbage".

    print("-" * 60)
    print("ATTACKER2: New Request:")
    print("ATTACKER2:   victim      = [{0}]".format(victim))
    print("ATTACKER2:   victim_list = [{0}]".format(victim_list))
    print("ATTACKER2:   attacker    = [{0}]".format(attacker))
    print("ATTACKER2:   amount      = [{0}]".format(amount))

    # Simulate grabbing the victim's original request ('R1' / 'M1').
    print("ATTACKER2:   Capturing victim's request...")
    (ok, r1) = client_send_request_2(victim, victim_list)
    print("ATTACKER2:   Capturing victim's request...done")
    if not ok:
        print("ATTACKER2: Capture victim's request FAILED")
        print("-" * 60)
        return (False, None)
    # Extract the msg and mac.
    mac1 = r1[-blk_sz:]
    m1 = r1[:-blk_sz]
    debug_msg("ATTACKER2:   r1          = [{0}]".format(r1))
    debug_msg("ATTACKER2:   m1          = [{0}]".format(m1))
    debug_msg("ATTACKER2:   mac1        = [{0}]".format(mac1.hex()))

    # Creating the fake name and account (to be used in 'M2').
    # The final attacking message ('M3') will contain this message, but with
    # its 1st block XORed with 'MAC1'. This is OK and actually required,
    # because we'll be wanting to remove the 'from' and 'tx_list' text from it,
    # so the final message extends the 'transactions' list of the original
    # victim's message.
    # The message will be:
    #  "from=X&tx_list=Y:0;<AttackerName>:<AttackerAmount>"
    # Note the 1st block ends at the 'Y' from the 'tx_list' part.
    # In the final message, this will turn to garbage and the extension to the
    # original victim's message will be ":0;<AttackerName>:<AttackerAmount>".
    # 'X' is a fake account controlled by the attacker.
    fake_from = "X"
    fake_list = [["Y", 0] , [attacker, amount]]
    print("ATTACKER2:   Sending fake request...")
    (ok, r2) = client_send_request_2(fake_from, fake_list)
    print("ATTACKER2:   Sending fake request...done")
    if not ok:
        print("ATTACKER2: Send fake request FAILED")
        print("-" * 60)
        return (False, None)
    # Extract the msg and mac.
    mac2 = r2[-blk_sz:]
    m2 = r2[:-blk_sz]
    debug_msg("ATTACKER2:   r2          = [{0}]".format(r2))
    debug_msg("ATTACKER2:   m2          = [{0}]".format(m2))
    debug_msg("ATTACKER2:   mac2        = [{0}]".format(mac2.hex()))

    # Build the final attacking message ('M3').
    # 'M1' padded.
    m1_pad = utils.pkcs7_pad(m1, blk_sz)
    #  1st block of 'M2' XORed with 'MAC1'.
    m3_ext_0 = utils.xor(m2[0:blk_sz], mac1)
    # Final 'M3'.
    m3 = m1_pad + m3_ext_0 + m2[blk_sz:]
    r3 = m3 + mac2
    debug_msg("ATTACKER2:   m1_pad      = [{0}]".format(m1_pad))
    debug_msg("ATTACKER2:   m3_ext_0    = [{0}]".format(m3_ext_0))
    debug_msg("ATTACKER2:   m3          = [{0}]".format(m3))
    debug_msg("ATTACKER2:   r3          = [{0}]".format(r3))
    print("ATTACKER2:   Injecting hacked request...")
    ok = server_process_request_2(r3)
    print("ATTACKER2:   Injecting hacked request...done")
    print("ATTACKER2: Inject hacked request {0}".format("OK" if ok else "FAILED"))
    print("-" * 60)
    return (ok, r3)

if __name__ == '__main__':
    try:
        me = sys.argv[0]
        in_victim = "VictorTheVictim"
        in_attacker = "AceTheAttacker"
        in_amount = 1000000
        in_victim_list = [["Alice", 1234], ["Bob", 5678]]
        (ok1, req1) = execute_forge_cbc_mac_1(in_victim, in_attacker, in_amount)
        (ok2, req2) = execute_forge_cbc_mac_2(in_victim, in_victim_list, in_attacker, in_amount)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: {1}".format(me, title))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: blk_sz      = [{1}]".format(me, blk_sz))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Scenario 1:".format(me))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: attacker    = [{1}]".format(me, in_attacker))
        print("{0}: victim      = [{1}]".format(me, in_victim))
        print("{0}: amount      = [{1}]".format(me, in_amount))
        print("{0}: ok          = [{1}]".format(me, ok1))
        print("{0}: req         = [{1}]".format(me, req1))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: Scenario 2:".format(me))
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: attacker    = [{1}]".format(me, in_attacker))
        print("{0}: victim      = [{1}]".format(me, in_victim))
        print("{0}: victim_list = [{1}]".format(me, in_victim_list))
        print("{0}: amount      = [{1}]".format(me, in_amount))
        print("{0}: ok          = [{1}]".format(me, ok2))
        print("{0}: req         = [{1}]".format(me, req2))
        ok = (ok1 and ok2)
        if not ok:
            err_str = "\n{0}: ".format(me) + "-" * 60
            err_str += "\n{0}: TEST        = [FAILED] Result doesn't match expected.".format(me)
            err_str += "\n{0}: ".format(me) + "-" * 60
            raise Exception(err_str)
        print("{0}: ".format(me) + "-" * 60)
        print("{0}: TEST        = [OK]".format(me))
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


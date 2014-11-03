# Expected comm as follows

import os
from binascii import hexlify as hex
import json
from functools import partial
import quopri

from nuts import AuthChannel, _messages, send as _send, hkdf_expand, mac, Message

shared_key = '39115349d0124171cccbdd46ce24c55f98a66809bff4f73d344abf81351a9ff6'.decode('hex')

id_a = b'NUTS-1'

id_b = b'GroundStation-1'

R_b = os.urandom(8)

conn = AuthChannel(id_a, shared_key)


def send(msg):
    _send(id_b, id_a, msg)
    conn.receive(_messages[-1])

m0 = '\x00' + R_b
m0_digest = mac(shared_key, id_a + id_b + m0)
send(m0 + m0_digest)

def ascii_bin(binstr):
    return repr(quopri.encodestring(binstr))


# First message from sat should be 128 bits + 1 byte msg type, and should verify the identify of the sat
assert _messages[-1].msg[0] == '\x80'
assert len(_messages[-1].msg) == 17
assert _messages[-1].dest == id_b
m1_mac_input = id_a + id_b + _messages[-1].msg[:-8] + R_b
expected_m1_digest = mac(shared_key, m1_mac_input)

# Message digest should be correct
assert _messages[-1].msg[-8:] == expected_m1_digest

# Prove our knowledge of shared_key, and send a SA proposal
R_a = _messages[-1].msg[1:9]

sa_proposal = {
    'macs': ['sha3_512'],
    'mac_len': 8,
}

m2 = '\x01' + json.dumps(sa_proposal)
m2_mac_input = id_a + id_b + m2 + _messages[-1].msg[1:9]
m2_digest = mac(shared_key, m2_mac_input)
send(m2 + m2_digest)

# SA response
proposal_response_raw, sig = _messages[-1].msg[:-8], _messages[-1].msg[-8:]

# Verify sig
assert sig == mac(shared_key, id_a + id_b + proposal_response_raw + R_a + R_b)

proposal_response = json.loads(proposal_response_raw[1:])


# Should agree on sha3_512
assert proposal_response['mac'] == 'sha3_512'

# Should agree on 8 byte sigs
assert proposal_response['mac_len'] == 8

session_key = hkdf_expand(shared_key + R_a + R_b, length=16)
s_seq = c_seq = 1

def conn_mac(message):
    return mac(session_key, id_a + id_b + message + str(c_seq),
        algo=proposal_response['mac'],
        mac_len=proposal_response['mac_len'])

# Send first actual command
cmd = {'cmd': 'TakePicture'}
cmd_msg = '\x02' + json.dumps(cmd)
send(cmd_msg + conn_mac(cmd_msg))

# Expect ACK
ack, sig = _messages[-1].msg[-8:], _messages[-1].msg[-8:]


c_seq += 1

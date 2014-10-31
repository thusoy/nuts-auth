# Expected comm as follows

import os
from binascii import hexlify as hex
import json
from functools import partial
import quopri

from nuts import AuthChannel, _messages, send as _send, hkdf_expand, mac, get_mac, Message

shared_key = '39115349d0124171cccbdd46ce24c55f98a66809bff4f73d344abf81351a9ff6'.decode('hex')

id_a = b'NUTS-1'

id_b = b'GroundStation-1'

R_b = os.urandom(8)

conn = AuthChannel(id_a, shared_key)

print 'R_b', quopri.encodestring(R_b)


def send(msg):
    _send(id_b, id_a, msg)
    conn.receive(_messages[-1])

m0 = '\x00' + R_b
m0_digest = mac(shared_key, id_a + id_b + m0)
send(m0 + m0_digest)

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
m2_mac_input = id_a + id_b + m2 + _messages[-1].msg[:9]
m2_digest = mac(shared_key, m2_mac_input)
send(m2 + m2_digest)
session_key = hkdf_expand(shared_key + R_a + R_b, length=16)


msg = json.dumps(sa_proposal)

send(id_a, msg + mac(session_key, msg))

conn.sa_proposal_received(_messages[-1].msg)

# SA response
proposal_response = json.loads(_messages[-1].msg[:-8])

# Should agree on sha3_512
assert proposal_response['mac'] == 'sha3_512'

conn_mac = get_mac(proposal_response['mac'], proposal_response['mac_len'])

# Should be valid signature
assert _messages[-1].msg[-8:] == conn_mac(session_key, _messages[-1].msg[:-8])


# Send first actual command
cmd = {'cmd': 'TakePicture'}
cmd_msg = json.dumps(cmd)
send(id_a, cmd_msg + conn_mac(session_key, cmd_msg))





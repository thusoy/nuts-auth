# Expected comm as follows

import os
import json

from nuts import Connection, _messages, send, hkdf_expand, mac, get_mac

shared_key = '39115349d0124171cccbdd46ce24c55f98a66809bff4f73d344abf81351a9ff6'.decode('hex')

id_a = b'NUTS-1'

id_b = b'GroundStation-1'

R_b = os.urandom(8)

conn = Connection(id_a, id_b, R_b)

# First message from sat should be 128 bits, and should verify the identify of the sat
assert len(_messages[0].msg) == 16
assert _messages[0].dest == id_b
msg = id_a + id_b + R_b
expected_m1_digest = mac(shared_key, msg)

# Message digest should be correct
assert _messages[0].msg[8:] == expected_m1_digest

# Prove our knowledge of shared_key
R_a = _messages[0].msg[:8]
msg = id_a + id_b + R_a
m2_digest = mac(shared_key, msg)

send(id_a, m2_digest)
conn.challenge_reply_received(_messages[-1].msg)
session_key = hkdf_expand(shared_key + R_a + R_b, length=16)
reply = 'Okay'

# Assert both agreed on the same session key
assert _messages[-1].msg[:8] == 'Go ahead'
assert _messages[-1].msg[len('Go ahead'):] == mac(session_key, 'Go ahead')

sa_proposal = {
    'macs': ['sha3_512'],
    'mac_len': 8,
}

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





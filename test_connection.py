# Expected comm as follows

import os
import hmac

from nuts import Connection, _messages, send, Hkdf

shared_key = '39115349d0124171cccbdd46ce24c55f98a66809bff4f73d344abf81351a9ff6'.decode('hex')

id_a = b'NUTS-1'

id_b = b'GroundStation-1'

R_b = os.urandom(8)

conn = Connection(shared_key, id_a, id_b, R_b)

# First message from sat should be 128 bits, and should verify the identify of the sat
assert len(_messages[0].msg) == 16
assert _messages[0].dest == id_b
expected_hash_m1 = hmac.sha256(shared_key)
expected_hash_m1.update(id_a)
expected_hash_m1.update(id_b)
expected_hash_m1.update(R_b)
expected_m1_digest = expected_hash_m1.digest()

# Message digest should be correct
assert _messages[0].msg[8:] == expected_m1_digest

# Prove our knowledge of shared_key
R_a = _messages[0].msg[:8]
h = hmac.sha256(shared_key)
h.update(id_a)
h.update(id_b)
h.update(R_a)
h.update(_messages[0].msg[8:])
m2_digest = h.digest()[:8]

send(id_a, m2_digest)
conn.challenge_reply_received(_messages[-1].msg)
session_key = Hkdf(shared_key + R_a + R_b)
reply = 'Okay'

# Assert both agreed on the same session key
assert _messages[-1].msg = hmac.sha256(session_key).update('Go ahead').digest()

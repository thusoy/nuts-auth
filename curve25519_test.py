from nacl.public import PrivateKey
from nacl.c import crypto_scalarmult

gs_key = PrivateKey.generate()
sat_key = PrivateKey.generate()

gs_pub = gs_key.public_key
sat_pub = sat_key.public_key

sat_token = crypto_scalarmult(sat_key._private_key, gs_pub._public_key)
gs_token = crypto_scalarmult(gs_key._private_key, sat_pub._public_key)

print sat_token.encode('hex')
print gs_token.encode('hex')
print len(gs_token)

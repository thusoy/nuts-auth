"""
    Define message type constants, sent as first byte in every message.

    First bit of byte (MSB) designates if the message is destined to server or client. 0 means target is server.
"""

from collections import namedtuple

_ProtocolMessage = namedtuple('ProtocolMessage', ['byte', 'description'])

# Client messages
CLIENT_HELLO               = _ProtocolMessage(b'\x00', 'First message from client, with challenge to server and protocol version.')
SA_PROPOSAL                = _ProtocolMessage(b'\x01', 'Security association suggested by client.')
COMMAND                    = _ProtocolMessage(b'\x02', 'Command from client.')
REKEY                      = _ProtocolMessage(b'\x03', 'Generate new master key')
REKEY_CONFIRM              = _ProtocolMessage(b'\x04', 'Confirm successful re-key by signing a random nonce with the new key')
CLIENT_TERMINATE           = _ProtocolMessage(b'\x0f', 'Client is terminating the session.')

# Server messages
SERVER_HELLO               = _ProtocolMessage(b'\x80', 'First response from server, responds to client challenge and challenges client')
SA                         = _ProtocolMessage(b'\x81', 'Negotiated security association from server.')
REPLY                      = _ProtocolMessage(b'\x82', 'Reply to command issued by client.')
REKEY_RESPONSE             = _ProtocolMessage(b'\x83', 'Respond to re-key command with satellites public key')
REKEY_COMPLETED            = _ProtocolMessage(b'\x84', 'Complete the re-keying by invalidating all existing sessions and ')
VERSION_NOT_SUPPORTED      = _ProtocolMessage(b'\x83', 'Version suggested by client is not supported by server.')
MESSAGE_TYPE_NOT_SUPPORTED = _ProtocolMessage(b'\x84', 'Message type received from client is not supported by server.')
SERVER_TERMINATE           = _ProtocolMessage(b'\x8f', 'Server is terminating the session.')

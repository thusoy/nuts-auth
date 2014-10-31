"""
    Define message type constants, sent as first byte in every message.

    First bit of byte (MSB) designates if the message is destined to server or client. 0 means target is server.
"""

from collections import namedtuple

_ProtocolMessage = namedtuple('ProtocolMessage', ['byte', 'description'])

CLIENT_HELLO               = _ProtocolMessage('\x00', 'First message from client, with challenge to server and protocol version.')
SA_PROPOSAL                = _ProtocolMessage('\x01', 'Security association suggested by client.')
COMMAND                    = _ProtocolMessage('\x02', 'Command from client.')
INVALID_MAC_FROM_SERVER    = _ProtocolMessage('\x0e', 'Server sent incorrect MAC')
CLIENT_TERMINATE           = _ProtocolMessage('\x0f', 'Client is terminating the session.')
SERVER_HELLO               = _ProtocolMessage('\x80', 'First response from server, responds to client challenge and challenges client')
SA                         = _ProtocolMessage('\x81', 'Negotiated security association from server.')
REPLY                      = _ProtocolMessage('\x82', 'Reply to command issues by client.')
VERSION_NOT_SUPPORTED      = _ProtocolMessage('\x83', 'Version suggested by client is not supported by server.')
MESSAGE_TYPE_NOT_SUPPORTED = _ProtocolMessage('\x84', 'Message type received from client is not supported by server.')
INVALID_MAC_FROM_CLIENT    = _ProtocolMessage('\x8e', 'Client sent message with incorrect MAC')
SERVER_TERMINATE           = _ProtocolMessage('\x8f', 'Server is terminating the session.')

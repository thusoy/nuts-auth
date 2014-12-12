from enum import Enum, IntEnum

class ServerState(Enum):
    inactive = 1
    wait_for_sa_proposal = 2
    established = 3
    rekey = 4
    rekey_confirmed = 5


class ClientState(Enum):
    inactive = 1
    wait_for_server_hello = 2
    wait_for_sa = 3
    established = 4
    rekey = 5
    wait_for_rekey_complete = 6
    terminated = 7


class Message(IntEnum):

    # Client messages

    #: First message from client, with challenge to server and protocol version.
    client_hello = 0x00
    #: Security association suggested by client.
    sa_proposal = 0x01
    #: Command from client.
    command = 0x02
    #: Generate new master key
    rekey = 0x03
    #: Confirm successful re-key by signing a random nonce with the new key
    rekey_confirm = 0x04
    #: Client is terminating the session.
    client_terminate = 0x7f

    # Server messages

    #: First response from server, responds to client challenge and challenges client
    server_hello = 0x80
    #: Negotiated security association from server.
    sa = 0x81
    #: Reply to command issued by client.
    reply = 0x82
    #: Respond to re-key command with satellites public key
    rekey_response = 0x83
    #: Complete the re-keying by invalidating all existing sessions
    rekey_completed = 0x84
    #: Version suggested by client is not supported by server.
    version_not_supported = 0x85
    #: Server is terminating the session.
    server_terminate = 0xff

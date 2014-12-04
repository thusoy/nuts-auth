from collections import namedtuple

# The main message class that the AuthChannel operate on
AuthenticatedMessage = namedtuple('Message', ['sender', 'msg'])


class NutsConnectionError(Exception):
    """ Something failed in the communication. """


from .channels import (
    AuthChannel,
    UDPAuthChannel,
)

from .enums import (
    ClientState,
    ServerState,
    Message,
)

# The main message class that the AuthChannel operate on
class AuthenticatedMessage(object):

    def __init__(self, sender, msg, session=None):
        self.sender = sender
        self.msg = msg
        self.session = session

    def __str__(self):
        return self.msg

class NutsError(Exception):
    """ General NUTS-related failure. """


class NutsConnectionError(NutsError):
    """ Something failed in the communication. """


class NutsMessageTooLarge(NutsError):
    """ Tried to send message larger than what's supported by the underlying
    transport.
    """


class NutsInvalidState(NutsError):
    """ Tried to perform an action which is unavilable in the current
    state. """




from .channels import (
    AuthChannel,
    UDPAuthChannel,
)

from .enums import (
    ClientState,
    ServerState,
    Message,
)

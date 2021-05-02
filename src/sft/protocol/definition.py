import csbuilder
from csbuilder.standard import Protocols, StandardRole, Roles, States


@csbuilder.protocols
class SFTProtocols(Protocols):
    SFT = 1


@csbuilder.roles(protocol=SFTProtocols.SFT)
class SFTRoles(Roles):
    SENDER = StandardRole.ACTIVE
    RECEIVER = StandardRole.PASSIVE


@csbuilder.states(SFTProtocols.SFT,SFTRoles.SENDER)
class SFTSenderStates(States):
    IGNORE = 0
    REQUEST = 1
    INFO = 2
    SEND = 3


@csbuilder.states(SFTProtocols.SFT, SFTRoles.RECEIVER)
class SFTReceiverStates(States):
    IGNORE = 0
    ACCEPT = 1
    DENY = 2
    REQUIRE = 3
    SUCCESS = 4
    FAILURE = 5

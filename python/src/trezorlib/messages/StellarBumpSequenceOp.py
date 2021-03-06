# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class StellarBumpSequenceOp(p.MessageType):
    MESSAGE_WIRE_TYPE = 221

    def __init__(
        self,
        *,
        source_account: Optional[str] = None,
        bump_to: Optional[int] = None,
    ) -> None:
        self.source_account = source_account
        self.bump_to = bump_to

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('source_account', p.UnicodeType, None),
            2: ('bump_to', p.UVarintType, None),
        }

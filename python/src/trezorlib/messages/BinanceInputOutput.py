# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .BinanceCoin import BinanceCoin

if __debug__:
    try:
        from typing import Dict, List, Optional  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class BinanceInputOutput(p.MessageType):

    def __init__(
        self,
        *,
        coins: Optional[List[BinanceCoin]] = None,
        address: Optional[str] = None,
    ) -> None:
        self.coins = coins if coins is not None else []
        self.address = address

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('address', p.UnicodeType, None),
            2: ('coins', BinanceCoin, p.FLAG_REPEATED),
        }

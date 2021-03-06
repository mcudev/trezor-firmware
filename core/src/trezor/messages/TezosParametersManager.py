# Automatically generated by pb2py
# fmt: off
import protobuf as p

from .TezosManagerTransfer import TezosManagerTransfer

if __debug__:
    try:
        from typing import Dict, List, Optional  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class TezosParametersManager(p.MessageType):

    def __init__(
        self,
        *,
        set_delegate: Optional[bytes] = None,
        cancel_delegate: Optional[bool] = None,
        transfer: Optional[TezosManagerTransfer] = None,
    ) -> None:
        self.set_delegate = set_delegate
        self.cancel_delegate = cancel_delegate
        self.transfer = transfer

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('set_delegate', p.BytesType, None),
            2: ('cancel_delegate', p.BoolType, None),
            3: ('transfer', TezosManagerTransfer, None),
        }

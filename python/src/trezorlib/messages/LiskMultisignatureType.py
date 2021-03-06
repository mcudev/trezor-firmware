# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class LiskMultisignatureType(p.MessageType):

    def __init__(
        self,
        *,
        keys_group: Optional[List[str]] = None,
        min: Optional[int] = None,
        life_time: Optional[int] = None,
    ) -> None:
        self.keys_group = keys_group if keys_group is not None else []
        self.min = min
        self.life_time = life_time

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('min', p.UVarintType, None),
            2: ('life_time', p.UVarintType, None),
            3: ('keys_group', p.UnicodeType, p.FLAG_REPEATED),
        }

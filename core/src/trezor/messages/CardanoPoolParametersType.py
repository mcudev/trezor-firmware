# Automatically generated by pb2py
# fmt: off
import protobuf as p

from .CardanoPoolMetadataType import CardanoPoolMetadataType
from .CardanoPoolOwnerType import CardanoPoolOwnerType
from .CardanoPoolRelayParametersType import CardanoPoolRelayParametersType

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        pass


class CardanoPoolParametersType(p.MessageType):

    def __init__(
        self,
        *,
        pool_id: bytes,
        vrf_key_hash: bytes,
        pledge: int,
        cost: int,
        margin_numerator: int,
        margin_denominator: int,
        reward_account: str,
        owners: List[CardanoPoolOwnerType] = None,
        relays: List[CardanoPoolRelayParametersType] = None,
        metadata: CardanoPoolMetadataType = None,
    ) -> None:
        self.owners = owners if owners is not None else []
        self.relays = relays if relays is not None else []
        self.pool_id = pool_id
        self.vrf_key_hash = vrf_key_hash
        self.pledge = pledge
        self.cost = cost
        self.margin_numerator = margin_numerator
        self.margin_denominator = margin_denominator
        self.reward_account = reward_account
        self.metadata = metadata

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('pool_id', p.BytesType, p.FLAG_REQUIRED),
            2: ('vrf_key_hash', p.BytesType, p.FLAG_REQUIRED),
            3: ('pledge', p.UVarintType, p.FLAG_REQUIRED),
            4: ('cost', p.UVarintType, p.FLAG_REQUIRED),
            5: ('margin_numerator', p.UVarintType, p.FLAG_REQUIRED),
            6: ('margin_denominator', p.UVarintType, p.FLAG_REQUIRED),
            7: ('reward_account', p.UnicodeType, p.FLAG_REQUIRED),
            8: ('owners', CardanoPoolOwnerType, p.FLAG_REPEATED),
            9: ('relays', CardanoPoolRelayParametersType, p.FLAG_REPEATED),
            10: ('metadata', CardanoPoolMetadataType, None),
        }
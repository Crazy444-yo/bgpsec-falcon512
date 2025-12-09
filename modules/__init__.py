"""
BGPsec Modules Package

Core modules for BGPsec implementation with Falcon-512.

Author: Sam Moes
Date: December 2025
"""

from .bgpsec import (
    SecurePathSegment,
    SignatureBlock,
    SecurePathAttribute,
    BGPsecPathSigner,
    compute_data_to_sign,
    BGPsec_SUITE_FALCON512,
    BGPsec_SUITE_ECDSA_P256,
    BGPsec_SUITE_ECDSA_P384
)

from .bgp_message import (
    BGPUpdateMessage,
    encode_nlri,
    decode_nlri,
    BGP_MSG_UPDATE,
    BGP_MSG_OPEN,
    BGP_MSG_NOTIFICATION,
    BGP_MSG_KEEPALIVE
)

from .path_signature import BGPsecPath

__all__ = [
    # bgpsec exports
    'SecurePathSegment',
    'SignatureBlock',
    'SecurePathAttribute',
    'BGPsecPathSigner',
    'compute_data_to_sign',
    'BGPsec_SUITE_FALCON512',
    'BGPsec_SUITE_ECDSA_P256',
    'BGPsec_SUITE_ECDSA_P384',
    # bgp_message exports
    'BGPUpdateMessage',
    'encode_nlri',
    'decode_nlri',
    'BGP_MSG_UPDATE',
    'BGP_MSG_OPEN',
    'BGP_MSG_NOTIFICATION',
    'BGP_MSG_KEEPALIVE',
    # path_signature exports
    'BGPsecPath',
]


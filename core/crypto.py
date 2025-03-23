"""
Author: Edunbar2
Version: 1.0
Description: SecureTCP v1.0 HMAC generation and validation
"""

import hmac
from hashlib import sha256

from secureTCP.config import SHARED_KEY

def compute_hmac(header, payload, key=SHARED_KEY) -> bytes:
    """
       Compute a truncated 16-byte HMAC using SHA-256 over the header and payload.

       Parameters:
           header (bytes): The SecureTCP header without the HMAC field.
           payload (bytes): The packet's payload.
           key (bytes): Optional; the shared secret key (defaults to SHARED_KEY).

       Returns:
           bytes: The first 16 bytes of the HMAC digest.
       """
    assert isinstance(header, bytes)
    assert isinstance(payload, bytes)
    h = hmac.new(key, header+payload, sha256)
    return h.digest()[:16]

def validate_hmac(header: bytes, payload: bytes, received_hmac: bytes) -> bool:
    """
        Validate the received HMAC against a freshly computed one.

        Parameters:
            header (bytes): The header portion of the packet (excluding the HMAC field).
            payload (bytes): The payload portion of the packet.
            received_hmac (bytes): The HMAC value received from the remote sender.

        Returns:
            bool: True if the HMAC is valid, False otherwise.
        """
    expected_hmac = compute_hmac(header, payload, key=SHARED_KEY)
    return hmac.compare_digest(expected_hmac, received_hmac)


def get_key()-> bytes:
    """
        Return the shared key used for computing HMACs.
        Intended to be used for dynamic key sharing in v2.0+

        Returns:
            bytes: The pre-shared secret key loaded from the configuration.
        """
    return SHARED_KEY
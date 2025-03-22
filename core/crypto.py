"""
Author: Edunbar2
Version: 1.0
"""

from hashlib import sha256
import hmac
from secureTCP.config import SHARED_KEY

def compute_hmac(header, paylaod):
    return 0
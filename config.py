import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def require_env(var_name: str) -> str:
    value = os.environ.get(var_name)
    if value is None:
        print(f"[ERROR] Required environment variable '{var_name}' is not set.")
        sys.exit(1)

# Required
SHARED_KEY = require_env("SECURETCP_KEY").encode()

# Optional/defaults
DEFAULT_INTERFACE = os.environ.get("SECURETCP_INTERFACE", "ens18")
DEFAULT_PORT = int(os.environ.get("SECURETCP_DEFAULT_PORT", "9011"))
SECURETCP_PROTOCOL_NUMBER = int(os.environ.get("SECURETCP_PROTO", "253"))
CURRENT_VERSION = int(os.environ.get("SECURETCP_CURRENT_VERSION"))
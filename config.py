import os
import sys

def require_env(var_name: str) -> str:
    value = os.environ.get(var_name)
    if value is None:
        print(f"[ERROR] Required environment variable '{var_name}' is not set.")
        sys.exit(1)

SHARED_KEY = b"secure-secret-key"